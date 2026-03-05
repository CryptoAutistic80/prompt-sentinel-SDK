use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

use crate::modules::audit::logger::{AuditError, AuditEvent, AuditLogger};
use crate::modules::audit::proof::AuditProof;
use crate::modules::bias_detection::dtos::{BiasScanRequest, BiasScanResult};
use crate::modules::bias_detection::service::BiasDetectionService;
use crate::modules::eu_law_compliance::model::{AiRiskTier, EuComplianceResult};
use crate::modules::eu_law_compliance::service::EuLawComplianceService;
use crate::modules::mistral_ai::dtos::ModerationResponse;
use crate::modules::mistral_ai::service::{MistralService, MistralServiceError};
use crate::modules::prompt_firewall::dtos::{
    FirewallAction, PromptFirewallRequest, PromptFirewallResult,
};
use crate::modules::prompt_firewall::service::PromptFirewallService;
use crate::modules::semantic_detection::dtos::{
    SemanticRiskLevel, SemanticScanRequest, SemanticScanResult,
};
use crate::modules::semantic_detection::service::{
    SemanticDetectionError, SemanticDetectionService,
};
use crate::modules::telemetry::correlation::generate_correlation_id_from_request;
use crate::modules::telemetry::tracing::{create_span_with_correlation, log_with_correlation};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Completed,
    BlockedByFirewall,
    BlockedBySemantic,
    BlockedByInputModeration,
    BlockedByOutputModeration,
    BlockedByEuCompliance,
    Sanitized,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComplianceRequest {
    pub correlation_id: Option<String>,
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub prompt: String,
}

/// Evidence explaining how the final decision was made
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct DecisionEvidence {
    /// Firewall action taken
    pub firewall_action: String,
    /// Rules matched by the firewall
    pub firewall_matched_rules: Vec<String>,
    /// Semantic risk score (0.0 - 1.0)
    pub semantic_risk_score: Option<f32>,
    /// ID of matched attack template
    pub semantic_matched_template: Option<String>,
    /// Category of matched attack template
    pub semantic_category: Option<String>,
    /// Whether moderation flagged the input
    pub moderation_flagged: bool,
    /// Categories flagged by moderation
    pub moderation_categories: Vec<String>,
    /// Final decision
    pub final_decision: String,
    /// Human-readable explanation
    pub final_reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ComplianceResponse {
    pub correlation_id: String,
    pub status: WorkflowStatus,
    pub firewall: PromptFirewallResult,
    pub semantic: Option<SemanticScanResult>,
    pub bias: BiasScanResult,
    pub input_moderation: Option<ModerationResponse>,
    pub output_moderation: Option<ModerationResponse>,
    pub generated_text: Option<String>,
    pub audit_proof: AuditProof,
    /// Evidence explaining the decision
    pub decision_evidence: Option<DecisionEvidence>,
    /// EU AI Act compliance result
    pub eu_compliance: Option<EuComplianceResult>,
}

#[derive(Clone)]
pub struct ComplianceEngine {
    firewall_service: PromptFirewallService,
    semantic_service: SemanticDetectionService,
    bias_service: BiasDetectionService,
    mistral_service: MistralService,
    audit_logger: AuditLogger,
    eu_compliance_service: EuLawComplianceService,
}

impl ComplianceEngine {
    pub fn new(
        firewall_service: PromptFirewallService,
        semantic_service: SemanticDetectionService,
        bias_service: BiasDetectionService,
        mistral_service: MistralService,
        audit_logger: AuditLogger,
    ) -> Self {
        Self {
            firewall_service,
            semantic_service,
            bias_service,
            mistral_service,
            audit_logger,
            eu_compliance_service: EuLawComplianceService::default(),
        }
    }

    /// Initialize the semantic detection service (call at startup)
    pub async fn initialize_semantic(&self) -> Result<(), SemanticDetectionError> {
        self.semantic_service.initialize().await
    }

    /// Get a reference to the Mistral service for health checks
    pub fn mistral_service(&self) -> &MistralService {
        &self.mistral_service
    }

    /// Get a reference to the audit logger for audit trail access
    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit_logger
    }

    /// Detect the language of the original prompt
    async fn detect_original_language(&self, prompt: &str) -> String {
        // Default to English if detection fails
        let Ok(lang_detection) = self
            .mistral_service
            .detect_language(prompt.to_owned())
            .await
        else {
            return "English".to_string();
        };

        lang_detection.language
    }

    /// Translate text back to the original language
    async fn translate_to_original_language(&self, text: &str, target_language: &str) -> String {
        // If translation fails, return original English text
        let Ok(translation) = self
            .mistral_service
            .translate_text(text.to_owned(), target_language.to_owned())
            .await
        else {
            return text.to_owned();
        };

        translation.translated_text
    }

    pub async fn process(
        &self,
        request: ComplianceRequest,
    ) -> Result<ComplianceResponse, WorkflowError> {
        let ComplianceRequest {
            correlation_id: request_correlation_id,
            tenant_id,
            workspace_id,
            prompt: original_prompt,
        } = request;
        let correlation_id = generate_correlation_id_from_request(request_correlation_id);
        let span = create_span_with_correlation(&correlation_id, "compliance_workflow");
        let _enter = span.enter();

        log_with_correlation(
            &correlation_id,
            tracing::Level::INFO,
            "Starting compliance workflow",
        );

        // Detect original language for response translation
        let original_language = self.detect_original_language(&original_prompt).await;
        log_with_correlation(
            &correlation_id,
            tracing::Level::DEBUG,
            &format!("Detected original language: {}", original_language),
        );

        // Step 1: Firewall check (fast, deterministic)
        let firewall = self
            .firewall_service
            .inspect(PromptFirewallRequest {
                prompt: original_prompt.clone(),
                correlation_id: Some(correlation_id.clone()),
            })
            .await;

        // Step 2: EU AI Act compliance check
        log_with_correlation(
            &correlation_id,
            tracing::Level::INFO,
            "Performing EU AI Act compliance check",
        );
        let eu_compliance = self.eu_compliance_service.check_prompt(&original_prompt);

        // Step 3: Bias detection
        let bias = self
            .bias_service
            .scan(BiasScanRequest {
                text: firewall.sanitized_prompt.clone(),
                threshold: None,
            })
            .await;

        // Policy combiner: Apply precedence rules
        // 0. EU Compliance Unacceptable -> Block (Article 5 prohibited practices)
        if matches!(eu_compliance.risk_tier, AiRiskTier::Unacceptable) {
            let evidence = DecisionEvidence {
                firewall_action: format!("{:?}", firewall.action),
                firewall_matched_rules: firewall.matched_rules.clone(),
                semantic_risk_score: None,
                semantic_matched_template: None,
                semantic_category: None,
                moderation_flagged: false,
                moderation_categories: vec![],
                final_decision: "block".to_string(),
                final_reason: format!(
                    "Blocked by EU AI Act Article 5 (Prohibited Practices): {}",
                    eu_compliance
                        .findings
                        .first()
                        .map(|f| f.detail.as_str())
                        .unwrap_or("Unacceptable risk tier detected")
                ),
            };

            log_with_correlation(
                &correlation_id,
                tracing::Level::WARN,
                &format!(
                    "Prompt blocked by EU AI Act compliance: {:?}",
                    eu_compliance.risk_tier
                ),
            );

            let proof = self.audit_logger.log_event(AuditEvent {
                correlation_id: correlation_id.clone(),
                tenant_id: tenant_id.clone(),
                workspace_id: workspace_id.clone(),
                original_prompt: original_prompt.clone(),
                sanitized_prompt: firewall.sanitized_prompt.clone(),
                firewall_action: format!("{:?}", firewall.action),
                firewall_reasons: firewall.reasons.clone(),
                semantic_risk_score: None,
                semantic_template_id: None,
                semantic_category: None,
                bias_score: bias.score,
                bias_level: format!("{:?}", bias.level),
                input_moderation_flagged: false,
                output_moderation_flagged: false,
                final_status: "blocked_by_eu_compliance".to_owned(),
                final_reason: evidence.final_reason.clone(),
                model_used: None,
                output_preview: None,
                full_output_text: None,
                output_moderation_categories: vec![],
                eu_risk_tier: Some(format!("{:?}", eu_compliance.risk_tier)),
                eu_findings: Some(
                    eu_compliance
                        .findings
                        .iter()
                        .map(|f| f.detail.clone())
                        .collect(),
                ),
                tokens_used: None,
                response_latency_ms: None,
                detected_language: Some(original_language.clone()),
                was_translated: false,
            })?;

            return Ok(ComplianceResponse {
                correlation_id,
                status: WorkflowStatus::BlockedByEuCompliance,
                firewall,
                semantic: None,
                bias,
                input_moderation: None,
                output_moderation: None,
                generated_text: None,
                audit_proof: proof,
                decision_evidence: Some(evidence),
                eu_compliance: Some(eu_compliance),
            });
        }

        // 1. Firewall Block -> Block
        if firewall.action == FirewallAction::Block {
            let evidence = DecisionEvidence {
                firewall_action: format!("{:?}", firewall.action),
                firewall_matched_rules: firewall.matched_rules.clone(),
                semantic_risk_score: None,
                semantic_matched_template: None,
                semantic_category: None,
                moderation_flagged: false,
                moderation_categories: vec![],
                final_decision: "block".to_string(),
                final_reason: format!(
                    "Blocked by firewall rule: {}",
                    firewall.matched_rules.join(", ")
                ),
            };

            log_with_correlation(
                &correlation_id,
                tracing::Level::WARN,
                "Prompt blocked by firewall",
            );

            let proof = self.audit_logger.log_event(AuditEvent {
                correlation_id: correlation_id.clone(),
                tenant_id: tenant_id.clone(),
                workspace_id: workspace_id.clone(),
                original_prompt: original_prompt.clone(),
                sanitized_prompt: firewall.sanitized_prompt.clone(),
                firewall_action: format!("{:?}", firewall.action),
                firewall_reasons: firewall.reasons.clone(),
                semantic_risk_score: None,
                semantic_template_id: None,
                semantic_category: None,
                bias_score: bias.score,
                bias_level: format!("{:?}", bias.level),
                input_moderation_flagged: false,
                output_moderation_flagged: false,
                final_status: "blocked_by_firewall".to_owned(),
                final_reason: evidence.final_reason.clone(),
                model_used: None,
                output_preview: None,
                full_output_text: None,
                output_moderation_categories: vec![],
                eu_risk_tier: Some(format!("{:?}", eu_compliance.risk_tier)),
                eu_findings: Some(
                    eu_compliance
                        .findings
                        .iter()
                        .map(|f| f.detail.clone())
                        .collect(),
                ),
                tokens_used: None,
                response_latency_ms: None,
                detected_language: Some(original_language.clone()),
                was_translated: false,
            })?;

            return Ok(ComplianceResponse {
                correlation_id,
                status: WorkflowStatus::BlockedByFirewall,
                firewall,
                semantic: None,
                bias,
                input_moderation: None,
                output_moderation: None,
                generated_text: None,
                audit_proof: proof,
                decision_evidence: Some(evidence),
                eu_compliance: Some(eu_compliance),
            });
        }

        // Step 4: Run semantic scan and input moderation concurrently.
        log_with_correlation(
            &correlation_id,
            tracing::Level::INFO,
            "Performing semantic scan and input moderation",
        );
        let (semantic_result, input_moderation_result) = tokio::join!(
            self.semantic_service.scan(SemanticScanRequest {
                text: firewall.sanitized_prompt.clone(),
            }),
            self.mistral_service
                .moderate_text(firewall.sanitized_prompt.clone())
        );
        let semantic = semantic_result.ok();
        let input_moderation = input_moderation_result?;

        // 2. Semantic High -> Block
        if let Some(ref sem) = semantic
            && sem.risk_level == SemanticRiskLevel::High
        {
            let evidence = DecisionEvidence {
                firewall_action: format!("{:?}", firewall.action),
                firewall_matched_rules: firewall.matched_rules.clone(),
                semantic_risk_score: Some(sem.risk_score),
                semantic_matched_template: sem.nearest_template_id.clone(),
                semantic_category: sem.category.clone(),
                moderation_flagged: false,
                moderation_categories: vec![],
                final_decision: "block".to_string(),
                final_reason: format!(
                    "Semantic similarity to attack pattern {} (category: {}, score: {:.2})",
                    sem.nearest_template_id.as_deref().unwrap_or("unknown"),
                    sem.category.as_deref().unwrap_or("unknown"),
                    sem.similarity
                ),
            };

            log_with_correlation(
                &correlation_id,
                tracing::Level::WARN,
                "Prompt blocked by semantic detection",
            );

            let proof = self.audit_logger.log_event(AuditEvent {
                correlation_id: correlation_id.clone(),
                tenant_id: tenant_id.clone(),
                workspace_id: workspace_id.clone(),
                original_prompt: original_prompt.clone(),
                sanitized_prompt: firewall.sanitized_prompt.clone(),
                firewall_action: format!("{:?}", firewall.action),
                firewall_reasons: firewall.reasons.clone(),
                semantic_risk_score: Some(sem.risk_score),
                semantic_template_id: sem.nearest_template_id.clone(),
                semantic_category: sem.category.clone(),
                bias_score: bias.score,
                bias_level: format!("{:?}", bias.level),
                input_moderation_flagged: false,
                output_moderation_flagged: false,
                final_status: "blocked_by_semantic".to_owned(),
                final_reason: evidence.final_reason.clone(),
                model_used: None,
                output_preview: None,
                full_output_text: None,
                output_moderation_categories: vec![],
                eu_risk_tier: Some(format!("{:?}", eu_compliance.risk_tier)),
                eu_findings: Some(
                    eu_compliance
                        .findings
                        .iter()
                        .map(|f| f.detail.clone())
                        .collect(),
                ),
                tokens_used: None,
                response_latency_ms: None,
                detected_language: Some(original_language.clone()),
                was_translated: false,
            })?;

            return Ok(ComplianceResponse {
                correlation_id,
                status: WorkflowStatus::BlockedBySemantic,
                firewall,
                semantic,
                bias,
                input_moderation: None,
                output_moderation: None,
                generated_text: None,
                audit_proof: proof,
                decision_evidence: Some(evidence),
                eu_compliance: Some(eu_compliance),
            });
        }

        // 3. Input moderation check
        if input_moderation.flagged {
            let evidence = DecisionEvidence {
                firewall_action: format!("{:?}", firewall.action),
                firewall_matched_rules: firewall.matched_rules.clone(),
                semantic_risk_score: semantic.as_ref().map(|s| s.risk_score),
                semantic_matched_template: semantic
                    .as_ref()
                    .and_then(|s| s.nearest_template_id.clone()),
                semantic_category: semantic.as_ref().and_then(|s| s.category.clone()),
                moderation_flagged: true,
                moderation_categories: input_moderation.categories.clone(),
                final_decision: "block".to_string(),
                final_reason: format!(
                    "Flagged by content moderation: {}",
                    input_moderation.categories.join(", ")
                ),
            };

            log_with_correlation(
                &correlation_id,
                tracing::Level::WARN,
                "Input flagged by moderation",
            );

            let proof = self.audit_logger.log_event(AuditEvent {
                correlation_id: correlation_id.clone(),
                tenant_id: tenant_id.clone(),
                workspace_id: workspace_id.clone(),
                original_prompt: original_prompt.clone(),
                sanitized_prompt: firewall.sanitized_prompt.clone(),
                firewall_action: format!("{:?}", firewall.action),
                firewall_reasons: firewall.reasons.clone(),
                semantic_risk_score: semantic.as_ref().map(|s| s.risk_score),
                semantic_template_id: semantic
                    .as_ref()
                    .and_then(|s| s.nearest_template_id.clone()),
                semantic_category: semantic.as_ref().and_then(|s| s.category.clone()),
                bias_score: bias.score,
                bias_level: format!("{:?}", bias.level),
                input_moderation_flagged: true,
                output_moderation_flagged: false,
                final_status: "blocked_by_input_moderation".to_owned(),
                final_reason: evidence.final_reason.clone(),
                model_used: None,
                output_preview: None,
                full_output_text: None,
                output_moderation_categories: input_moderation.categories.clone(),
                eu_risk_tier: Some(format!("{:?}", eu_compliance.risk_tier)),
                eu_findings: Some(
                    eu_compliance
                        .findings
                        .iter()
                        .map(|f| f.detail.clone())
                        .collect(),
                ),
                tokens_used: None,
                response_latency_ms: None,
                detected_language: Some(original_language.clone()),
                was_translated: false,
            })?;

            return Ok(ComplianceResponse {
                correlation_id,
                status: WorkflowStatus::BlockedByInputModeration,
                firewall,
                semantic,
                bias,
                input_moderation: Some(input_moderation),
                output_moderation: None,
                generated_text: None,
                audit_proof: proof,
                decision_evidence: Some(evidence),
                eu_compliance: Some(eu_compliance),
            });
        }

        // 4. Semantic Medium or Firewall Sanitize -> Sanitize (proceed with caution)
        let is_sanitized = firewall.action == FirewallAction::Sanitize
            || semantic
                .as_ref()
                .map(|s| s.risk_level == SemanticRiskLevel::Medium)
                .unwrap_or(false);

        // Generate text with timing
        log_with_correlation(
            &correlation_id,
            tracing::Level::INFO,
            "Generating text with Mistral AI",
        );
        let generation_start = Instant::now();
        let generation = self
            .mistral_service
            .generate_text(firewall.sanitized_prompt.clone(), true)
            .await?;
        let generation_latency_ms = generation_start.elapsed().as_millis() as u64;

        // Clone the English output for moderation and audit logging
        let english_output = generation.output_text.clone();
        let tokens_used = generation.usage.as_ref().map(|u| u.total_tokens);

        // Translate generated text back to original language if needed
        let was_translated = original_language.to_lowercase() != "english";
        let generated_text = if was_translated {
            self.translate_to_original_language(&english_output, &original_language)
                .await
        } else {
            english_output.clone()
        };

        // Output moderation (moderate the English version before translation)
        log_with_correlation(
            &correlation_id,
            tracing::Level::INFO,
            "Performing output moderation",
        );
        let output_moderation = self
            .mistral_service
            .moderate_text(english_output.clone())
            .await?;

        if output_moderation.flagged {
            let evidence = DecisionEvidence {
                firewall_action: format!("{:?}", firewall.action),
                firewall_matched_rules: firewall.matched_rules.clone(),
                semantic_risk_score: semantic.as_ref().map(|s| s.risk_score),
                semantic_matched_template: semantic
                    .as_ref()
                    .and_then(|s| s.nearest_template_id.clone()),
                semantic_category: semantic.as_ref().and_then(|s| s.category.clone()),
                moderation_flagged: true,
                moderation_categories: output_moderation.categories.clone(),
                final_decision: "block".to_string(),
                final_reason: format!(
                    "Output flagged by moderation: {}",
                    output_moderation.categories.join(", ")
                ),
            };

            log_with_correlation(
                &correlation_id,
                tracing::Level::WARN,
                "Output flagged by moderation",
            );

            let proof = self.audit_logger.log_event(AuditEvent {
                correlation_id: correlation_id.clone(),
                tenant_id: tenant_id.clone(),
                workspace_id: workspace_id.clone(),
                original_prompt: original_prompt.clone(),
                sanitized_prompt: firewall.sanitized_prompt.clone(),
                firewall_action: format!("{:?}", firewall.action),
                firewall_reasons: firewall.reasons.clone(),
                semantic_risk_score: semantic.as_ref().map(|s| s.risk_score),
                semantic_template_id: semantic
                    .as_ref()
                    .and_then(|s| s.nearest_template_id.clone()),
                semantic_category: semantic.as_ref().and_then(|s| s.category.clone()),
                bias_score: bias.score,
                bias_level: format!("{:?}", bias.level),
                input_moderation_flagged: false,
                output_moderation_flagged: true,
                final_status: "blocked_by_output_moderation".to_owned(),
                final_reason: evidence.final_reason.clone(),
                model_used: Some(generation.model),
                output_preview: Some(english_output.chars().take(160).collect()),
                full_output_text: Some(english_output.clone()),
                output_moderation_categories: output_moderation.categories.clone(),
                eu_risk_tier: Some(format!("{:?}", eu_compliance.risk_tier)),
                eu_findings: Some(
                    eu_compliance
                        .findings
                        .iter()
                        .map(|f| f.detail.clone())
                        .collect(),
                ),
                tokens_used,
                response_latency_ms: Some(generation_latency_ms),
                detected_language: Some(original_language.clone()),
                was_translated,
            })?;

            return Ok(ComplianceResponse {
                correlation_id,
                status: WorkflowStatus::BlockedByOutputModeration,
                firewall,
                semantic,
                bias,
                input_moderation: Some(input_moderation),
                output_moderation: Some(output_moderation),
                generated_text: None,
                audit_proof: proof,
                decision_evidence: Some(evidence),
                eu_compliance: Some(eu_compliance),
            });
        }

        // Build final evidence
        let (final_decision, final_reason, final_status) = if is_sanitized {
            let reason = if firewall.action == FirewallAction::Sanitize {
                "Input sanitized by firewall".to_string()
            } else {
                format!(
                    "Elevated risk (semantic score: {:.2}), proceeded with caution",
                    semantic.as_ref().map(|s| s.similarity).unwrap_or(0.0)
                )
            };
            ("sanitize".to_string(), reason, WorkflowStatus::Sanitized)
        } else {
            (
                "allow".to_string(),
                "All checks passed".to_string(),
                WorkflowStatus::Completed,
            )
        };

        let evidence = DecisionEvidence {
            firewall_action: format!("{:?}", firewall.action),
            firewall_matched_rules: firewall.matched_rules.clone(),
            semantic_risk_score: semantic.as_ref().map(|s| s.risk_score),
            semantic_matched_template: semantic
                .as_ref()
                .and_then(|s| s.nearest_template_id.clone()),
            semantic_category: semantic.as_ref().and_then(|s| s.category.clone()),
            moderation_flagged: false,
            moderation_categories: vec![],
            final_decision,
            final_reason: final_reason.clone(),
        };

        log_with_correlation(
            &correlation_id,
            tracing::Level::INFO,
            "Workflow completed successfully",
        );

        let proof = self.audit_logger.log_event(AuditEvent {
            correlation_id: correlation_id.clone(),
            tenant_id: tenant_id.clone(),
            workspace_id: workspace_id.clone(),
            original_prompt,
            sanitized_prompt: firewall.sanitized_prompt.clone(),
            firewall_action: format!("{:?}", firewall.action),
            firewall_reasons: firewall.reasons.clone(),
            semantic_risk_score: semantic.as_ref().map(|s| s.risk_score),
            semantic_template_id: semantic
                .as_ref()
                .and_then(|s| s.nearest_template_id.clone()),
            semantic_category: semantic.as_ref().and_then(|s| s.category.clone()),
            bias_score: bias.score,
            bias_level: format!("{:?}", bias.level),
            input_moderation_flagged: false,
            output_moderation_flagged: false,
            final_status: if is_sanitized {
                "sanitized"
            } else {
                "completed"
            }
            .to_owned(),
            final_reason: evidence.final_reason.clone(),
            model_used: Some(generation.model.clone()),
            output_preview: Some(english_output.chars().take(160).collect()),
            full_output_text: Some(english_output),
            output_moderation_categories: vec![],
            eu_risk_tier: Some(format!("{:?}", eu_compliance.risk_tier)),
            eu_findings: Some(
                eu_compliance
                    .findings
                    .iter()
                    .map(|f| f.detail.clone())
                    .collect(),
            ),
            tokens_used,
            response_latency_ms: Some(generation_latency_ms),
            detected_language: Some(original_language),
            was_translated,
        })?;

        log_with_correlation(
            &correlation_id,
            tracing::Level::DEBUG,
            &format!(
                "Generated text preview: {}",
                generated_text.chars().take(160).collect::<String>()
            ),
        );

        Ok(ComplianceResponse {
            correlation_id,
            status: final_status,
            firewall,
            semantic,
            bias,
            input_moderation: Some(input_moderation),
            output_moderation: Some(output_moderation),
            generated_text: Some(generated_text),
            audit_proof: proof,
            decision_evidence: Some(evidence),
            eu_compliance: Some(eu_compliance),
        })
    }
}

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("mistral workflow failure: {0}")]
    Mistral(#[from] MistralServiceError),
    #[error("audit workflow failure: {0}")]
    Audit(#[from] AuditError),
}
