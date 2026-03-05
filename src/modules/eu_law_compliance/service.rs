use std::fs;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::dtos::{
    ComplianceCheckRequest, ComplianceCheckResponse, ComplianceConfigurationRequest,
    ComplianceConfigurationResponse, ComplianceConfigurationSummary, ComplianceReportRequest,
    ComplianceReportResponse, DocumentationRequirements, RiskKeywordCounts,
};
use super::model::{
    AiRiskTier, ComplianceFinding, EuComplianceResult, ObligationResult, ObligationStatus,
};

const DEFAULT_EU_KEYWORDS_PATH: &str = "config/eu_risk_keywords.json";
const EU_KEYWORDS_PATH_ENV: &str = "PROMPT_SENTINEL_EU_KEYWORDS_PATH";

const DEFAULT_UNACCEPTABLE_KEYWORDS: &[&str] = &[
    "social scoring",
    "biometric surveillance",
    "biometric categorization",
    "emotion recognition in workplace",
    "emotion recognition in school",
    "manipulative subliminal",
];

const DEFAULT_HIGH_KEYWORDS: &[&str] = &[
    "employment",
    "hiring",
    "education",
    "credit",
    "insurance",
    "critical infrastructure",
    "law enforcement",
    "migration",
    "asylum",
    "border control",
    "justice",
    "judicial",
    "essential public service",
    "medical triage",
];

const DEFAULT_LIMITED_KEYWORDS: &[&str] = &[
    "chatbot",
    "recommendation",
    "generative assistant",
    "customer support bot",
    "deepfake",
];

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct EuKeywordOverrides {
    #[serde(default)]
    pub additional_unacceptable_keywords: Vec<String>,
    #[serde(default)]
    pub additional_high_keywords: Vec<String>,
    #[serde(default)]
    pub additional_limited_keywords: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EuRiskKeywordConfig {
    #[serde(default = "default_unacceptable_keywords")]
    unacceptable: Vec<String>,
    #[serde(default = "default_high_keywords")]
    high: Vec<String>,
    #[serde(default = "default_limited_keywords")]
    limited: Vec<String>,
}

impl Default for EuRiskKeywordConfig {
    fn default() -> Self {
        Self {
            unacceptable: default_unacceptable_keywords(),
            high: default_high_keywords(),
            limited: default_limited_keywords(),
        }
    }
}

/// Global configuration manager with runtime reloading support
#[derive(Clone, Debug)]
struct ConfigManager {
    config: Arc<RwLock<EuRiskKeywordConfig>>,
}

impl ConfigManager {
    fn new() -> Self {
        let config = load_risk_keywords();
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    fn get_config(&self) -> EuRiskKeywordConfig {
        let guard = self.config.read().unwrap();
        guard.clone()
    }

    fn update_config(&self, new_config: EuRiskKeywordConfig) -> Result<(), std::io::Error> {
        let mut guard = self.config.write().unwrap();

        // Save to file first
        save_risk_keywords(&new_config)?;

        // Update in-memory config
        *guard = new_config;

        Ok(())
    }
}

// Global configuration instance
lazy_static::lazy_static! {
    static ref CONFIG_MANAGER: ConfigManager = ConfigManager::new();
}

#[derive(Clone, Debug, Default)]
pub struct EuLawComplianceService;

impl EuLawComplianceService {
    /// Check compliance for a prompt/use-case and return structured result
    pub fn check_prompt(&self, prompt: &str) -> EuComplianceResult {
        self.check_prompt_with_overrides(prompt, None)
    }

    /// Check compliance for a prompt/use-case using optional tenant/workspace keyword overlays.
    pub fn check_prompt_with_overrides(
        &self,
        prompt: &str,
        overrides: Option<&EuKeywordOverrides>,
    ) -> EuComplianceResult {
        let risk_tier = classify_risk_with_overrides(prompt, overrides);
        let mut obligations = Vec::new();
        let mut findings = Vec::new();

        // Article 5 - Prohibited Practices (applicable from Feb 2, 2025)
        let prohibited_status = if matches!(risk_tier, AiRiskTier::Unacceptable) {
            findings.push(ComplianceFinding {
                code: "EU-RISK-001".to_owned(),
                detail: "Prompt matches a prohibited-risk category under EU AI Act Article 5."
                    .to_owned(),
            });
            ObligationStatus::Gap
        } else {
            ObligationStatus::Met
        };
        obligations.push(ObligationResult {
            id: "ART5-PROHIBITED".to_owned(),
            name: "Prohibited AI Practices".to_owned(),
            legal_basis: "Article 5, EU AI Act (Regulation 2024/1689)".to_owned(),
            status: prohibited_status,
            detail: if matches!(risk_tier, AiRiskTier::Unacceptable) {
                Some("Use case matches prohibited practices: social scoring, biometric surveillance, emotion recognition in workplace/school, or manipulative content.".to_owned())
            } else {
                None
            },
            applicable_from: Some("2025-02-02".to_owned()),
        });

        // Article 4 - AI Literacy (applicable from Feb 2, 2025)
        obligations.push(ObligationResult {
            id: "ART4-LITERACY".to_owned(),
            name: "AI Literacy".to_owned(),
            legal_basis: "Article 4, EU AI Act (Regulation 2024/1689)".to_owned(),
            status: ObligationStatus::Met, // Assumed met by using this compliance framework
            detail: Some("Deployers must ensure staff have sufficient AI literacy.".to_owned()),
            applicable_from: Some("2025-02-02".to_owned()),
        });

        // Article 50 - Transparency (applicable based on risk tier)
        let transparency_status = match risk_tier {
            AiRiskTier::Unacceptable | AiRiskTier::High | AiRiskTier::Limited => {
                ObligationStatus::Partial // Demo assumes no transparency notice yet
            }
            AiRiskTier::Minimal => ObligationStatus::NotApplicable,
        };
        if matches!(transparency_status, ObligationStatus::Partial) {
            findings.push(ComplianceFinding {
                code: "EU-TRN-002".to_owned(),
                detail: "Transparency notice required for this risk tier.".to_owned(),
            });
        }
        obligations.push(ObligationResult {
            id: "ART50-TRANSPARENCY".to_owned(),
            name: "Transparency Obligations".to_owned(),
            legal_basis: "Article 50, EU AI Act (Regulation 2024/1689)".to_owned(),
            status: transparency_status,
            detail: Some(
                "Users must be informed they are interacting with an AI system.".to_owned(),
            ),
            applicable_from: Some("2026-08-02".to_owned()),
        });

        // High-risk specific obligations
        if matches!(risk_tier, AiRiskTier::High) {
            // Article 9 - Risk Management
            obligations.push(ObligationResult {
                id: "ART9-RISK-MGMT".to_owned(),
                name: "Risk Management System".to_owned(),
                legal_basis: "Article 9, EU AI Act (Regulation 2024/1689)".to_owned(),
                status: ObligationStatus::Partial,
                detail: Some("High-risk AI requires documented risk management system.".to_owned()),
                applicable_from: Some("2026-08-02".to_owned()),
            });

            // Article 14 - Human Oversight
            obligations.push(ObligationResult {
                id: "ART14-OVERSIGHT".to_owned(),
                name: "Human Oversight".to_owned(),
                legal_basis: "Article 14, EU AI Act (Regulation 2024/1689)".to_owned(),
                status: ObligationStatus::Partial,
                detail: Some(
                    "High-risk AI must enable human oversight and intervention.".to_owned(),
                ),
                applicable_from: Some("2026-08-02".to_owned()),
            });

            findings.push(ComplianceFinding {
                code: "EU-HIGH-001".to_owned(),
                detail: "High-risk use case detected. Additional compliance controls required."
                    .to_owned(),
            });
        }

        let compliant = !matches!(risk_tier, AiRiskTier::Unacceptable)
            && !obligations
                .iter()
                .any(|o| matches!(o.status, ObligationStatus::Gap));

        EuComplianceResult {
            risk_tier,
            compliant,
            obligations,
            findings,
            scope_disclaimer: "This compliance check applies to a defined limited-risk EU chatbot use case. It does not constitute legal advice or guarantee compliance for all deployment scenarios.".to_owned(),
        }
    }

    pub fn check(&self, request: ComplianceCheckRequest) -> ComplianceCheckResponse {
        let intended_use = request.intended_use.trim();
        let risk_tier = classify_risk(intended_use);
        let mut findings = Vec::new();

        if intended_use.len() < 8 {
            findings.push(ComplianceFinding {
                code: "EU-SCOPE-001".to_owned(),
                detail: "Intended-use description is too short for reliable risk classification."
                    .to_owned(),
            });
        }

        if matches!(risk_tier, AiRiskTier::Unacceptable) {
            findings.push(ComplianceFinding {
                code: "EU-RISK-001".to_owned(),
                detail: "Intended use matches a prohibited-risk category under EU AI Act controls."
                    .to_owned(),
            });
        }

        if matches!(risk_tier, AiRiskTier::High | AiRiskTier::Unacceptable) {
            if !request.technical_documentation_available {
                findings.push(ComplianceFinding {
                    code: "EU-DOC-001".to_owned(),
                    detail: "Technical documentation is missing.".to_owned(),
                });
            }
            if !request.transparency_notice_available {
                findings.push(ComplianceFinding {
                    code: "EU-TRN-001".to_owned(),
                    detail: "Transparency notice is missing.".to_owned(),
                });
            }
            if !request.copyright_controls_available {
                findings.push(ComplianceFinding {
                    code: "EU-CPY-001".to_owned(),
                    detail: "Copyright safeguard documentation is missing.".to_owned(),
                });
            }
        } else if matches!(risk_tier, AiRiskTier::Limited) && !request.transparency_notice_available
        {
            findings.push(ComplianceFinding {
                code: "EU-TRN-002".to_owned(),
                detail: "Limited-risk systems must include a transparency notice.".to_owned(),
            });
        }

        let compliant = !matches!(risk_tier, AiRiskTier::Unacceptable) && findings.is_empty();
        ComplianceCheckResponse {
            risk_tier,
            compliant,
            findings,
        }
    }

    pub fn generate_compliance_report(
        &self,
        request: ComplianceReportRequest,
    ) -> ComplianceReportResponse {
        let check_response = self.check(ComplianceCheckRequest {
            intended_use: request.intended_use,
            technical_documentation_available: true,
            transparency_notice_available: true,
            copyright_controls_available: true,
        });

        ComplianceReportResponse {
            report_id: format!("COMP-REPORT-{}", request.correlation_id),
            risk_tier: check_response.risk_tier,
            compliant: check_response.compliant,
            findings: check_response.findings,
            generated_at: Utc::now(),
            pdf_available: request.generate_pdf,
            pdf_url: if request.generate_pdf {
                Some(format!(
                    "/api/compliance/reports/{}/pdf",
                    request.correlation_id
                ))
            } else {
                None
            },
        }
    }

    pub fn get_current_configuration(&self) -> ComplianceConfigurationSummary {
        let keywords = CONFIG_MANAGER.get_config();

        ComplianceConfigurationSummary {
            risk_keyword_counts: RiskKeywordCounts {
                unacceptable: keywords.unacceptable.len(),
                high: keywords.high.len(),
                limited: keywords.limited.len(),
            },
            documentation_requirements: DocumentationRequirements {
                technical_documentation_required: Some(true),
                transparency_notice_required: Some(true),
                copyright_controls_required: Some(true),
            },
        }
    }

    pub fn update_configuration(
        &self,
        request: ComplianceConfigurationRequest,
    ) -> ComplianceConfigurationResponse {
        // Load current configuration
        let current_config = CONFIG_MANAGER.get_config();
        let mut new_config = current_config.clone();

        // Apply updates from request
        if let Some(risk_thresholds) = request.risk_thresholds {
            if let Some(keywords) = risk_thresholds
                .unacceptable_keywords
                .filter(|k| !k.is_empty())
            {
                new_config.unacceptable = keywords;
            }
            if let Some(keywords) = risk_thresholds.high_risk_keywords.filter(|k| !k.is_empty()) {
                new_config.high = keywords;
            }
            if let Some(keywords) = risk_thresholds
                .limited_risk_keywords
                .filter(|k| !k.is_empty())
            {
                new_config.limited = keywords;
            }
        }

        // Save updated configuration to file and memory
        match CONFIG_MANAGER.update_config(new_config) {
            Ok(_) => ComplianceConfigurationResponse {
                status: "success".to_string(),
                message: "Configuration updated successfully".to_string(),
                current_configuration: self.get_current_configuration(),
            },
            Err(e) => ComplianceConfigurationResponse {
                status: "error".to_string(),
                message: format!("Failed to update configuration: {}", e),
                current_configuration: self.get_current_configuration(),
            },
        }
    }
}

fn classify_risk(intended_use: &str) -> AiRiskTier {
    classify_risk_with_overrides(intended_use, None)
}

fn classify_risk_with_overrides(
    intended_use: &str,
    overrides: Option<&EuKeywordOverrides>,
) -> AiRiskTier {
    let text = intended_use.to_ascii_lowercase();
    let keywords = CONFIG_MANAGER.get_config();

    let unacceptable = merged_keywords(
        &keywords.unacceptable,
        overrides.map(|value| value.additional_unacceptable_keywords.as_slice()),
    );
    let high = merged_keywords(
        &keywords.high,
        overrides.map(|value| value.additional_high_keywords.as_slice()),
    );
    let limited = merged_keywords(
        &keywords.limited,
        overrides.map(|value| value.additional_limited_keywords.as_slice()),
    );

    if contains_any(&text, &unacceptable) {
        AiRiskTier::Unacceptable
    } else if contains_any(&text, &high) {
        AiRiskTier::High
    } else if contains_any(&text, &limited) {
        AiRiskTier::Limited
    } else {
        AiRiskTier::Minimal
    }
}

fn load_risk_keywords() -> EuRiskKeywordConfig {
    let path =
        std::env::var(EU_KEYWORDS_PATH_ENV).unwrap_or_else(|_| DEFAULT_EU_KEYWORDS_PATH.to_owned());

    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<EuRiskKeywordConfig>(&content).ok())
        .unwrap_or_default()
}

fn contains_any(text: &str, keywords: &[String]) -> bool {
    keywords.iter().any(|keyword| text.contains(keyword))
}

fn merged_keywords(base: &[String], additional: Option<&[String]>) -> Vec<String> {
    let mut merged = base
        .iter()
        .map(|keyword| keyword.trim().to_ascii_lowercase())
        .filter(|keyword| !keyword.is_empty())
        .collect::<Vec<_>>();

    if let Some(additional) = additional {
        for keyword in additional {
            let normalized = keyword.trim().to_ascii_lowercase();
            if normalized.is_empty() || merged.iter().any(|item| item == &normalized) {
                continue;
            }
            merged.push(normalized);
        }
    }

    merged
}

fn save_risk_keywords(config: &EuRiskKeywordConfig) -> Result<(), std::io::Error> {
    let path =
        std::env::var(EU_KEYWORDS_PATH_ENV).unwrap_or_else(|_| DEFAULT_EU_KEYWORDS_PATH.to_owned());

    // Create directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    fs::write(path, content)
}

fn default_unacceptable_keywords() -> Vec<String> {
    DEFAULT_UNACCEPTABLE_KEYWORDS
        .iter()
        .map(|keyword| (*keyword).to_owned())
        .collect()
}

fn default_high_keywords() -> Vec<String> {
    DEFAULT_HIGH_KEYWORDS
        .iter()
        .map(|keyword| (*keyword).to_owned())
        .collect()
}

fn default_limited_keywords() -> Vec<String> {
    DEFAULT_LIMITED_KEYWORDS
        .iter()
        .map(|keyword| (*keyword).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_keyword_overrides_raise_risk_tier() {
        let service = EuLawComplianceService;
        let overrides = EuKeywordOverrides {
            additional_unacceptable_keywords: vec!["predict criminality by dna".to_string()],
            additional_high_keywords: vec![],
            additional_limited_keywords: vec![],
        };

        let response = service.check_prompt_with_overrides(
            "Build a tool to predict criminality by DNA profile.",
            Some(&overrides),
        );

        assert_eq!(response.risk_tier, AiRiskTier::Unacceptable);
    }

    #[test]
    fn tenant_keyword_overrides_default_to_base_when_empty() {
        let service = EuLawComplianceService;
        let response = service.check_prompt_with_overrides(
            "Customer support chatbot for FAQ triage",
            Some(&EuKeywordOverrides::default()),
        );

        assert_eq!(response.risk_tier, AiRiskTier::Limited);
    }
}
