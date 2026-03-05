use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::policy::{AuditStoragePolicy, AuditStoragePolicyResolver};
use super::proof::{AuditProof, chain_hash, hash_record};
use super::storage::{AuditStorage, AuditStorageError, StoredAuditRecord};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    pub correlation_id: String,
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub original_prompt: String,
    pub sanitized_prompt: String,
    pub firewall_action: String,
    pub firewall_reasons: Vec<String>,
    /// Semantic risk score (0.0 - 1.0)
    pub semantic_risk_score: Option<f32>,
    /// ID of matched attack template
    pub semantic_template_id: Option<String>,
    /// Category of matched attack template
    pub semantic_category: Option<String>,
    pub bias_score: f32,
    pub bias_level: String,
    pub input_moderation_flagged: bool,
    pub output_moderation_flagged: bool,
    pub final_status: String,
    /// Human-readable explanation of the decision
    pub final_reason: String,
    pub model_used: Option<String>,
    /// Short preview of the output (first 160 chars)
    pub output_preview: Option<String>,
    /// Full model response text (for complete audit trail)
    pub full_output_text: Option<String>,
    /// Categories flagged by output moderation
    pub output_moderation_categories: Vec<String>,
    /// EU AI Act risk tier classification
    pub eu_risk_tier: Option<String>,
    /// EU AI Act compliance findings
    pub eu_findings: Option<Vec<String>>,
    /// Token count for the request (prompt + completion)
    pub tokens_used: Option<u32>,
    /// Response generation latency in milliseconds
    pub response_latency_ms: Option<u64>,
    /// Detected language of the original prompt
    pub detected_language: Option<String>,
    /// Whether the response was translated back to original language
    pub was_translated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthAccessAuditEvent {
    pub correlation_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub principal_id: Option<String>,
    pub role: Option<String>,
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub method: String,
    pub path: String,
    pub outcome: String,
    pub required_permission: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TypedAuditPayload<T> {
    event_type: String,
    event: T,
}

#[derive(Clone)]
pub struct AuditLogger {
    storage: Arc<dyn AuditStorage>,
    storage_policy_resolver: Option<AuditStoragePolicyResolver>,
}

impl AuditLogger {
    pub fn new(storage: Arc<dyn AuditStorage>) -> Self {
        Self {
            storage,
            storage_policy_resolver: None,
        }
    }

    pub fn with_storage_policy_resolver(mut self, resolver: AuditStoragePolicyResolver) -> Self {
        self.storage_policy_resolver = Some(resolver);
        self
    }

    pub fn log_event(&self, event: AuditEvent) -> Result<AuditProof, AuditError> {
        let correlation_id = event.correlation_id.clone();
        let tenant_id = event.tenant_id.clone();
        let workspace_id = event.workspace_id.clone();
        let storage_policy =
            self.resolve_storage_policy(tenant_id.as_deref(), workspace_id.as_deref());
        let payload = serde_json::to_string(&event)?;
        self.append_payload(
            correlation_id,
            Utc::now(),
            payload,
            tenant_id,
            workspace_id,
            storage_policy,
        )
    }

    pub fn log_auth_access_event(
        &self,
        event: AuthAccessAuditEvent,
    ) -> Result<AuditProof, AuditError> {
        let correlation_id = normalize_correlation_id(event.correlation_id.clone())
            .unwrap_or_else(|| format!("auth-{}", Uuid::new_v4().simple()));
        let timestamp = event.timestamp;
        let tenant_id = event.tenant_id.clone();
        let workspace_id = event.workspace_id.clone();
        let storage_policy =
            self.resolve_storage_policy(tenant_id.as_deref(), workspace_id.as_deref());
        let payload = serde_json::to_string(&TypedAuditPayload {
            event_type: "auth_access".to_string(),
            event,
        })?;

        self.append_payload(
            correlation_id,
            timestamp,
            payload,
            tenant_id,
            workspace_id,
            storage_policy,
        )
    }

    fn resolve_storage_policy(
        &self,
        tenant_id: Option<&str>,
        workspace_id: Option<&str>,
    ) -> AuditStoragePolicy {
        self.storage_policy_resolver
            .as_ref()
            .map(|resolver| resolver.resolve(tenant_id, workspace_id))
            .unwrap_or_default()
    }

    fn append_payload(
        &self,
        correlation_id: String,
        timestamp: DateTime<Utc>,
        payload: String,
        tenant_id: Option<String>,
        workspace_id: Option<String>,
        storage_policy: AuditStoragePolicy,
    ) -> Result<AuditProof, AuditError> {
        let record_hash = hash_record(&payload);
        let previous_chain = self.storage.latest_chain_hash()?;
        let chain_hash = chain_hash(previous_chain.as_deref(), &record_hash);

        let proof = AuditProof {
            algorithm: "sha256".to_owned(),
            record_hash,
            chain_hash,
        };

        let record = StoredAuditRecord {
            correlation_id,
            timestamp,
            payload,
            proof: proof.clone(),
            tenant_id,
            workspace_id,
            data_region: storage_policy.data_region,
            storage_policy: storage_policy.storage_policy,
            retention_days: storage_policy.retention_days,
        };
        self.storage.append(record)?;

        Ok(proof)
    }

    pub fn records(&self) -> Result<Vec<StoredAuditRecord>, AuditError> {
        self.storage.all().map_err(Into::into)
    }

    pub fn storage(&self) -> &Arc<dyn AuditStorage> {
        &self.storage
    }
}

fn normalize_correlation_id(raw: Option<String>) -> Option<String> {
    raw.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to serialize audit event: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("audit storage failure: {0}")]
    Storage(#[from] AuditStorageError),
}
