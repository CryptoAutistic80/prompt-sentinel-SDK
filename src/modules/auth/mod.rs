use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::warn;

use crate::config::settings::{AppSettings, AuthCredentialConfig};

const DEFAULT_ACCESS_LOG_LIMIT: usize = 200;
const MAX_ACCESS_LOG_ENTRIES: usize = 5_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContext {
    pub principal_id: String,
    pub role: String,
    pub is_service_account: bool,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug)]
struct CredentialEntry {
    key_id: String,
    label: Option<String>,
    role: String,
    scopes: Vec<String>,
    is_service_account: bool,
    created_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
}

impl CredentialEntry {
    fn metadata(&self) -> CredentialMetadata {
        CredentialMetadata {
            key_id: self.key_id.clone(),
            label: self.label.clone(),
            role: self.role.clone(),
            scopes: self.scopes.clone(),
            is_service_account: self.is_service_account,
            created_at: self.created_at,
            rotated_at: self.rotated_at,
        }
    }

    fn has_permission(&self, permission: &str) -> bool {
        if self.scopes.is_empty() {
            let role_permissions = permissions_for_role(&self.role);
            return role_permissions
                .iter()
                .any(|candidate| permission_match(candidate, permission));
        }

        self.scopes
            .iter()
            .any(|candidate| permission_match(candidate, permission))
    }
}

#[derive(Clone, Debug)]
struct RateLimiter {
    max_requests: u32,
    window: Duration,
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl RateLimiter {
    fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn allow(&self, principal_key: &str) -> bool {
        let Ok(mut guard) = self.buckets.lock() else {
            return false;
        };

        let now = Instant::now();
        let bucket = guard
            .entry(principal_key.to_owned())
            .or_insert_with(VecDeque::new);

        while let Some(front) = bucket.front() {
            if now.duration_since(*front) > self.window {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() as u32 >= self.max_requests {
            return false;
        }

        bucket.push_back(now);
        true
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialMetadata {
    pub key_id: String,
    pub label: Option<String>,
    pub role: String,
    pub scopes: Vec<String>,
    pub is_service_account: bool,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessAuditEvent {
    pub timestamp: DateTime<Utc>,
    pub principal_id: Option<String>,
    pub role: Option<String>,
    pub method: String,
    pub path: String,
    pub outcome: String,
    pub required_permission: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RotateCredentialCommand {
    pub old_token: String,
    pub new_token: String,
    pub role: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub label: Option<String>,
    pub is_service_account: Option<bool>,
}

#[derive(Clone)]
pub struct AuthService {
    enabled: bool,
    credentials: Arc<Mutex<HashMap<String, CredentialEntry>>>,
    rate_limiter: Option<RateLimiter>,
    access_events: Arc<Mutex<VecDeque<AccessAuditEvent>>>,
}

impl AuthService {
    pub fn from_settings(settings: &AppSettings) -> Self {
        let mut credentials = HashMap::new();
        register_credentials(&mut credentials, &settings.auth_api_keys, false);
        register_credentials(&mut credentials, &settings.auth_service_tokens, true);

        let rate_limiter = if settings.auth_enabled && settings.auth_rate_limit_per_minute > 0 {
            Some(RateLimiter::new(
                settings.auth_rate_limit_per_minute,
                Duration::from_secs(60),
            ))
        } else {
            None
        };

        Self {
            enabled: settings.auth_enabled,
            credentials: Arc::new(Mutex::new(credentials)),
            rate_limiter,
            access_events: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn authorize_request(
        &self,
        headers: &HeaderMap,
        method: &Method,
        path: &str,
    ) -> Result<Option<AuthContext>, AuthError> {
        if !self.enabled {
            return Ok(None);
        }

        let required_permission = required_permission(method, path).map(ToOwned::to_owned);
        let method_str = method.as_str().to_owned();
        let path_str = path.to_owned();

        let token = extract_token(headers).ok_or_else(|| {
            self.record_access(AccessAuditEvent {
                timestamp: Utc::now(),
                principal_id: None,
                role: None,
                method: method_str.clone(),
                path: path_str.clone(),
                outcome: "deny_missing_credentials".to_string(),
                required_permission: required_permission.clone(),
                detail: None,
            });
            AuthError::MissingCredentials
        })?;

        let entry = {
            let Ok(guard) = self.credentials.lock() else {
                self.record_access(AccessAuditEvent {
                    timestamp: Utc::now(),
                    principal_id: None,
                    role: None,
                    method: method_str,
                    path: path_str,
                    outcome: "deny_internal_error".to_string(),
                    required_permission,
                    detail: Some("auth credential storage lock poisoned".to_string()),
                });
                return Err(AuthError::InternalError);
            };

            guard.get(token).cloned()
        }
        .ok_or_else(|| {
            self.record_access(AccessAuditEvent {
                timestamp: Utc::now(),
                principal_id: None,
                role: None,
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                outcome: "deny_invalid_credentials".to_string(),
                required_permission: required_permission.clone(),
                detail: None,
            });
            AuthError::InvalidCredentials
        })?;

        if let Some(rate_limiter) = &self.rate_limiter
            && !rate_limiter.allow(token)
        {
            self.record_access(AccessAuditEvent {
                timestamp: Utc::now(),
                principal_id: Some(entry.key_id.clone()),
                role: Some(entry.role.clone()),
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                outcome: "deny_rate_limited".to_string(),
                required_permission: required_permission.clone(),
                detail: None,
            });
            return Err(AuthError::RateLimited);
        }

        if let Some(permission) = required_permission.as_deref()
            && !entry.has_permission(permission)
        {
            self.record_access(AccessAuditEvent {
                timestamp: Utc::now(),
                principal_id: Some(entry.key_id.clone()),
                role: Some(entry.role.clone()),
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                outcome: "deny_forbidden".to_string(),
                required_permission: required_permission.clone(),
                detail: Some(format!("missing required permission `{permission}`")),
            });
            return Err(AuthError::Forbidden {
                required_permission: permission.to_owned(),
            });
        }

        self.record_access(AccessAuditEvent {
            timestamp: Utc::now(),
            principal_id: Some(entry.key_id.clone()),
            role: Some(entry.role.clone()),
            method: method.as_str().to_owned(),
            path: path.to_owned(),
            outcome: "allow".to_string(),
            required_permission,
            detail: None,
        });

        Ok(Some(AuthContext {
            principal_id: entry.key_id,
            role: entry.role,
            is_service_account: entry.is_service_account,
            scopes: entry.scopes,
        }))
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialMetadata>, AuthAdminError> {
        if !self.enabled {
            return Err(AuthAdminError::NotEnabled);
        }

        let guard = self
            .credentials
            .lock()
            .map_err(|_| AuthAdminError::StoragePoisoned)?;

        let mut credentials = guard
            .values()
            .map(CredentialEntry::metadata)
            .collect::<Vec<_>>();
        credentials.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        Ok(credentials)
    }

    pub fn rotate_credential(
        &self,
        command: RotateCredentialCommand,
    ) -> Result<CredentialMetadata, AuthAdminError> {
        if !self.enabled {
            return Err(AuthAdminError::NotEnabled);
        }

        let old_token = command.old_token.trim();
        let new_token = command.new_token.trim();
        if old_token.is_empty() || new_token.is_empty() {
            return Err(AuthAdminError::InvalidRequest(
                "old_token and new_token are required".to_string(),
            ));
        }
        if old_token == new_token {
            return Err(AuthAdminError::InvalidRequest(
                "new_token must differ from old_token".to_string(),
            ));
        }

        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| AuthAdminError::StoragePoisoned)?;

        let mut entry = guard
            .remove(old_token)
            .ok_or(AuthAdminError::CredentialNotFound)?;

        if guard.contains_key(new_token) {
            guard.insert(old_token.to_owned(), entry);
            return Err(AuthAdminError::NewTokenAlreadyExists);
        }

        if let Some(role) = command.role {
            let role = role.trim();
            if role.is_empty() {
                guard.insert(old_token.to_owned(), entry);
                return Err(AuthAdminError::InvalidRequest(
                    "role cannot be empty".to_string(),
                ));
            }
            entry.role = role.to_owned();
        }

        if let Some(scopes) = command.scopes {
            entry.scopes = scopes
                .into_iter()
                .map(|scope| scope.trim().to_owned())
                .filter(|scope| !scope.is_empty())
                .collect();
        }

        if let Some(label) = command.label {
            let label = label.trim();
            entry.label = if label.is_empty() {
                None
            } else {
                Some(label.to_owned())
            };
        }

        if let Some(is_service_account) = command.is_service_account {
            entry.is_service_account = is_service_account;
        }

        entry.key_id = credential_fingerprint(new_token);
        entry.rotated_at = Some(Utc::now());

        let metadata = entry.metadata();
        guard.insert(new_token.to_owned(), entry);
        Ok(metadata)
    }

    pub fn access_events(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<AccessAuditEvent>, AuthAdminError> {
        if !self.enabled {
            return Err(AuthAdminError::NotEnabled);
        }

        let limit = limit.unwrap_or(DEFAULT_ACCESS_LOG_LIMIT).clamp(1, 1_000);

        let guard = self
            .access_events
            .lock()
            .map_err(|_| AuthAdminError::StoragePoisoned)?;

        Ok(guard.iter().rev().take(limit).cloned().collect())
    }

    fn record_access(&self, event: AccessAuditEvent) {
        let Ok(mut guard) = self.access_events.lock() else {
            return;
        };

        guard.push_back(event);
        while guard.len() > MAX_ACCESS_LOG_ENTRIES {
            guard.pop_front();
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing API credentials")]
    MissingCredentials,
    #[error("invalid API credentials")]
    InvalidCredentials,
    #[error("forbidden: missing permission `{required_permission}`")]
    Forbidden { required_permission: String },
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("authentication system unavailable")]
    InternalError,
}

#[derive(Debug, Error)]
pub enum AuthAdminError {
    #[error("authentication is disabled")]
    NotEnabled,
    #[error("credential not found")]
    CredentialNotFound,
    #[error("new token already exists")]
    NewTokenAlreadyExists,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("auth storage unavailable")]
    StoragePoisoned,
}

fn register_credentials(
    target: &mut HashMap<String, CredentialEntry>,
    source: &[AuthCredentialConfig],
    is_service_account: bool,
) {
    for credential in source {
        if credential.token.trim().is_empty() {
            continue;
        }

        let entry = CredentialEntry {
            key_id: credential_fingerprint(&credential.token),
            label: credential.label.clone(),
            role: credential.role.clone(),
            scopes: credential.scopes.clone(),
            is_service_account,
            created_at: Utc::now(),
            rotated_at: None,
        };

        if target.insert(credential.token.clone(), entry).is_some() {
            warn!("Duplicate auth credential detected; keeping latest assignment");
        }
    }
}

fn extract_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let token = value.trim();
        if !token.is_empty() {
            return Some(token);
        }
    }

    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)?;

    if bearer.is_empty() {
        None
    } else {
        Some(bearer)
    }
}

fn required_permission(method: &Method, path: &str) -> Option<&'static str> {
    match (method.as_str(), path) {
        ("POST", "/api/compliance/check") => Some("check:invoke"),
        ("POST", "/api/audit/trail") => Some("audit:read"),
        ("POST", "/api/compliance/report") => Some("reports:read"),
        ("GET", "/api/compliance/config") => Some("config:read"),
        ("POST", "/api/compliance/config") => Some("config:write"),
        ("GET", "/api/mistral/health") => Some("llm:read"),
        ("GET", "/api/llm/health") => Some("llm:read"),
        ("GET", "/v1/models") => Some("llm:read"),
        ("GET", "/api/auth/keys") => Some("auth:read"),
        ("POST", "/api/auth/keys/rotate") => Some("auth:write"),
        ("GET", "/api/auth/access-log") => Some("auth:read"),
        _ => None,
    }
}

fn permissions_for_role(role: &str) -> &'static [&'static str] {
    match role {
        "compliance_admin" => &["*"],
        "compliance_viewer" => &["audit:read", "reports:read", "config:read", "llm:read"],
        "developer" => &["check:invoke", "audit:read", "llm:read"],
        "service_account" => &["check:invoke", "llm:read"],
        _ => &[],
    }
}

fn permission_match(candidate: &str, required: &str) -> bool {
    if candidate == "*" || candidate == required {
        return true;
    }

    if let Some(prefix) = candidate.strip_suffix('*') {
        return required.starts_with(prefix);
    }

    false
}

fn credential_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let hex = hex::encode(digest);
    format!("key_{}", &hex[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_permissions_match_expected_behavior() {
        assert!(permission_match("audit:*", "audit:read"));
        assert!(permission_match("check:invoke", "check:invoke"));
        assert!(!permission_match("reports:read", "reports:write"));
    }

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.allow("abc"));
        assert!(limiter.allow("abc"));
        assert!(!limiter.allow("abc"));
    }

    #[test]
    fn rotating_credential_changes_fingerprint() {
        let settings = AppSettings {
            server_port: 3000,
            llm_backend: crate::config::settings::LlmBackend::OpenAICompat,
            llm_api_key: None,
            llm_base_url: "http://localhost:11434/v1".to_string(),
            generation_model: "model".to_string(),
            moderation_model: Some("model".to_string()),
            embedding_model: "model".to_string(),
            cors_allowed_origins: vec![],
            llm_request_timeout_secs: 60,
            llm_connect_timeout_secs: 5,
            llm_pool_max_idle_per_host: 5,
            llm_pool_idle_timeout_secs: 30,
            llm_circuit_breaker_failure_threshold: 5,
            llm_circuit_breaker_open_duration_secs: 30,
            auth_enabled: true,
            auth_api_keys: vec![AuthCredentialConfig {
                label: None,
                token: "old-token".to_string(),
                role: "compliance_admin".to_string(),
                scopes: vec![],
            }],
            auth_service_tokens: vec![],
            auth_rate_limit_per_minute: 60,
            bias_threshold: 0.35,
            max_input_length: 1024,
            semantic_medium_threshold: 0.70,
            semantic_high_threshold: 0.80,
            semantic_decision_margin: 0.02,
        };

        let service = AuthService::from_settings(&settings);
        let before = service
            .list_credentials()
            .expect("credentials")
            .first()
            .expect("one credential")
            .key_id
            .clone();

        let rotated = service
            .rotate_credential(RotateCredentialCommand {
                old_token: "old-token".to_string(),
                new_token: "new-token".to_string(),
                role: None,
                scopes: None,
                label: None,
                is_service_account: None,
            })
            .expect("rotation should work");

        assert_ne!(before, rotated.key_id);
    }
}
