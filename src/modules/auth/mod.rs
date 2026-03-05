use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::warn;

use crate::config::settings::{AppSettings, AuthCredentialConfig};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContext {
    pub principal_id: String,
    pub role: String,
    pub is_service_account: bool,
}

#[derive(Clone, Debug)]
struct CredentialEntry {
    role: String,
    is_service_account: bool,
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

#[derive(Clone)]
pub struct AuthService {
    enabled: bool,
    credentials: HashMap<String, CredentialEntry>,
    rate_limiter: Option<RateLimiter>,
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
            credentials,
            rate_limiter,
        }
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

        let token = extract_token(headers).ok_or(AuthError::MissingCredentials)?;
        let entry = self
            .credentials
            .get(token)
            .ok_or(AuthError::InvalidCredentials)?;

        if let Some(rate_limiter) = &self.rate_limiter
            && !rate_limiter.allow(token)
        {
            return Err(AuthError::RateLimited);
        }

        if let Some(required_permission) = required_permission(method, path)
            && !role_has_permission(&entry.role, required_permission)
        {
            return Err(AuthError::Forbidden {
                required_permission: required_permission.to_owned(),
            });
        }

        Ok(Some(AuthContext {
            principal_id: credential_fingerprint(token),
            role: entry.role.clone(),
            is_service_account: entry.is_service_account,
        }))
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

        if target
            .insert(
                credential.token.clone(),
                CredentialEntry {
                    role: credential.role.clone(),
                    is_service_account,
                },
            )
            .is_some()
        {
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
        _ => None,
    }
}

fn role_has_permission(role: &str, permission: &str) -> bool {
    let permissions = permissions_for_role(role);
    permissions
        .iter()
        .any(|candidate| permission_match(candidate, permission))
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
    fn developer_can_invoke_check() {
        assert!(role_has_permission("developer", "check:invoke"));
        assert!(!role_has_permission("developer", "config:write"));
    }

    #[test]
    fn wildcard_admin_has_all_permissions() {
        assert!(role_has_permission("compliance_admin", "anything:anything"));
    }

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.allow("abc"));
        assert!(limiter.allow("abc"));
        assert!(!limiter.allow("abc"));
    }
}
