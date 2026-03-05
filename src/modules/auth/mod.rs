use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

use crate::config::settings::{AppSettings, AuthCredentialConfig};

const DEFAULT_ACCESS_LOG_LIMIT: usize = 200;
const MAX_ACCESS_LOG_ENTRIES: usize = 5_000;
const CREDENTIAL_STORE_VERSION: u32 = 1;
const TOKEN_GENERATION_RETRIES: usize = 5;

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
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl CredentialEntry {
    fn metadata(&self) -> CredentialMetadata {
        let now = Utc::now();
        CredentialMetadata {
            key_id: self.key_id.clone(),
            label: self.label.clone(),
            role: self.role.clone(),
            scopes: self.scopes.clone(),
            is_service_account: self.is_service_account,
            created_at: self.created_at,
            rotated_at: self.rotated_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            active: self.is_active_at(now),
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

    fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_revoked() && !self.is_expired_at(now)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredCredential {
    token_hash: String,
    key_id: String,
    label: Option<String>,
    role: String,
    scopes: Vec<String>,
    is_service_account: bool,
    created_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl StoredCredential {
    fn from_runtime(token_hash: &str, entry: &CredentialEntry) -> Self {
        Self {
            token_hash: token_hash.to_owned(),
            key_id: entry.key_id.clone(),
            label: entry.label.clone(),
            role: entry.role.clone(),
            scopes: entry.scopes.clone(),
            is_service_account: entry.is_service_account,
            created_at: entry.created_at,
            rotated_at: entry.rotated_at,
            expires_at: entry.expires_at,
            revoked_at: entry.revoked_at,
        }
    }

    fn into_runtime(self) -> Option<(String, CredentialEntry)> {
        let token_hash = self.token_hash.trim().to_owned();
        if token_hash.is_empty() || self.key_id.trim().is_empty() || self.role.trim().is_empty() {
            return None;
        }

        Some((
            token_hash,
            CredentialEntry {
                key_id: self.key_id,
                label: self.label,
                role: self.role,
                scopes: self.scopes,
                is_service_account: self.is_service_account,
                created_at: self.created_at,
                rotated_at: self.rotated_at,
                expires_at: self.expires_at,
                revoked_at: self.revoked_at,
            },
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CredentialStoreSnapshot {
    version: u32,
    updated_at: DateTime<Utc>,
    credentials: Vec<StoredCredential>,
}

#[derive(Clone, Debug)]
struct CredentialStore {
    path: PathBuf,
}

impl CredentialStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Result<Option<HashMap<String, CredentialEntry>>, String> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.path).map_err(|error| {
            format!(
                "failed to read auth key store `{}`: {error}",
                self.path.display()
            )
        })?;

        let snapshot: CredentialStoreSnapshot =
            serde_json::from_str(&content).map_err(|error| {
                format!(
                    "failed to parse auth key store `{}`: {error}",
                    self.path.display()
                )
            })?;

        if snapshot.version != CREDENTIAL_STORE_VERSION {
            return Err(format!(
                "unsupported auth key store version {} in `{}`",
                snapshot.version,
                self.path.display()
            ));
        }

        let mut credentials = HashMap::new();
        for stored in snapshot.credentials {
            if let Some((token_hash, entry)) = stored.into_runtime() {
                credentials.insert(token_hash, entry);
            }
        }

        Ok(Some(credentials))
    }

    fn save(&self, credentials: &HashMap<String, CredentialEntry>) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create auth key store directory `{}`: {error}",
                    parent.display()
                )
            })?;
        }

        let mut records = credentials
            .iter()
            .map(|(token_hash, entry)| StoredCredential::from_runtime(token_hash, entry))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.key_id.cmp(&right.key_id));

        let payload = CredentialStoreSnapshot {
            version: CREDENTIAL_STORE_VERSION,
            updated_at: Utc::now(),
            credentials: records,
        };

        let encoded = serde_json::to_string_pretty(&payload).map_err(|error| {
            format!(
                "failed to encode auth key store payload for `{}`: {error}",
                self.path.display()
            )
        })?;

        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, encoded).map_err(|error| {
            format!(
                "failed to write auth key store temp file `{}`: {error}",
                temp_path.display()
            )
        })?;

        if let Err(error) = fs::rename(&temp_path, &self.path) {
            if self.path.exists() {
                let _ = fs::remove_file(&self.path);
                fs::rename(&temp_path, &self.path).map_err(|rename_error| {
                    format!(
                        "failed to replace auth key store `{}` after rename error `{error}`: {rename_error}",
                        self.path.display()
                    )
                })?;
            } else {
                return Err(format!(
                    "failed to move auth key store temp file `{}` into `{}`: {error}",
                    temp_path.display(),
                    self.path.display()
                ));
            }
        }

        Ok(())
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
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub active: bool,
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
    pub expires_in_seconds: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct GenerateCredentialCommand {
    pub role: String,
    pub scopes: Vec<String>,
    pub label: Option<String>,
    pub is_service_account: bool,
    pub expires_in_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeneratedCredential {
    pub token: String,
    pub credential: CredentialMetadata,
}

#[derive(Clone)]
pub struct AuthService {
    enabled: bool,
    credentials: Arc<Mutex<HashMap<String, CredentialEntry>>>,
    rate_limiter: Option<RateLimiter>,
    access_events: Arc<Mutex<VecDeque<AccessAuditEvent>>>,
    credential_store: Option<CredentialStore>,
    default_key_expiry_secs: Option<u64>,
}

impl AuthService {
    pub fn from_settings(settings: &AppSettings) -> Self {
        let mut credentials = HashMap::new();
        register_credentials(&mut credentials, &settings.auth_api_keys, false);
        register_credentials(&mut credentials, &settings.auth_service_tokens, true);

        let credential_store = settings
            .auth_key_store_path
            .as_ref()
            .map(|path| path.trim())
            .filter(|path| !path.is_empty())
            .map(|path| CredentialStore::new(PathBuf::from(path)));

        let mut loaded_from_store = false;
        if let Some(store) = &credential_store {
            match store.load() {
                Ok(Some(stored_credentials)) if !stored_credentials.is_empty() => {
                    credentials = stored_credentials;
                    loaded_from_store = true;
                }
                Ok(_) => {}
                Err(error) => {
                    warn!(
                        "Failed to load auth credential store from `{}`: {error}",
                        store.path.display()
                    );
                }
            }

            if !loaded_from_store
                && !credentials.is_empty()
                && let Err(error) = store.save(&credentials)
            {
                warn!(
                    "Failed to initialize auth credential store at `{}`: {error}",
                    store.path.display()
                );
            }
        }

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
            credential_store,
            default_key_expiry_secs: settings.auth_default_key_expiry_secs,
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

        let token_hash = hash_token(token);
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

            guard.get(&token_hash).cloned()
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

        if entry.is_revoked() {
            self.record_access(AccessAuditEvent {
                timestamp: Utc::now(),
                principal_id: Some(entry.key_id.clone()),
                role: Some(entry.role.clone()),
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                outcome: "deny_revoked_credentials".to_string(),
                required_permission: required_permission.clone(),
                detail: None,
            });
            return Err(AuthError::RevokedCredentials);
        }

        if entry.is_expired_at(Utc::now()) {
            self.record_access(AccessAuditEvent {
                timestamp: Utc::now(),
                principal_id: Some(entry.key_id.clone()),
                role: Some(entry.role.clone()),
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                outcome: "deny_expired_credentials".to_string(),
                required_permission: required_permission.clone(),
                detail: None,
            });
            return Err(AuthError::ExpiredCredentials);
        }

        if let Some(rate_limiter) = &self.rate_limiter
            && !rate_limiter.allow(&entry.key_id)
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

    pub fn generate_credential(
        &self,
        command: GenerateCredentialCommand,
    ) -> Result<GeneratedCredential, AuthAdminError> {
        if !self.enabled {
            return Err(AuthAdminError::NotEnabled);
        }

        let role = command.role.trim();
        if role.is_empty() {
            return Err(AuthAdminError::InvalidRequest(
                "role is required".to_string(),
            ));
        }

        let expires_at =
            resolve_expiry(command.expires_in_seconds.or(self.default_key_expiry_secs))?;
        let label = normalize_optional_string(command.label);
        let scopes = normalize_scopes(command.scopes);

        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| AuthAdminError::StoragePoisoned)?;
        let mut next = guard.clone();

        let (token, token_hash) = generate_unique_token(&next)?;
        let now = Utc::now();

        let entry = CredentialEntry {
            key_id: credential_fingerprint_from_hash(&token_hash),
            label,
            role: role.to_owned(),
            scopes,
            is_service_account: command.is_service_account,
            created_at: now,
            rotated_at: None,
            expires_at,
            revoked_at: None,
        };
        let metadata = entry.metadata();

        next.insert(token_hash, entry);
        self.persist_credentials(&next)?;
        *guard = next;

        Ok(GeneratedCredential {
            token,
            credential: metadata,
        })
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

        let old_hash = hash_token(old_token);
        let new_hash = hash_token(new_token);

        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| AuthAdminError::StoragePoisoned)?;
        let mut next = guard.clone();

        let mut entry = next
            .remove(&old_hash)
            .ok_or(AuthAdminError::CredentialNotFound)?;

        if next.contains_key(&new_hash) {
            return Err(AuthAdminError::NewTokenAlreadyExists);
        }

        if let Some(role) = command.role {
            let role = role.trim();
            if role.is_empty() {
                return Err(AuthAdminError::InvalidRequest(
                    "role cannot be empty".to_string(),
                ));
            }
            entry.role = role.to_owned();
        }

        if let Some(scopes) = command.scopes {
            entry.scopes = normalize_scopes(scopes);
        }

        if let Some(label) = command.label {
            entry.label = normalize_optional_string(Some(label));
        }

        if let Some(is_service_account) = command.is_service_account {
            entry.is_service_account = is_service_account;
        }

        if command.expires_in_seconds.is_some() {
            entry.expires_at = resolve_expiry(command.expires_in_seconds)?;
        }

        entry.key_id = credential_fingerprint_from_hash(&new_hash);
        entry.rotated_at = Some(Utc::now());
        entry.revoked_at = None;

        let metadata = entry.metadata();
        next.insert(new_hash, entry);

        self.persist_credentials(&next)?;
        *guard = next;
        Ok(metadata)
    }

    pub fn revoke_credential(&self, key_id: &str) -> Result<CredentialMetadata, AuthAdminError> {
        self.update_key_lifecycle_state(key_id, |entry| {
            entry.revoked_at = Some(Utc::now());
        })
    }

    pub fn expire_credential(&self, key_id: &str) -> Result<CredentialMetadata, AuthAdminError> {
        self.update_key_lifecycle_state(key_id, |entry| {
            entry.expires_at = Some(Utc::now());
        })
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

    fn update_key_lifecycle_state<F>(
        &self,
        key_id: &str,
        mut update: F,
    ) -> Result<CredentialMetadata, AuthAdminError>
    where
        F: FnMut(&mut CredentialEntry),
    {
        if !self.enabled {
            return Err(AuthAdminError::NotEnabled);
        }

        let key_id = key_id.trim();
        if key_id.is_empty() {
            return Err(AuthAdminError::InvalidRequest(
                "key_id is required".to_string(),
            ));
        }

        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| AuthAdminError::StoragePoisoned)?;
        let mut next = guard.clone();

        let mut metadata = None;
        for entry in next.values_mut() {
            if entry.key_id == key_id {
                update(entry);
                metadata = Some(entry.metadata());
                break;
            }
        }

        let metadata = metadata.ok_or(AuthAdminError::CredentialNotFound)?;
        self.persist_credentials(&next)?;
        *guard = next;
        Ok(metadata)
    }

    fn persist_credentials(
        &self,
        credentials: &HashMap<String, CredentialEntry>,
    ) -> Result<(), AuthAdminError> {
        if let Some(store) = &self.credential_store {
            store
                .save(credentials)
                .map_err(AuthAdminError::PersistenceFailed)?;
        }
        Ok(())
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
    #[error("API credentials have expired")]
    ExpiredCredentials,
    #[error("API credentials have been revoked")]
    RevokedCredentials,
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
    #[error("failed to generate unique credential token")]
    TokenGenerationFailed,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("auth storage unavailable")]
    StoragePoisoned,
    #[error("auth credential persistence failed: {0}")]
    PersistenceFailed(String),
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

        let token_hash = hash_token(&credential.token);
        let entry = CredentialEntry {
            key_id: credential_fingerprint_from_hash(&token_hash),
            label: credential.label.clone(),
            role: credential.role.clone(),
            scopes: normalize_scopes(credential.scopes.clone()),
            is_service_account,
            created_at: Utc::now(),
            rotated_at: None,
            expires_at: None,
            revoked_at: None,
        };

        if target.insert(token_hash, entry).is_some() {
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
        ("POST", "/api/auth/keys/generate") => Some("auth:write"),
        ("POST", "/api/auth/keys/rotate") => Some("auth:write"),
        ("POST", "/api/auth/keys/revoke") => Some("auth:write"),
        ("POST", "/api/auth/keys/expire") => Some("auth:write"),
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

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

fn credential_fingerprint_from_hash(token_hash: &str) -> String {
    let truncated = &token_hash[..12.min(token_hash.len())];
    format!("key_{truncated}")
}

fn resolve_expiry(
    expires_in_seconds: Option<u64>,
) -> Result<Option<DateTime<Utc>>, AuthAdminError> {
    match expires_in_seconds {
        Some(seconds) => Ok(Some(expiry_from_seconds(seconds)?)),
        None => Ok(None),
    }
}

fn expiry_from_seconds(seconds: u64) -> Result<DateTime<Utc>, AuthAdminError> {
    if seconds == 0 {
        return Err(AuthAdminError::InvalidRequest(
            "expires_in_seconds must be greater than zero".to_string(),
        ));
    }

    let seconds = i64::try_from(seconds).map_err(|_| {
        AuthAdminError::InvalidRequest("expires_in_seconds exceeds supported range".to_string())
    })?;

    let delta = TimeDelta::seconds(seconds);
    Utc::now().checked_add_signed(delta).ok_or_else(|| {
        AuthAdminError::InvalidRequest(
            "expires_in_seconds creates an unsupported expiry timestamp".to_string(),
        )
    })
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for scope in scopes {
        let trimmed = scope.trim();
        if trimmed.is_empty() {
            continue;
        }

        let scope = trimmed.to_owned();
        if seen.insert(scope.clone()) {
            normalized.push(scope);
        }
    }

    normalized
}

fn generate_unique_token(
    existing_credentials: &HashMap<String, CredentialEntry>,
) -> Result<(String, String), AuthAdminError> {
    for _ in 0..TOKEN_GENERATION_RETRIES {
        let token = format!("psk_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_hash = hash_token(&token);
        if !existing_credentials.contains_key(&token_hash) {
            return Ok((token, token_hash));
        }
    }

    Err(AuthAdminError::TokenGenerationFailed)
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
        let mut settings = test_settings();
        settings.auth_enabled = true;
        settings.auth_api_keys = vec![AuthCredentialConfig {
            label: None,
            token: "old-token".to_string(),
            role: "compliance_admin".to_string(),
            scopes: vec![],
        }];

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
                expires_in_seconds: None,
            })
            .expect("rotation should work");

        assert_ne!(before, rotated.key_id);
    }

    #[test]
    fn expiring_credential_blocks_authorization() {
        let mut settings = test_settings();
        settings.auth_enabled = true;
        settings.auth_api_keys = vec![AuthCredentialConfig {
            label: None,
            token: "expiring-token".to_string(),
            role: "compliance_admin".to_string(),
            scopes: vec![],
        }];

        let service = AuthService::from_settings(&settings);
        let key_id = service
            .list_credentials()
            .expect("credentials")
            .first()
            .expect("credential exists")
            .key_id
            .clone();

        service
            .expire_credential(&key_id)
            .expect("expiry should succeed");

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "expiring-token".parse().expect("header"));

        let result = service.authorize_request(&headers, &Method::POST, "/api/compliance/check");
        assert!(matches!(result, Err(AuthError::ExpiredCredentials)));
    }

    #[test]
    fn revoked_credential_blocks_authorization() {
        let mut settings = test_settings();
        settings.auth_enabled = true;
        settings.auth_api_keys = vec![AuthCredentialConfig {
            label: None,
            token: "revoked-token".to_string(),
            role: "compliance_admin".to_string(),
            scopes: vec![],
        }];

        let service = AuthService::from_settings(&settings);
        let key_id = service
            .list_credentials()
            .expect("credentials")
            .first()
            .expect("credential exists")
            .key_id
            .clone();

        service
            .revoke_credential(&key_id)
            .expect("revoke should succeed");

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "revoked-token".parse().expect("header"));

        let result = service.authorize_request(&headers, &Method::POST, "/api/compliance/check");
        assert!(matches!(result, Err(AuthError::RevokedCredentials)));
    }

    #[test]
    fn generated_credential_persists_to_disk() {
        let mut settings = test_settings();
        settings.auth_enabled = true;
        settings.auth_api_keys = Vec::new();
        settings.auth_key_store_path = Some(
            std::env::temp_dir()
                .join(format!("prompt_sentinel_auth_keys_{}.json", Uuid::new_v4()))
                .to_string_lossy()
                .to_string(),
        );

        let store_path = settings.auth_key_store_path.clone().expect("path");
        let service = AuthService::from_settings(&settings);
        let generated = service
            .generate_credential(GenerateCredentialCommand {
                role: "developer".to_string(),
                scopes: vec!["check:invoke".to_string()],
                label: Some("generated".to_string()),
                is_service_account: false,
                expires_in_seconds: None,
            })
            .expect("generated");

        drop(service);

        let reloaded_service = AuthService::from_settings(&settings);
        let listed = reloaded_service
            .list_credentials()
            .expect("list after reload should work");
        assert!(
            listed
                .iter()
                .any(|credential| credential.key_id == generated.credential.key_id)
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", generated.token.parse().expect("header"));

        let authorization =
            reloaded_service.authorize_request(&headers, &Method::POST, "/api/compliance/check");
        assert!(authorization.is_ok());

        let _ = fs::remove_file(store_path);
    }

    #[test]
    fn default_expiry_applies_to_generated_credentials() {
        let mut settings = test_settings();
        settings.auth_enabled = true;
        settings.auth_default_key_expiry_secs = Some(60);

        let service = AuthService::from_settings(&settings);
        let generated = service
            .generate_credential(GenerateCredentialCommand {
                role: "developer".to_string(),
                scopes: vec![],
                label: None,
                is_service_account: false,
                expires_in_seconds: None,
            })
            .expect("generated");

        assert!(generated.credential.expires_at.is_some());
        assert!(generated.credential.active);
    }

    fn test_settings() -> AppSettings {
        AppSettings {
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
            auth_enabled: false,
            auth_api_keys: vec![],
            auth_service_tokens: vec![],
            auth_rate_limit_per_minute: 60,
            auth_key_store_path: None,
            auth_default_key_expiry_secs: None,
            bias_threshold: 0.35,
            max_input_length: 1024,
            semantic_medium_threshold: 0.70,
            semantic_high_threshold: 0.80,
            semantic_decision_margin: 0.02,
        }
    }
}
