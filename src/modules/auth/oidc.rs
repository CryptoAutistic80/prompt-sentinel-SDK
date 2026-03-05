use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tracing::warn;

use crate::config::settings::AppSettings;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidcProvider {
    Generic,
    Auth0,
    Okta,
    AzureAd,
    Keycloak,
}

impl OidcProvider {
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "auth0" => Self::Auth0,
            "okta" => Self::Okta,
            "azure_ad" | "azure" => Self::AzureAd,
            "keycloak" => Self::Keycloak,
            _ => Self::Generic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Auth0 => "auth0",
            Self::Okta => "okta",
            Self::AzureAd => "azure_ad",
            Self::Keycloak => "keycloak",
        }
    }
}

#[derive(Clone, Debug)]
pub struct OidcVerifierConfig {
    pub provider: OidcProvider,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub client_id: Option<String>,
    pub scopes_claims: Vec<String>,
    pub roles_claims: Vec<String>,
    pub jwks_url: Option<String>,
    pub jwks_refresh_interval_secs: u64,
    pub clock_skew_secs: u64,
}

impl OidcVerifierConfig {
    fn expected_audiences(&self) -> Vec<String> {
        let mut audiences = Vec::new();

        if let Some(value) = self
            .audience
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            audiences.push(value.to_owned());
        }

        if let Some(value) = self
            .client_id
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            && !audiences.iter().any(|existing| existing == value)
        {
            audiences.push(value.to_owned());
        }

        audiences
    }
}

#[derive(Clone, Debug)]
pub struct OidcPrincipal {
    pub subject: String,
    pub issuer: Option<String>,
    pub email: Option<String>,
    pub tenant_id: Option<String>,
    pub provider: OidcProvider,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
}

impl OidcPrincipal {
    pub fn primary_role(&self) -> &str {
        self.roles
            .first()
            .map(String::as_str)
            .unwrap_or("oidc_user")
    }
}

pub trait OidcTokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<OidcPrincipal, OidcVerificationError>;
    fn provider(&self) -> OidcProvider;
}

#[derive(Debug, Error)]
pub enum OidcVerificationError {
    #[error("token is not a JWT")]
    NotJwt,
    #[error("token payload is invalid")]
    InvalidPayload,
    #[error("token algorithm is unsupported: {0}")]
    UnsupportedAlgorithm(String),
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("required subject claim is missing")]
    MissingSubject,
    #[error("JWT header is missing key id")]
    MissingKeyId,
    #[error("no matching JWKS signing key found")]
    SigningKeyNotFound,
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("token has expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("OIDC verifier unavailable: {0}")]
    Unavailable(String),
}

#[derive(Clone)]
pub struct InsecureJwtClaimVerifier {
    config: OidcVerifierConfig,
}

impl InsecureJwtClaimVerifier {
    pub fn new(config: OidcVerifierConfig) -> Self {
        Self { config }
    }
}

impl OidcTokenVerifier for InsecureJwtClaimVerifier {
    fn verify(&self, token: &str) -> Result<OidcPrincipal, OidcVerificationError> {
        let payload = decode_jwt_claims(token)?;

        let subject = payload
            .sub
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or(OidcVerificationError::MissingSubject)?;

        if let Some(expected_issuer) = self
            .config
            .issuer
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            let issuer = payload.iss.clone().unwrap_or_default();
            if issuer != expected_issuer {
                return Err(OidcVerificationError::IssuerMismatch);
            }
        }

        let expected_audiences = self.config.expected_audiences();
        if !expected_audiences.is_empty() {
            let audiences = payload.audience_values();
            if !expected_audiences
                .iter()
                .any(|expected| audiences.iter().any(|audience| audience == expected))
            {
                return Err(OidcVerificationError::AudienceMismatch);
            }
        }

        let now = Utc::now().timestamp();
        if let Some(exp) = payload.exp
            && exp <= now
        {
            return Err(OidcVerificationError::Expired);
        }
        if let Some(nbf) = payload.nbf
            && nbf > now
        {
            return Err(OidcVerificationError::NotYetValid);
        }

        let scopes = payload.claim_as_scopes_candidates(
            &self.config.scopes_claims,
            self.config.client_id.as_deref(),
        );
        let roles = payload
            .claim_as_list_candidates(&self.config.roles_claims, self.config.client_id.as_deref());
        let issuer = payload.iss.clone();
        let email = payload.email.clone();
        let tenant_id = payload.tenant_id();

        Ok(OidcPrincipal {
            subject,
            issuer,
            email,
            tenant_id,
            provider: self.config.provider.clone(),
            roles,
            scopes,
        })
    }

    fn provider(&self) -> OidcProvider {
        self.config.provider.clone()
    }
}

#[derive(Clone)]
pub struct JwksJwtVerifier {
    config: OidcVerifierConfig,
    cache: Arc<JwksCache>,
}

impl JwksJwtVerifier {
    pub fn new(config: OidcVerifierConfig) -> Result<Self, String> {
        let jwks_url = config
            .jwks_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "OIDC_JWKS_URL is required for secure OIDC verification".to_string())?;

        let refresh_interval = Duration::from_secs(config.jwks_refresh_interval_secs.max(30));
        let cache = Arc::new(JwksCache::new(jwks_url.to_owned(), refresh_interval)?);
        cache
            .refresh(true)
            .map_err(|error| format!("failed to initialize JWKS cache: {error}"))?;
        Ok(Self { config, cache })
    }
}

impl OidcTokenVerifier for JwksJwtVerifier {
    fn verify(&self, token: &str) -> Result<OidcPrincipal, OidcVerificationError> {
        let header = decode_header(token).map_err(map_jwt_header_error)?;
        let algorithm = header.alg;
        if !matches!(
            algorithm,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
        ) {
            return Err(OidcVerificationError::UnsupportedAlgorithm(format!(
                "{algorithm:?}"
            )));
        }

        let kid = header.kid.ok_or(OidcVerificationError::MissingKeyId)?;
        let key = self.cache.key_for_kid(&kid)?;

        let mut validation = Validation::new(algorithm);
        validation.validate_nbf = true;
        validation.leeway = self.config.clock_skew_secs;
        validation
            .required_spec_claims
            .extend(["exp".to_string(), "sub".to_string()]);

        if let Some(expected_issuer) = self
            .config
            .issuer
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            validation.set_issuer(&[expected_issuer.to_owned()]);
        }

        let expected_audiences = self.config.expected_audiences();
        if !expected_audiences.is_empty() {
            validation.set_audience(&expected_audiences);
        }

        let token_data =
            decode::<JwtClaims>(token, key.as_ref(), &validation).map_err(map_jwt_decode_error)?;
        let claims = token_data.claims;

        let subject = claims
            .sub
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or(OidcVerificationError::MissingSubject)?;

        let scopes = claims.claim_as_scopes_candidates(
            &self.config.scopes_claims,
            self.config.client_id.as_deref(),
        );
        let roles = claims
            .claim_as_list_candidates(&self.config.roles_claims, self.config.client_id.as_deref());
        let issuer = claims.iss.clone();
        let email = claims.email.clone();
        let tenant_id = claims.tenant_id();

        Ok(OidcPrincipal {
            subject,
            issuer,
            email,
            tenant_id,
            provider: self.config.provider.clone(),
            roles,
            scopes,
        })
    }

    fn provider(&self) -> OidcProvider {
        self.config.provider.clone()
    }
}

#[derive(Clone)]
pub struct DisabledOidcVerifier {
    provider: OidcProvider,
    reason: String,
}

impl DisabledOidcVerifier {
    pub fn new(provider: OidcProvider, reason: String) -> Self {
        Self { provider, reason }
    }
}

impl OidcTokenVerifier for DisabledOidcVerifier {
    fn verify(&self, _token: &str) -> Result<OidcPrincipal, OidcVerificationError> {
        Err(OidcVerificationError::Unavailable(self.reason.clone()))
    }

    fn provider(&self) -> OidcProvider {
        self.provider.clone()
    }
}

pub fn build_oidc_verifier(
    settings: &AppSettings,
) -> Option<Arc<dyn OidcTokenVerifier + Send + Sync>> {
    if !settings.oidc_enabled {
        return None;
    }

    let provider = OidcProvider::from_config(&settings.oidc_provider);
    let profile = profile_for_provider(&provider);
    let config = OidcVerifierConfig {
        provider: provider.clone(),
        issuer: settings.oidc_issuer_url.clone(),
        audience: settings.oidc_audience.clone(),
        client_id: settings.oidc_client_id.clone(),
        scopes_claims: resolve_claim_candidates(&settings.oidc_scopes_claim, profile.scopes_claims),
        roles_claims: resolve_claim_candidates(&settings.oidc_roles_claim, profile.roles_claims),
        jwks_url: settings.oidc_jwks_url.clone(),
        jwks_refresh_interval_secs: settings.oidc_jwks_refresh_interval_secs,
        clock_skew_secs: settings.oidc_clock_skew_secs,
    };

    if settings.oidc_allow_insecure_jwt_parse {
        warn!(
            "OIDC insecure claim parsing is enabled; signature verification is bypassed (development-only)"
        );
        return Some(Arc::new(InsecureJwtClaimVerifier::new(config)));
    }

    match JwksJwtVerifier::new(config) {
        Ok(verifier) => Some(Arc::new(verifier)),
        Err(error) => {
            warn!("Secure OIDC verifier initialization failed: {error}");
            Some(Arc::new(DisabledOidcVerifier::new(provider, error)))
        }
    }
}

struct OidcProfileClaims {
    scopes_claims: &'static [&'static str],
    roles_claims: &'static [&'static str],
}

fn profile_for_provider(provider: &OidcProvider) -> OidcProfileClaims {
    match provider {
        OidcProvider::Auth0 => OidcProfileClaims {
            scopes_claims: &["scope", "permissions", "suffix:/permissions"],
            roles_claims: &["roles", "suffix:/roles"],
        },
        OidcProvider::Okta => OidcProfileClaims {
            scopes_claims: &["scp", "scope"],
            roles_claims: &["groups", "roles"],
        },
        OidcProvider::AzureAd => OidcProfileClaims {
            scopes_claims: &["scp", "scope"],
            roles_claims: &["roles", "groups"],
        },
        OidcProvider::Keycloak => OidcProfileClaims {
            scopes_claims: &["scope", "scp"],
            roles_claims: &[
                "realm_access.roles",
                "resource_access.{client_id}.roles",
                "roles",
            ],
        },
        OidcProvider::Generic => OidcProfileClaims {
            scopes_claims: &["scope", "scp"],
            roles_claims: &["roles", "groups"],
        },
    }
}

fn resolve_claim_candidates(configured: &str, defaults: &[&str]) -> Vec<String> {
    let configured = parse_claim_candidates(configured);
    let mut merged = if configured.is_empty()
        || (configured.len() == 1 && configured[0].eq_ignore_ascii_case("auto"))
    {
        defaults.iter().map(|claim| (*claim).to_string()).collect()
    } else {
        configured
    };

    push_unique(
        &mut merged,
        defaults.iter().map(|claim| (*claim).to_string()),
    );
    merged
}

fn parse_claim_candidates(raw: &str) -> Vec<String> {
    raw.split([',', '|'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

struct JwksCacheState {
    keys: HashMap<String, Arc<DecodingKey>>,
    last_refresh: Option<Instant>,
}

#[derive(Clone)]
struct JwksCache {
    jwks_url: String,
    refresh_interval: Duration,
    http_client: reqwest::blocking::Client,
    state: Arc<Mutex<JwksCacheState>>,
}

impl JwksCache {
    fn new(jwks_url: String, refresh_interval: Duration) -> Result<Self, String> {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|error| format!("failed to build JWKS HTTP client: {error}"))?;

        Ok(Self {
            jwks_url,
            refresh_interval,
            http_client,
            state: Arc::new(Mutex::new(JwksCacheState {
                keys: HashMap::new(),
                last_refresh: None,
            })),
        })
    }

    fn key_for_kid(&self, kid: &str) -> Result<Arc<DecodingKey>, OidcVerificationError> {
        self.refresh(false)?;
        if let Some(key) = self.lookup_key(kid)? {
            return Ok(key);
        }

        self.refresh(true)?;
        self.lookup_key(kid)?
            .ok_or(OidcVerificationError::SigningKeyNotFound)
    }

    fn lookup_key(&self, kid: &str) -> Result<Option<Arc<DecodingKey>>, OidcVerificationError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| OidcVerificationError::Unavailable("JWKS cache lock poisoned".into()))?;
        Ok(guard.keys.get(kid).cloned())
    }

    fn refresh(&self, force: bool) -> Result<(), OidcVerificationError> {
        let should_refresh = {
            let guard = self.state.lock().map_err(|_| {
                OidcVerificationError::Unavailable("JWKS cache lock poisoned".into())
            })?;
            let stale = guard
                .last_refresh
                .is_none_or(|last_refresh| last_refresh.elapsed() >= self.refresh_interval);
            force || stale || guard.keys.is_empty()
        };

        if !should_refresh {
            return Ok(());
        }

        let fetched = fetch_jwks(&self.http_client, &self.jwks_url)?;

        let mut guard = self
            .state
            .lock()
            .map_err(|_| OidcVerificationError::Unavailable("JWKS cache lock poisoned".into()))?;
        guard.keys = fetched;
        guard.last_refresh = Some(Instant::now());
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: Option<String>,
    kty: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_field: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

fn fetch_jwks(
    client: &reqwest::blocking::Client,
    jwks_url: &str,
) -> Result<HashMap<String, Arc<DecodingKey>>, OidcVerificationError> {
    let response = client.get(jwks_url).send().map_err(|error| {
        OidcVerificationError::Unavailable(format!("JWKS request failed: {error}"))
    })?;

    let response = response.error_for_status().map_err(|error| {
        OidcVerificationError::Unavailable(format!("JWKS endpoint returned error: {error}"))
    })?;

    let document = response.json::<JwksDocument>().map_err(|error| {
        OidcVerificationError::Unavailable(format!("invalid JWKS payload: {error}"))
    })?;

    let mut keys = HashMap::new();
    for key in document.keys {
        if !matches!(key.kty.as_deref(), Some("RSA")) {
            continue;
        }
        if let Some(use_field) = key.use_field.as_deref()
            && use_field != "sig"
        {
            continue;
        }
        if let Some(alg) = key.alg.as_deref()
            && !matches!(alg, "RS256" | "RS384" | "RS512")
        {
            continue;
        }

        let Some(kid) = key
            .kid
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(n) = key
            .n
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(e) = key
            .e
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        match DecodingKey::from_rsa_components(n, e) {
            Ok(decoding_key) => {
                keys.insert(kid.to_owned(), Arc::new(decoding_key));
            }
            Err(error) => {
                warn!("Skipping invalid JWKS RSA key for kid `{kid}`: {error}");
            }
        }
    }

    if keys.is_empty() {
        return Err(OidcVerificationError::Unavailable(
            "JWKS did not contain supported RSA signing keys".to_string(),
        ));
    }

    Ok(keys)
}

#[derive(Clone, Debug, Deserialize)]
struct JwtClaims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Option<Value>,
    exp: Option<i64>,
    nbf: Option<i64>,
    email: Option<String>,
    #[serde(rename = "tid")]
    tid: Option<String>,
    #[serde(rename = "tenant_id")]
    tenant_id: Option<String>,
    #[serde(flatten)]
    custom: serde_json::Map<String, Value>,
}

impl JwtClaims {
    fn audience_values(&self) -> Vec<String> {
        match self.aud.as_ref() {
            Some(Value::String(aud)) if !aud.trim().is_empty() => vec![aud.clone()],
            Some(Value::Array(entries)) => entries
                .iter()
                .filter_map(|entry| entry.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn claim_as_list_candidates(
        &self,
        claim_names: &[String],
        client_id: Option<&str>,
    ) -> Vec<String> {
        let mut values = Vec::new();
        for claim_name in claim_names {
            for value in self.claim_values_for_selector(claim_name, client_id) {
                let candidates = claim_value_to_list(&value);
                push_unique(&mut values, candidates);
            }
        }
        values
    }

    fn claim_as_scopes_candidates(
        &self,
        claim_names: &[String],
        client_id: Option<&str>,
    ) -> Vec<String> {
        let mut values = Vec::new();
        for claim_name in claim_names {
            for value in self.claim_values_for_selector(claim_name, client_id) {
                let candidates = match value {
                    Value::String(scopes) => scopes
                        .split_whitespace()
                        .map(str::trim)
                        .filter(|scope| !scope.is_empty())
                        .map(ToOwned::to_owned)
                        .collect(),
                    _ => claim_value_to_list(&value),
                };
                push_unique(&mut values, candidates);
            }
        }
        values
    }

    fn claim_values_for_selector(&self, selector: &str, client_id: Option<&str>) -> Vec<Value> {
        if let Some(suffix) = selector.strip_prefix("suffix:") {
            return self
                .custom
                .iter()
                .filter(|(key, _)| key.ends_with(suffix))
                .map(|(_, value)| value.clone())
                .collect();
        }

        self.claim_value_for_path(selector, client_id)
            .into_iter()
            .collect()
    }

    fn claim_value_for_path(&self, path: &str, client_id: Option<&str>) -> Option<Value> {
        let resolved = resolve_claim_path(path, client_id)?;
        let mut segments = resolved.split('.');
        let first = segments.next()?;
        let mut current = self.custom.get(first)?.clone();
        for segment in segments {
            let Value::Object(map) = current else {
                return None;
            };
            current = map.get(segment)?.clone();
        }

        Some(current)
    }

    fn tenant_id(&self) -> Option<String> {
        self.tid.clone().or_else(|| self.tenant_id.clone())
    }
}

fn claim_value_to_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(single) => {
            let value = single.trim();
            if value.is_empty() {
                Vec::new()
            } else {
                vec![value.to_owned()]
            }
        }
        Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| entry.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn resolve_claim_path(path: &str, client_id: Option<&str>) -> Option<String> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }

    if path.contains("{client_id}") {
        let client_id = client_id.map(str::trim).filter(|value| !value.is_empty())?;
        return Some(path.replace("{client_id}", client_id));
    }

    Some(path.to_string())
}

fn push_unique<I>(target: &mut Vec<String>, values: I)
where
    I: IntoIterator<Item = String>,
{
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn decode_jwt_claims(token: &str) -> Result<JwtClaims, OidcVerificationError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(OidcVerificationError::NotJwt)?;
    let payload = parts.next().ok_or(OidcVerificationError::NotJwt)?;
    let _signature = parts.next().ok_or(OidcVerificationError::NotJwt)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| OidcVerificationError::InvalidPayload)?;
    serde_json::from_slice::<JwtClaims>(&bytes).map_err(|_| OidcVerificationError::InvalidPayload)
}

fn map_jwt_header_error(error: JwtError) -> OidcVerificationError {
    match error.kind() {
        JwtErrorKind::InvalidAlgorithm => {
            OidcVerificationError::UnsupportedAlgorithm("invalid JWT algorithm".to_string())
        }
        _ => OidcVerificationError::NotJwt,
    }
}

fn map_jwt_decode_error(error: JwtError) -> OidcVerificationError {
    match error.kind() {
        JwtErrorKind::InvalidSignature => OidcVerificationError::InvalidSignature,
        JwtErrorKind::ExpiredSignature => OidcVerificationError::Expired,
        JwtErrorKind::ImmatureSignature => OidcVerificationError::NotYetValid,
        JwtErrorKind::InvalidAudience => OidcVerificationError::AudienceMismatch,
        JwtErrorKind::InvalidIssuer => OidcVerificationError::IssuerMismatch,
        JwtErrorKind::MissingRequiredClaim(claim) if claim == "sub" => {
            OidcVerificationError::MissingSubject
        }
        JwtErrorKind::InvalidAlgorithm => {
            OidcVerificationError::UnsupportedAlgorithm("invalid JWT algorithm".to_string())
        }
        _ => OidcVerificationError::InvalidPayload,
    }
}

pub fn looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    #[test]
    fn parses_provider_aliases() {
        assert_eq!(OidcProvider::from_config("auth0"), OidcProvider::Auth0);
        assert_eq!(OidcProvider::from_config("azure"), OidcProvider::AzureAd);
        assert_eq!(OidcProvider::from_config("unknown"), OidcProvider::Generic);
    }

    #[test]
    fn verifier_accepts_valid_claims() {
        let verifier = InsecureJwtClaimVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::Generic,
            issuer: Some("https://issuer.example.com".to_string()),
            audience: Some("prompt-sentinel".to_string()),
            client_id: None,
            scopes_claims: vec!["scope".to_string()],
            roles_claims: vec!["roles".to_string()],
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        let token = build_jwt(json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": ["prompt-sentinel"],
            "exp": Utc::now().timestamp() + 300,
            "scope": "check:invoke audit:read",
            "roles": ["developer"]
        }));

        let principal = verifier.verify(&token).expect("token should verify");
        assert_eq!(principal.subject, "user-123");
        assert_eq!(principal.roles, vec!["developer".to_string()]);
        assert_eq!(
            principal.scopes,
            vec!["check:invoke".to_string(), "audit:read".to_string()]
        );
    }

    #[test]
    fn verifier_rejects_expired_token() {
        let verifier = InsecureJwtClaimVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::Generic,
            issuer: None,
            audience: None,
            client_id: None,
            scopes_claims: vec!["scope".to_string()],
            roles_claims: vec!["roles".to_string()],
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        let token = build_jwt(json!({
            "sub": "user-123",
            "exp": Utc::now().timestamp() - 1
        }));

        let result = verifier.verify(&token);
        assert!(matches!(result, Err(OidcVerificationError::Expired)));
    }

    #[test]
    fn secure_verifier_requires_jwks_url() {
        let result = JwksJwtVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::Generic,
            issuer: None,
            audience: None,
            client_id: None,
            scopes_claims: vec!["scope".to_string()],
            roles_claims: vec!["roles".to_string()],
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        assert!(result.is_err());
    }

    #[test]
    fn expected_audience_list_deduplicates_values() {
        let config = OidcVerifierConfig {
            provider: OidcProvider::Generic,
            issuer: None,
            audience: Some("prompt-sentinel".to_string()),
            client_id: Some("prompt-sentinel".to_string()),
            scopes_claims: vec!["scope".to_string()],
            roles_claims: vec!["roles".to_string()],
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        };

        assert_eq!(
            config.expected_audiences(),
            vec!["prompt-sentinel".to_string()]
        );
    }

    #[test]
    fn auth0_profile_maps_namespaced_roles_and_permissions() {
        let profile = profile_for_provider(&OidcProvider::Auth0);
        let verifier = InsecureJwtClaimVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::Auth0,
            issuer: None,
            audience: None,
            client_id: Some("prompt-sentinel".to_string()),
            scopes_claims: resolve_claim_candidates("auto", profile.scopes_claims),
            roles_claims: resolve_claim_candidates("auto", profile.roles_claims),
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        let token = build_jwt(json!({
            "sub": "auth0-user",
            "aud": ["prompt-sentinel"],
            "exp": Utc::now().timestamp() + 300,
            "permissions": ["check:invoke", "audit:read"],
            "https://tenant.example.com/roles": ["developer"]
        }));

        let principal = verifier.verify(&token).expect("token should verify");
        assert_eq!(principal.roles, vec!["developer".to_string()]);
        assert_eq!(
            principal.scopes,
            vec!["check:invoke".to_string(), "audit:read".to_string()]
        );
    }

    #[test]
    fn okta_profile_maps_groups_and_scp() {
        let profile = profile_for_provider(&OidcProvider::Okta);
        let verifier = InsecureJwtClaimVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::Okta,
            issuer: None,
            audience: None,
            client_id: Some("prompt-sentinel".to_string()),
            scopes_claims: resolve_claim_candidates("auto", profile.scopes_claims),
            roles_claims: resolve_claim_candidates("auto", profile.roles_claims),
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        let token = build_jwt(json!({
            "sub": "okta-user",
            "aud": ["prompt-sentinel"],
            "exp": Utc::now().timestamp() + 300,
            "scp": ["check:invoke", "audit:read"],
            "groups": ["compliance_admin"]
        }));

        let principal = verifier.verify(&token).expect("token should verify");
        assert_eq!(principal.roles, vec!["compliance_admin".to_string()]);
        assert_eq!(
            principal.scopes,
            vec!["check:invoke".to_string(), "audit:read".to_string()]
        );
    }

    #[test]
    fn azure_profile_maps_scp_and_roles() {
        let profile = profile_for_provider(&OidcProvider::AzureAd);
        let verifier = InsecureJwtClaimVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::AzureAd,
            issuer: None,
            audience: None,
            client_id: Some("prompt-sentinel".to_string()),
            scopes_claims: resolve_claim_candidates("auto", profile.scopes_claims),
            roles_claims: resolve_claim_candidates("auto", profile.roles_claims),
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        let token = build_jwt(json!({
            "sub": "azure-user",
            "aud": ["prompt-sentinel"],
            "exp": Utc::now().timestamp() + 300,
            "scp": "check:invoke audit:read",
            "roles": ["developer"]
        }));

        let principal = verifier.verify(&token).expect("token should verify");
        assert_eq!(principal.roles, vec!["developer".to_string()]);
        assert_eq!(
            principal.scopes,
            vec!["check:invoke".to_string(), "audit:read".to_string()]
        );
    }

    #[test]
    fn keycloak_profile_maps_realm_and_client_roles() {
        let profile = profile_for_provider(&OidcProvider::Keycloak);
        let verifier = InsecureJwtClaimVerifier::new(OidcVerifierConfig {
            provider: OidcProvider::Keycloak,
            issuer: None,
            audience: None,
            client_id: Some("prompt-sentinel".to_string()),
            scopes_claims: resolve_claim_candidates("auto", profile.scopes_claims),
            roles_claims: resolve_claim_candidates("auto", profile.roles_claims),
            jwks_url: None,
            jwks_refresh_interval_secs: 300,
            clock_skew_secs: 60,
        });

        let token = build_jwt(json!({
            "sub": "keycloak-user",
            "aud": ["prompt-sentinel"],
            "exp": Utc::now().timestamp() + 300,
            "scope": "check:invoke audit:read",
            "realm_access": {
                "roles": ["realm_admin"]
            },
            "resource_access": {
                "prompt-sentinel": {
                    "roles": ["developer"]
                }
            }
        }));

        let principal = verifier.verify(&token).expect("token should verify");
        assert_eq!(
            principal.roles,
            vec!["realm_admin".to_string(), "developer".to_string()]
        );
        assert_eq!(
            principal.scopes,
            vec!["check:invoke".to_string(), "audit:read".to_string()]
        );
    }

    fn build_jwt(claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#.as_bytes());
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims should serialize"));
        format!("{header}.{payload}.")
    }
}
