use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

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
    pub scopes_claim: String,
    pub roles_claim: String,
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
    #[error("required subject claim is missing")]
    MissingSubject,
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

        if let Some(expected_audience) = self
            .config
            .audience
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            let audiences = payload.audience_values();
            if !audiences.iter().any(|aud| aud == expected_audience) {
                return Err(OidcVerificationError::AudienceMismatch);
            }
        }

        if let Some(expected_client_id) = self
            .config
            .client_id
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            let audiences = payload.audience_values();
            if !audiences.iter().any(|aud| aud == expected_client_id) {
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

        let scopes = payload.claim_as_scopes(&self.config.scopes_claim);
        let roles = payload.claim_as_list(&self.config.roles_claim);

        let tenant_id = payload.tenant_id();
        let issuer = payload.iss.clone();
        let email = payload.email.clone();

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
}

impl DisabledOidcVerifier {
    pub fn new(provider: OidcProvider) -> Self {
        Self { provider }
    }
}

impl OidcTokenVerifier for DisabledOidcVerifier {
    fn verify(&self, _token: &str) -> Result<OidcPrincipal, OidcVerificationError> {
        Err(OidcVerificationError::Unavailable(
            "no active OIDC verifier configured".to_string(),
        ))
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
    if settings.oidc_allow_insecure_jwt_parse {
        let config = OidcVerifierConfig {
            provider,
            issuer: settings.oidc_issuer_url.clone(),
            audience: settings.oidc_audience.clone(),
            client_id: settings.oidc_client_id.clone(),
            scopes_claim: settings.oidc_scopes_claim.clone(),
            roles_claim: settings.oidc_roles_claim.clone(),
        };
        Some(Arc::new(InsecureJwtClaimVerifier::new(config)))
    } else {
        Some(Arc::new(DisabledOidcVerifier::new(provider)))
    }
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

    fn claim_as_list(&self, claim_name: &str) -> Vec<String> {
        let Some(value) = self.custom.get(claim_name) else {
            return Vec::new();
        };

        claim_value_to_list(value)
    }

    fn claim_as_scopes(&self, claim_name: &str) -> Vec<String> {
        let Some(value) = self.custom.get(claim_name) else {
            return Vec::new();
        };

        match value {
            Value::String(scopes) => scopes
                .split_whitespace()
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            _ => claim_value_to_list(value),
        }
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
            scopes_claim: "scope".to_string(),
            roles_claim: "roles".to_string(),
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
            scopes_claim: "scope".to_string(),
            roles_claim: "roles".to_string(),
        });

        let token = build_jwt(json!({
            "sub": "user-123",
            "exp": Utc::now().timestamp() - 1
        }));

        let result = verifier.verify(&token);
        assert!(matches!(result, Err(OidcVerificationError::Expired)));
    }

    fn build_jwt(claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#.as_bytes());
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims should serialize"));
        format!("{header}.{payload}.")
    }
}
