use std::env;
use std::num::ParseFloatError;
use std::num::ParseIntError;

use thiserror::Error;

pub const DEFAULT_MISTRAL_BASE_URL: &str = "https://api.mistral.ai/v1";
pub const DEFAULT_MISTRAL_GENERATION_MODEL: &str = "mistral-small-latest";
pub const DEFAULT_MISTRAL_MODERATION_MODEL: &str = "mistral-moderation-latest";
pub const DEFAULT_MISTRAL_EMBEDDING_MODEL: &str = "mistral-embed";
pub const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-4-5-20250929";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LlmBackend {
    OpenAICompat,
    AnthropicCompat,
    Ollama,
    Vllm,
}

impl LlmBackend {
    fn from_env() -> Self {
        match env::var("LLM_BACKEND")
            .unwrap_or_else(|_| "openai_compat".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "anthropic_compat" => Self::AnthropicCompat,
            "ollama" => Self::Ollama,
            "vllm" => Self::Vllm,
            _ => Self::OpenAICompat,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthCredentialConfig {
    pub token: String,
    pub role: String,
}

#[derive(Clone, Debug)]
pub struct AppSettings {
    pub server_port: u16,
    pub llm_backend: LlmBackend,
    pub llm_api_key: Option<String>,
    pub llm_base_url: String,
    pub generation_model: String,
    pub moderation_model: Option<String>,
    pub embedding_model: String,
    pub cors_allowed_origins: Vec<String>,
    pub llm_request_timeout_secs: u64,
    pub llm_connect_timeout_secs: u64,
    pub llm_pool_max_idle_per_host: usize,
    pub llm_pool_idle_timeout_secs: u64,
    pub llm_circuit_breaker_failure_threshold: u32,
    pub llm_circuit_breaker_open_duration_secs: u64,
    pub auth_enabled: bool,
    pub auth_api_keys: Vec<AuthCredentialConfig>,
    pub auth_service_tokens: Vec<AuthCredentialConfig>,
    pub auth_rate_limit_per_minute: u32,
    pub bias_threshold: f32,
    pub max_input_length: usize,
    /// Threshold for semantic Low/Medium boundary (default: 0.70)
    pub semantic_medium_threshold: f32,
    /// Threshold for semantic Medium/High boundary (default: 0.80)
    pub semantic_high_threshold: f32,
    /// Extra buffer added to semantic thresholds to reduce borderline false positives
    pub semantic_decision_margin: f32,
}

impl AppSettings {
    pub fn from_env() -> Result<Self, SettingsError> {
        let server_port = parse_env_u16("SERVER_PORT", 3000)?;
        let bias_threshold = parse_env_f32("BIAS_THRESHOLD", 0.35)?;
        let max_input_length = parse_env_usize("MAX_INPUT_LENGTH", 4096)?;
        let semantic_medium_threshold = parse_env_f32("SEMANTIC_MEDIUM_THRESHOLD", 0.70)?;
        let semantic_high_threshold = parse_env_f32("SEMANTIC_HIGH_THRESHOLD", 0.80)?;
        let semantic_decision_margin = parse_env_f32("SEMANTIC_DECISION_MARGIN", 0.02)?;
        let llm_backend = LlmBackend::from_env();

        let llm_base_url = env::var("LLM_BASE_URL")
            .or_else(|_| env::var("MISTRAL_BASE_URL"))
            .unwrap_or_else(|_| default_base_url(&llm_backend).to_string());

        let llm_api_key = env::var("LLM_API_KEY")
            .or_else(|_| env::var("MISTRAL_API_KEY"))
            .or_else(|_| env::var("ANTHROPIC_API_KEY"))
            .ok()
            .filter(|v| !v.is_empty());

        let generation_model = env::var("LLM_GENERATION_MODEL")
            .or_else(|_| env::var("MISTRAL_GENERATION_MODEL"))
            .unwrap_or_else(|_| default_generation_model(&llm_backend).to_string());

        let moderation_model = env::var("LLM_MODERATION_MODEL")
            .or_else(|_| env::var("MISTRAL_MODERATION_MODEL"))
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| Some(default_moderation_model(&llm_backend, &generation_model)));

        let embedding_model = env::var("LLM_EMBEDDING_MODEL")
            .or_else(|_| env::var("MISTRAL_EMBEDDING_MODEL"))
            .unwrap_or_else(|_| default_embedding_model(&llm_backend, &generation_model));

        Ok(Self {
            server_port,
            llm_backend,
            llm_api_key,
            llm_base_url,
            generation_model,
            moderation_model,
            embedding_model,
            cors_allowed_origins: parse_csv_env(
                "CORS_ALLOW_ORIGINS",
                &["http://localhost:5175", "http://127.0.0.1:5175"],
            ),
            llm_request_timeout_secs: parse_env_u64("LLM_REQUEST_TIMEOUT_SECS", 120)?,
            llm_connect_timeout_secs: parse_env_u64("LLM_CONNECT_TIMEOUT_SECS", 10)?,
            llm_pool_max_idle_per_host: parse_env_usize("LLM_POOL_MAX_IDLE_PER_HOST", 20)?,
            llm_pool_idle_timeout_secs: parse_env_u64("LLM_POOL_IDLE_TIMEOUT_SECS", 90)?,
            llm_circuit_breaker_failure_threshold: parse_env_u32(
                "LLM_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
                5,
            )?,
            llm_circuit_breaker_open_duration_secs: parse_env_u64(
                "LLM_CIRCUIT_BREAKER_OPEN_DURATION_SECS",
                30,
            )?,
            auth_enabled: parse_env_bool("AUTH_ENABLED", false),
            auth_api_keys: parse_auth_credentials("AUTH_API_KEYS"),
            auth_service_tokens: parse_auth_credentials("AUTH_SERVICE_TOKENS"),
            auth_rate_limit_per_minute: parse_env_u32("AUTH_RATE_LIMIT_PER_MINUTE", 300)?,
            bias_threshold,
            max_input_length,
            semantic_medium_threshold,
            semantic_high_threshold,
            semantic_decision_margin,
        })
    }
}

fn default_base_url(backend: &LlmBackend) -> &'static str {
    match backend {
        LlmBackend::OpenAICompat => DEFAULT_MISTRAL_BASE_URL,
        LlmBackend::AnthropicCompat => DEFAULT_ANTHROPIC_BASE_URL,
        LlmBackend::Ollama => "http://localhost:11434/v1",
        LlmBackend::Vllm => "http://localhost:8000/v1",
    }
}

fn default_generation_model(backend: &LlmBackend) -> &'static str {
    match backend {
        LlmBackend::OpenAICompat => DEFAULT_MISTRAL_GENERATION_MODEL,
        LlmBackend::AnthropicCompat => DEFAULT_ANTHROPIC_MODEL,
        LlmBackend::Ollama => "llama3.2",
        LlmBackend::Vllm => "meta-llama/Meta-Llama-3.1-8B-Instruct",
    }
}

fn default_moderation_model(backend: &LlmBackend, generation_model: &str) -> String {
    match backend {
        LlmBackend::OpenAICompat => DEFAULT_MISTRAL_MODERATION_MODEL.to_string(),
        _ => generation_model.to_string(),
    }
}

fn default_embedding_model(backend: &LlmBackend, generation_model: &str) -> String {
    match backend {
        LlmBackend::OpenAICompat => DEFAULT_MISTRAL_EMBEDDING_MODEL.to_string(),
        _ => generation_model.to_string(),
    }
}

fn parse_csv_env(key: &str, defaults: &[&str]) -> Vec<String> {
    let value = env::var(key).unwrap_or_else(|_| defaults.join(","));
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_auth_credentials(key: &str) -> Vec<AuthCredentialConfig> {
    let value = env::var(key).unwrap_or_default();
    if value.trim().is_empty() {
        return Vec::new();
    }

    value
        .split(',')
        .filter_map(parse_auth_credential_entry)
        .collect()
}

fn parse_auth_credential_entry(entry: &str) -> Option<AuthCredentialConfig> {
    let fields = entry
        .split(':')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();

    match fields.as_slice() {
        [token, role] => Some(AuthCredentialConfig {
            token: (*token).to_owned(),
            role: (*role).to_owned(),
        }),
        [_label, token, role] => Some(AuthCredentialConfig {
            token: (*token).to_owned(),
            role: (*role).to_owned(),
        }),
        _ => None,
    }
}

fn parse_env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

fn parse_env_f32(key: &str, default: f32) -> Result<f32, SettingsError> {
    match env::var(key) {
        Ok(value) => value
            .parse::<f32>()
            .map_err(|source| SettingsError::ParseFloat {
                key: key.to_owned(),
                source,
            }),
        Err(_) => Ok(default),
    }
}

fn parse_env_usize(key: &str, default: usize) -> Result<usize, SettingsError> {
    match env::var(key) {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|source| SettingsError::ParseInt {
                key: key.to_owned(),
                source,
            }),
        Err(_) => Ok(default),
    }
}

fn parse_env_u16(key: &str, default: u16) -> Result<u16, SettingsError> {
    match env::var(key) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|source| SettingsError::ParseInt {
                key: key.to_owned(),
                source,
            }),
        Err(_) => Ok(default),
    }
}

fn parse_env_u32(key: &str, default: u32) -> Result<u32, SettingsError> {
    match env::var(key) {
        Ok(value) => value
            .parse::<u32>()
            .map_err(|source| SettingsError::ParseInt {
                key: key.to_owned(),
                source,
            }),
        Err(_) => Ok(default),
    }
}

fn parse_env_u64(key: &str, default: u64) -> Result<u64, SettingsError> {
    match env::var(key) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|source| SettingsError::ParseInt {
                key: key.to_owned(),
                source,
            }),
        Err(_) => Ok(default),
    }
}

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("failed to parse floating-point setting {key}: {source}")]
    ParseFloat {
        key: String,
        source: ParseFloatError,
    },
    #[error("failed to parse integer setting {key}: {source}")]
    ParseInt { key: String, source: ParseIntError },
}
