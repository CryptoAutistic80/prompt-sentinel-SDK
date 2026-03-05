use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use super::dtos::{
    ChatCompletionRequest, ChatCompletionResponse, EmbeddingRequest, EmbeddingResponse,
    LanguageDetectionRequest, LanguageDetectionResponse, ModelListResponse, ModerationRequest,
    ModerationResponse, TokenUsage, TranslationRequest, TranslationResponse,
};
use crate::modules::llm::{HealthStatus, LLMProvider, ProviderCapabilities};
use crate::modules::mistral_ai::dtos::ChatMessage;

#[async_trait]
pub trait MistralClient: Send + Sync {
    async fn chat_completion(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError>;
    async fn moderate(
        &self,
        request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError>;
    async fn embeddings(
        &self,
        request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError>;
    async fn list_models(&self) -> Result<ModelListResponse, MistralClientError>;
    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError>;
    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError>;
}

#[derive(Clone, Debug)]
pub struct HttpClientConfig {
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
            pool_max_idle_per_host: 20,
            pool_idle_timeout: Duration::from_secs(90),
            max_retries: 3,
            retry_delay: Duration::from_millis(500),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub open_duration: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
struct CircuitBreakerState {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

#[derive(Clone, Debug)]
struct CircuitBreaker {
    state: Arc<Mutex<CircuitBreakerState>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(CircuitBreakerState {
                consecutive_failures: 0,
                opened_at: None,
            })),
            config,
        }
    }

    fn try_acquire(&self) -> Result<(), MistralClientError> {
        let mut guard = self.state.lock().map_err(|_| {
            MistralClientError::InvalidResponse("circuit state poisoned".to_owned())
        })?;

        if let Some(opened_at) = guard.opened_at {
            let elapsed = opened_at.elapsed();
            if elapsed < self.config.open_duration {
                let retry_after_secs = (self.config.open_duration - elapsed).as_secs().max(1);
                return Err(MistralClientError::CircuitOpen { retry_after_secs });
            }

            // Half-open probe allowed after timeout window.
            guard.opened_at = None;
            guard.consecutive_failures = 0;
        }

        Ok(())
    }

    fn on_success(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.consecutive_failures = 0;
            guard.opened_at = None;
        }
    }

    fn on_failure(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
            if guard.consecutive_failures >= self.config.failure_threshold {
                guard.opened_at = Some(Instant::now());
                warn!(
                    "Circuit breaker opened after {} consecutive failures",
                    guard.consecutive_failures
                );
            }
        }
    }
}

#[derive(Clone)]
pub struct HttpMistralClient {
    http: Client,
    base_url: String,
    api_key: String,
    max_retries: u32,
    retry_delay: Duration,
    language_model: String,
    circuit_breaker: CircuitBreaker,
}

impl HttpMistralClient {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self::new_with_config(
            base_url,
            api_key,
            HttpClientConfig::default(),
            CircuitBreakerConfig::default(),
        )
    }

    pub fn new_with_config(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        http_config: HttpClientConfig,
        circuit_breaker_config: CircuitBreakerConfig,
    ) -> Self {
        let http = Client::builder()
            .timeout(http_config.request_timeout)
            .connect_timeout(http_config.connect_timeout)
            .pool_max_idle_per_host(http_config.pool_max_idle_per_host)
            .pool_idle_timeout(http_config.pool_idle_timeout)
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            base_url: base_url.into(),
            api_key: api_key.into(),
            max_retries: http_config.max_retries,
            retry_delay: http_config.retry_delay,
            language_model: "mistral-large-latest".to_string(),
            circuit_breaker: CircuitBreaker::new(circuit_breaker_config),
        }
    }

    pub fn with_language_model(mut self, model: impl Into<String>) -> Self {
        self.language_model = model.into();
        self
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        if base.ends_with("/v1") {
            format!("{base}/{path}")
        } else {
            format!("{base}/v1/{path}")
        }
    }

    fn with_auth(&self, request_builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.api_key.is_empty() {
            request_builder
        } else {
            request_builder.bearer_auth(&self.api_key)
        }
    }

    async fn send_request_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<T, MistralClientError> {
        self.circuit_breaker.try_acquire()?;

        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            match request_builder.try_clone() {
                Some(cloned_builder) => {
                    debug!("Attempt {} for OpenAI-compatible API request", attempt + 1);

                    match cloned_builder.send().await {
                        Ok(response) => {
                            let status = response.status();
                            if response.status().is_success() {
                                let json = response.json::<T>().await?;
                                self.circuit_breaker.on_success();
                                debug!("OpenAI-compatible API request successful");
                                return Ok(json);
                            }

                            let error_body = response.text().await.unwrap_or_default();
                            error!("OpenAI-compatible API error {}: {}", status, error_body);

                            last_error = Some(MistralClientError::ApiError {
                                status: status.as_u16(),
                                message: error_body,
                            });
                        }
                        Err(e) => {
                            error!("OpenAI-compatible API request failed: {}", e);
                            last_error = Some(MistralClientError::Request(e));
                        }
                    }
                }
                None => {
                    return Err(MistralClientError::InvalidResponse(
                        "Failed to clone request builder".to_owned(),
                    ));
                }
            }

            if attempt < self.max_retries {
                warn!("Retrying in {:?}...", self.retry_delay);
                tokio::time::sleep(self.retry_delay).await;
            }
        }

        self.circuit_breaker.on_failure();

        Err(last_error.unwrap_or_else(|| {
            MistralClientError::InvalidResponse("All retry attempts failed".to_owned())
        }))
    }
}

#[async_trait]
impl MistralClient for HttpMistralClient {
    async fn chat_completion(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError> {
        info!(
            "Sending chat completion request to model: {}",
            request.model
        );

        let request_builder = self
            .with_auth(self.http.post(self.url("chat/completions")))
            .json(&request);

        let json: Value = self.send_request_with_retry(request_builder).await?;
        let output_text = extract_openai_content(&json)?;
        let model = json
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(request.model.as_str())
            .to_owned();

        let usage = json.get("usage").and_then(|u| {
            Some(TokenUsage {
                prompt_tokens: u.get("prompt_tokens")?.as_u64()? as u32,
                completion_tokens: u.get("completion_tokens")?.as_u64()? as u32,
                total_tokens: u.get("total_tokens")?.as_u64()? as u32,
            })
        });

        debug!("Chat completion successful for model: {}", model);
        Ok(ChatCompletionResponse {
            model,
            output_text,
            usage,
        })
    }

    async fn moderate(
        &self,
        request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError> {
        info!("Sending moderation request");

        let request_builder = self
            .with_auth(self.http.post(self.url("moderations")))
            .json(&request);

        let json: Value = self.send_request_with_retry(request_builder).await?;
        let result = json
            .get("results")
            .and_then(Value::as_array)
            .and_then(|results| results.first())
            .ok_or_else(|| {
                MistralClientError::InvalidResponse("missing moderation results".to_owned())
            })?;

        let flagged = result
            .get("flagged")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut categories = Vec::new();
        if let Some(map) = result.get("categories").and_then(Value::as_object) {
            for (category, value) in map {
                if value.as_bool().unwrap_or(false) {
                    categories.push(category.clone());
                }
            }
        }

        let severity = if flagged {
            (categories.len() as f32 / 5.0).min(1.0)
        } else {
            0.0
        };

        debug!(
            "Moderation completed: flagged={}, severity={}",
            flagged, severity
        );
        Ok(ModerationResponse {
            flagged,
            categories,
            severity,
        })
    }

    async fn embeddings(
        &self,
        request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError> {
        info!("Sending embedding request for model: {}", request.model);

        let request_builder = self
            .with_auth(self.http.post(self.url("embeddings")))
            .json(&request);

        let json: Value = self.send_request_with_retry(request_builder).await?;
        let vector_values = json
            .get("data")
            .and_then(Value::as_array)
            .and_then(|data| data.first())
            .and_then(|item| item.get("embedding"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                MistralClientError::InvalidResponse("missing embedding vector".to_owned())
            })?;

        let vector = vector_values
            .iter()
            .map(|value| value.as_f64().unwrap_or_default() as f32)
            .collect::<Vec<_>>();

        debug!("Embedding successful: vector length = {}", vector.len());
        Ok(EmbeddingResponse {
            model: request.model,
            vector,
        })
    }

    async fn list_models(&self) -> Result<ModelListResponse, MistralClientError> {
        info!("Fetching available models from OpenAI-compatible API");

        let request_builder = self.with_auth(self.http.get(self.url("models")));

        let json: Value = self.send_request_with_retry(request_builder).await?;
        let models = json
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| MistralClientError::InvalidResponse("missing model list".to_owned()))?
            .iter()
            .filter_map(|model| model.get("id").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        debug!("Available models: {:?}", models);
        Ok(ModelListResponse { models })
    }

    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError> {
        info!("Detecting language for text");

        let prompt = format!(
            "What language is this text written in? Reply with ONLY the language name (for example: English, German, Spanish, French) and nothing else.\n\nText: {}",
            request.text
        );

        let chat_request = ChatCompletionRequest {
            model: self.language_model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: prompt,
            }],
            safe_prompt: false,
        };

        let response = self.chat_completion(chat_request).await?;

        let language = response
            .output_text
            .trim()
            .trim_matches(|c| c == '"' || c == '\'' || c == '.' || c == ':')
            .to_owned();

        debug!("Detected language: {}", language);

        Ok(LanguageDetectionResponse {
            language,
            confidence: 0.95,
        })
    }

    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError> {
        info!("Translating text to {}", request.target_language);

        let prompt = format!(
            "Translate the following text to {}. Return ONLY the translated text, nothing else.\n\nText: {}",
            request.target_language, request.text
        );

        let chat_request = ChatCompletionRequest {
            model: self.language_model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: prompt,
            }],
            safe_prompt: false,
        };

        let response = self.chat_completion(chat_request).await?;

        Ok(TranslationResponse {
            translated_text: response.output_text.trim().to_owned(),
        })
    }
}

#[async_trait]
impl LLMProvider for HttpMistralClient {
    async fn generate(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError> {
        self.chat_completion(request).await
    }

    async fn moderate(
        &self,
        request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError> {
        MistralClient::moderate(self, request).await
    }

    async fn embed(
        &self,
        request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError> {
        self.embeddings(request).await
    }

    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError> {
        MistralClient::detect_language(self, request).await
    }

    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError> {
        MistralClient::translate_text(self, request).await
    }

    async fn list_models(&self) -> Result<Vec<String>, MistralClientError> {
        Ok(MistralClient::list_models(self).await?.models)
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            generation: true,
            moderation: true,
            embeddings: true,
            language_detection: true,
            translation: true,
            model_listing: true,
        }
    }

    async fn health_check(&self) -> HealthStatus {
        match MistralClient::list_models(self).await {
            Ok(models) if !models.models.is_empty() => HealthStatus::Healthy,
            Ok(_) => HealthStatus::Unhealthy {
                reason: "No models returned".to_string(),
            },
            Err(error) => HealthStatus::Unhealthy {
                reason: error.to_string(),
            },
        }
    }
}

#[derive(Clone)]
pub struct HttpAnthropicCompatClient {
    http: Client,
    base_url: String,
    api_key: String,
    default_model: String,
    max_retries: u32,
    retry_delay: Duration,
    circuit_breaker: CircuitBreaker,
}

impl HttpAnthropicCompatClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        default_model: impl Into<String>,
    ) -> Self {
        Self::new_with_config(
            base_url,
            api_key,
            default_model,
            HttpClientConfig::default(),
            CircuitBreakerConfig::default(),
        )
    }

    pub fn new_with_config(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        default_model: impl Into<String>,
        http_config: HttpClientConfig,
        circuit_breaker_config: CircuitBreakerConfig,
    ) -> Self {
        let http = Client::builder()
            .timeout(http_config.request_timeout)
            .connect_timeout(http_config.connect_timeout)
            .pool_max_idle_per_host(http_config.pool_max_idle_per_host)
            .pool_idle_timeout(http_config.pool_idle_timeout)
            .build()
            .expect("failed to build anthropic HTTP client");

        Self {
            http,
            base_url: base_url.into(),
            api_key: api_key.into(),
            default_model: default_model.into(),
            max_retries: http_config.max_retries,
            retry_delay: http_config.retry_delay,
            circuit_breaker: CircuitBreaker::new(circuit_breaker_config),
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        if base.ends_with("/v1") {
            format!("{base}/{path}")
        } else {
            format!("{base}/v1/{path}")
        }
    }

    fn with_anthropic_headers(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        request_builder
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
    }

    async fn send_request_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<T, MistralClientError> {
        self.circuit_breaker.try_acquire()?;

        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            match request_builder.try_clone() {
                Some(cloned_builder) => {
                    debug!("Attempt {} for Anthropic API request", attempt + 1);

                    match cloned_builder.send().await {
                        Ok(response) => {
                            let status = response.status();
                            if response.status().is_success() {
                                let json = response.json::<T>().await?;
                                self.circuit_breaker.on_success();
                                return Ok(json);
                            }

                            let error_body = response.text().await.unwrap_or_default();
                            error!("Anthropic API error {}: {}", status, error_body);
                            last_error = Some(MistralClientError::ApiError {
                                status: status.as_u16(),
                                message: error_body,
                            });
                        }
                        Err(e) => {
                            error!("Anthropic API request failed: {}", e);
                            last_error = Some(MistralClientError::Request(e));
                        }
                    }
                }
                None => {
                    return Err(MistralClientError::InvalidResponse(
                        "Failed to clone request builder".to_owned(),
                    ));
                }
            }

            if attempt < self.max_retries {
                warn!("Retrying in {:?}...", self.retry_delay);
                tokio::time::sleep(self.retry_delay).await;
            }
        }

        self.circuit_breaker.on_failure();

        Err(last_error.unwrap_or_else(|| {
            MistralClientError::InvalidResponse("All retry attempts failed".to_owned())
        }))
    }

    fn build_moderation_prompt(&self, content: &str) -> String {
        format!(
            "Classify the following text for policy violations. Return ONLY JSON in this exact shape: \
{{\"flagged\": boolean, \"categories\": [\"category\"], \"severity\": number between 0 and 1}}.\n\nText: {content}"
        )
    }
}

#[async_trait]
impl MistralClient for HttpAnthropicCompatClient {
    async fn chat_completion(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError> {
        let prompt = request
            .messages
            .last()
            .map(|m| m.content.clone())
            .unwrap_or_default();

        let body = json!({
            "model": request.model,
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let request_builder =
            self.with_anthropic_headers(self.http.post(self.url("messages")).json(&body));

        let json: Value = self.send_request_with_retry(request_builder).await?;
        let output_text = extract_anthropic_content(&json)?;
        let model = json
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(request.model.as_str())
            .to_owned();

        let usage = json.get("usage").and_then(|u| {
            let prompt_tokens = u.get("input_tokens")?.as_u64()? as u32;
            let completion_tokens = u.get("output_tokens")?.as_u64()? as u32;
            Some(TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens.saturating_add(completion_tokens),
            })
        });

        Ok(ChatCompletionResponse {
            model,
            output_text,
            usage,
        })
    }

    async fn moderate(
        &self,
        request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError> {
        let chat_request = ChatCompletionRequest {
            model: request.model.unwrap_or_else(|| self.default_model.clone()),
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: self.build_moderation_prompt(&request.input),
            }],
            safe_prompt: false,
        };

        let response = self.chat_completion(chat_request).await?;
        Ok(parse_moderation_response(&response.output_text))
    }

    async fn embeddings(
        &self,
        request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError> {
        // Anthropic does not expose a native embeddings endpoint. We return a deterministic
        // fallback embedding so the rest of the compliance pipeline remains operational.
        Ok(EmbeddingResponse {
            model: request.model,
            vector: pseudo_embedding(&request.input),
        })
    }

    async fn list_models(&self) -> Result<ModelListResponse, MistralClientError> {
        let request_builder = self.with_anthropic_headers(self.http.get(self.url("models")));
        let json: Value = self.send_request_with_retry(request_builder).await?;
        let models = json
            .get("data")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("id").and_then(Value::as_str))
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if models.is_empty() {
            return Ok(ModelListResponse {
                models: vec![self.default_model.clone()],
            });
        }

        Ok(ModelListResponse { models })
    }

    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError> {
        let chat_request = ChatCompletionRequest {
            model: self.default_model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: format!(
                    "What language is this text written in? Reply with only the language name.\n\nText: {}",
                    request.text
                ),
            }],
            safe_prompt: false,
        };

        let response = self.chat_completion(chat_request).await?;
        Ok(LanguageDetectionResponse {
            language: response
                .output_text
                .trim()
                .trim_matches(|c| c == '"' || c == '\'' || c == '.' || c == ':')
                .to_owned(),
            confidence: 0.90,
        })
    }

    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError> {
        let chat_request = ChatCompletionRequest {
            model: self.default_model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: format!(
                    "Translate the following text to {}. Return only the translated text.\n\nText: {}",
                    request.target_language, request.text
                ),
            }],
            safe_prompt: false,
        };

        let response = self.chat_completion(chat_request).await?;
        Ok(TranslationResponse {
            translated_text: response.output_text.trim().to_owned(),
        })
    }
}

#[async_trait]
impl LLMProvider for HttpAnthropicCompatClient {
    async fn generate(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError> {
        self.chat_completion(request).await
    }

    async fn moderate(
        &self,
        request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError> {
        MistralClient::moderate(self, request).await
    }

    async fn embed(
        &self,
        request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError> {
        self.embeddings(request).await
    }

    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError> {
        MistralClient::detect_language(self, request).await
    }

    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError> {
        MistralClient::translate_text(self, request).await
    }

    async fn list_models(&self) -> Result<Vec<String>, MistralClientError> {
        Ok(MistralClient::list_models(self).await?.models)
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            generation: true,
            moderation: true,
            embeddings: false,
            language_detection: true,
            translation: true,
            model_listing: true,
        }
    }

    async fn health_check(&self) -> HealthStatus {
        match MistralClient::list_models(self).await {
            Ok(models) if !models.models.is_empty() => HealthStatus::Healthy,
            Ok(_) => HealthStatus::Unhealthy {
                reason: "No models returned".to_string(),
            },
            Err(error) => HealthStatus::Unhealthy {
                reason: error.to_string(),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct MockMistralClient {
    chat_response: ChatCompletionResponse,
    moderation_responses: Arc<Mutex<Vec<ModerationResponse>>>,
    embedding_response: EmbeddingResponse,
    models: Vec<String>,
}

impl Default for MockMistralClient {
    fn default() -> Self {
        Self {
            chat_response: ChatCompletionResponse {
                model: "mistral-large-latest".to_owned(),
                output_text: "Mock response".to_owned(),
                usage: Some(TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 20,
                    total_tokens: 30,
                }),
            },
            moderation_responses: Arc::new(Mutex::new(vec![
                ModerationResponse {
                    flagged: false,
                    categories: Vec::new(),
                    severity: 0.0,
                },
                ModerationResponse {
                    flagged: false,
                    categories: Vec::new(),
                    severity: 0.0,
                },
            ])),
            embedding_response: EmbeddingResponse {
                model: "mistral-embed".to_owned(),
                vector: vec![0.1, 0.2, 0.3],
            },
            models: vec![
                "mistral-large-latest".to_owned(),
                "mistral-embed".to_owned(),
            ],
        }
    }
}

impl MockMistralClient {
    pub fn with_moderation_sequence(
        sequence: Vec<ModerationResponse>,
    ) -> Result<Self, MistralClientError> {
        if sequence.is_empty() {
            return Err(MistralClientError::InvalidResponse(
                "moderation sequence cannot be empty".to_owned(),
            ));
        }
        Ok(Self {
            moderation_responses: Arc::new(Mutex::new(sequence)),
            ..Default::default()
        })
    }

    pub fn with_chat_response(mut self, response: ChatCompletionResponse) -> Self {
        self.chat_response = response;
        self
    }
}

#[async_trait]
impl MistralClient for MockMistralClient {
    async fn chat_completion(
        &self,
        _request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError> {
        Ok(self.chat_response.clone())
    }

    async fn moderate(
        &self,
        _request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError> {
        let mut guard = self.moderation_responses.lock().map_err(|_| {
            MistralClientError::InvalidResponse("moderation queue poisoned".to_owned())
        })?;

        if guard.len() > 1 {
            Ok(guard.remove(0))
        } else {
            Ok(guard[0].clone())
        }
    }

    async fn embeddings(
        &self,
        _request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError> {
        Ok(self.embedding_response.clone())
    }

    async fn list_models(&self) -> Result<ModelListResponse, MistralClientError> {
        Ok(ModelListResponse {
            models: self.models.clone(),
        })
    }

    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError> {
        let text_lower = request.text.to_ascii_lowercase();
        if text_lower.contains("hola") || text_lower.contains("el") || text_lower.contains("la") {
            Ok(LanguageDetectionResponse {
                language: "Spanish".to_owned(),
                confidence: 0.95,
            })
        } else {
            Ok(LanguageDetectionResponse {
                language: "English".to_owned(),
                confidence: 0.95,
            })
        }
    }

    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError> {
        Ok(TranslationResponse {
            translated_text: request.text,
        })
    }
}

fn extract_openai_content(response: &Value) -> Result<String, MistralClientError> {
    let message_content = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .ok_or_else(|| {
            MistralClientError::InvalidResponse("missing response content".to_owned())
        })?;

    if let Some(content) = message_content.as_str() {
        return Ok(content.to_owned());
    }

    if let Some(items) = message_content.as_array() {
        let combined = items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        if !combined.is_empty() {
            return Ok(combined);
        }
    }

    Err(MistralClientError::InvalidResponse(
        "unsupported response content shape".to_owned(),
    ))
}

fn extract_anthropic_content(response: &Value) -> Result<String, MistralClientError> {
    let content = response
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            MistralClientError::InvalidResponse("missing anthropic response text".to_owned())
        })?;

    Ok(content.to_owned())
}

fn parse_moderation_response(raw: &str) -> ModerationResponse {
    let payload = extract_json_payload(raw);
    let parsed = payload
        .as_deref()
        .and_then(|json_payload| serde_json::from_str::<Value>(json_payload).ok());

    if let Some(value) = parsed {
        let flagged = value
            .get("flagged")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let categories = value
            .get("categories")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let severity = value
            .get("severity")
            .and_then(Value::as_f64)
            .map(|num| num as f32)
            .unwrap_or_else(|| if flagged { 0.7 } else { 0.0 });

        return ModerationResponse {
            flagged,
            categories,
            severity: severity.clamp(0.0, 1.0),
        };
    }

    ModerationResponse {
        flagged: false,
        categories: Vec::new(),
        severity: 0.0,
    }
}

fn extract_json_payload(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end < start {
        return None;
    }
    Some(raw[start..=end].to_owned())
}

fn pseudo_embedding(text: &str) -> Vec<f32> {
    let mut vector = Vec::with_capacity(256);
    let mut seed = text.as_bytes().to_vec();

    while vector.len() < 256 {
        let digest = Sha256::digest(&seed);
        for byte in digest {
            let value = (byte as f32 / 255.0) * 2.0 - 1.0;
            vector.push(value);
            if vector.len() == 256 {
                break;
            }
        }
        seed = digest.to_vec();
    }

    vector
}

#[derive(Debug, Error)]
pub enum MistralClientError {
    #[error("upstream request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("upstream API error: HTTP {status} - {message}")]
    ApiError { status: u16, message: String },
    #[error("upstream response contract invalid: {0}")]
    InvalidResponse(String),
    #[error("upstream circuit breaker is open; retry in {retry_after_secs}s")]
    CircuitOpen { retry_after_secs: u64 },
}
