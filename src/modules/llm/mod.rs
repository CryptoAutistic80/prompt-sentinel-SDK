use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::modules::mistral_ai::client::MistralClientError;
use crate::modules::mistral_ai::dtos::{
    ChatCompletionRequest, ChatCompletionResponse, EmbeddingRequest, EmbeddingResponse,
    LanguageDetectionRequest, LanguageDetectionResponse, ModerationRequest, ModerationResponse,
    TranslationRequest, TranslationResponse,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ProviderBackend {
    OpenAICompat,
    AnthropicCompat,
    Ollama,
    Vllm,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub generation: bool,
    pub moderation: bool,
    pub embeddings: bool,
    pub language_detection: bool,
    pub translation: bool,
    pub model_listing: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy { reason: String },
}

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn generate(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, MistralClientError>;

    async fn moderate(
        &self,
        request: ModerationRequest,
    ) -> Result<ModerationResponse, MistralClientError>;

    async fn embed(
        &self,
        request: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, MistralClientError>;

    async fn detect_language(
        &self,
        request: LanguageDetectionRequest,
    ) -> Result<LanguageDetectionResponse, MistralClientError>;

    async fn translate_text(
        &self,
        request: TranslationRequest,
    ) -> Result<TranslationResponse, MistralClientError>;

    async fn list_models(&self) -> Result<Vec<String>, MistralClientError>;

    fn capabilities(&self) -> ProviderCapabilities;

    async fn health_check(&self) -> HealthStatus;
}
