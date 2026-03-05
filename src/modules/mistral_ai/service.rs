use std::sync::Arc;

use thiserror::Error;
use tracing::{debug, error, info, warn};

use super::client::{MistralClient, MistralClientError};
use super::dtos::{
    ChatCompletionRequest, ChatCompletionResponse, ChatMessage, EmbeddingRequest,
    EmbeddingResponse, LanguageDetectionRequest, LanguageDetectionResponse,
    ModelValidationResponse, ModelValidationStatus, ModerationRequest, ModerationResponse,
    TranslationRequest, TranslationResponse,
};

#[derive(Clone)]
pub struct MistralService {
    client: Arc<dyn MistralClient>,
    generation_model: String,
    moderation_model: Option<String>,
    embedding_model: String,
}

impl MistralService {
    pub fn new(
        client: Arc<dyn MistralClient>,
        generation_model: impl Into<String>,
        moderation_model: Option<String>,
        embedding_model: impl Into<String>,
    ) -> Self {
        Self {
            client,
            generation_model: generation_model.into(),
            moderation_model,
            embedding_model: embedding_model.into(),
        }
    }

    pub async fn validate_generation_model(&self) -> Result<(), MistralServiceError> {
        info!("Validating generation model: {}", self.generation_model);
        let models = self.client.list_models().await?;
        if models
            .models
            .iter()
            .any(|model| model == &self.generation_model)
        {
            debug!("Generation model validated successfully");
            return Ok(());
        }
        error!("Generation model not found: {}", self.generation_model);
        Err(MistralServiceError::UnknownModel(
            self.generation_model.clone(),
        ))
    }

    pub async fn validate_moderation_model(&self) -> Result<(), MistralServiceError> {
        if let Some(model) = &self.moderation_model {
            info!("Validating moderation model: {}", model);
            let models = self.client.list_models().await?;
            if models.models.iter().any(|m| m == model) {
                debug!("Moderation model validated successfully");
                return Ok(());
            }
            error!("Moderation model not found: {}", model);
            Err(MistralServiceError::UnknownModel(model.clone()))
        } else {
            warn!("No moderation model configured");
            Ok(())
        }
    }

    pub async fn validate_embedding_model(&self) -> Result<(), MistralServiceError> {
        info!("Validating embedding model: {}", self.embedding_model);
        let models = self.client.list_models().await?;
        if models
            .models
            .iter()
            .any(|model| model == &self.embedding_model)
        {
            debug!("Embedding model validated successfully");
            return Ok(());
        }
        error!("Embedding model not found: {}", self.embedding_model);
        Err(MistralServiceError::UnknownModel(
            self.embedding_model.clone(),
        ))
    }

    pub async fn validate_all_models(&self) -> Result<(), MistralServiceError> {
        info!("Starting comprehensive model validation");
        self.validate_generation_model().await?;
        self.validate_moderation_model().await?;
        self.validate_embedding_model().await?;
        info!("All models validated successfully");
        Ok(())
    }

    pub async fn moderate_text(
        &self,
        input: impl Into<String>,
    ) -> Result<ModerationResponse, MistralServiceError> {
        self.moderate_text_with_model(input, None).await
    }

    pub async fn moderate_text_with_model(
        &self,
        input: impl Into<String>,
        model_override: Option<&str>,
    ) -> Result<ModerationResponse, MistralServiceError> {
        debug!("Moderating text with model: {:?}", self.moderation_model);
        let request = ModerationRequest {
            model: model_override
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| self.moderation_model.clone()),
            input: input.into(),
        };
        self.client.moderate(request).await.map_err(Into::into)
    }

    pub async fn generate_text(
        &self,
        prompt: impl Into<String>,
        safe_prompt: bool,
    ) -> Result<ChatCompletionResponse, MistralServiceError> {
        self.generate_text_with_model(prompt, safe_prompt, None)
            .await
    }

    pub async fn generate_text_with_model(
        &self,
        prompt: impl Into<String>,
        safe_prompt: bool,
        model_override: Option<&str>,
    ) -> Result<ChatCompletionResponse, MistralServiceError> {
        let model = model_override
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(self.generation_model.as_str())
            .to_string();
        debug!("Generating text with model: {}", self.generation_model);
        let request = ChatCompletionRequest {
            model,
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: prompt.into(),
            }],
            safe_prompt,
        };
        self.client
            .chat_completion(request)
            .await
            .map_err(Into::into)
    }

    pub async fn embed_text(
        &self,
        text: impl Into<String>,
    ) -> Result<EmbeddingResponse, MistralServiceError> {
        debug!("Creating embeddings with model: {}", self.embedding_model);
        let request = EmbeddingRequest {
            model: self.embedding_model.clone(),
            input: text.into(),
        };
        self.client.embeddings(request).await.map_err(Into::into)
    }

    pub async fn detect_language(
        &self,
        text: impl Into<String>,
    ) -> Result<LanguageDetectionResponse, MistralServiceError> {
        debug!("Detecting language of text");
        let request = LanguageDetectionRequest { text: text.into() };
        self.client
            .detect_language(request)
            .await
            .map_err(Into::into)
    }

    pub async fn translate_text(
        &self,
        text: impl Into<String>,
        target_language: impl Into<String> + Clone,
    ) -> Result<TranslationResponse, MistralServiceError> {
        let target_lang = target_language.clone();
        debug!("Translating text to {}", target_lang.into());
        let request = TranslationRequest {
            text: text.into(),
            target_language: target_language.into(),
        };
        self.client
            .translate_text(request)
            .await
            .map_err(Into::into)
    }

    pub async fn health_check(&self) -> Result<(), MistralServiceError> {
        info!("Performing Mistral API health check");

        // Test API connectivity by listing models
        let models = self.client.list_models().await?;
        if models.models.is_empty() {
            error!("Health check failed: no models available");
            return Err(MistralServiceError::Client(
                MistralClientError::InvalidResponse("No models available".to_owned()),
            ));
        }

        // Validate all configured models
        self.validate_all_models().await?;

        debug!("Health check passed: API and models are available");
        Ok(())
    }

    pub async fn validate_models_endpoint(&self) -> ModelValidationResponse {
        info!("Performing comprehensive model validation for /v1/models endpoint");

        let generation_status = self
            .validate_model_with_status(&self.generation_model)
            .await;
        let moderation_status = match &self.moderation_model {
            Some(model) => Some(self.validate_model_with_status(model).await),
            None => None,
        };
        let embedding_status = self.validate_model_with_status(&self.embedding_model).await;

        let overall_status = if generation_status.available
            && moderation_status
                .as_ref()
                .map(|s| s.available)
                .unwrap_or(true)
            && embedding_status.available
        {
            "all_models_available".to_string()
        } else {
            "some_models_unavailable".to_string()
        };

        ModelValidationResponse {
            generation_model: generation_status,
            moderation_model: moderation_status,
            embedding_model: embedding_status,
            overall_status,
        }
    }

    async fn validate_model_with_status(&self, model: &str) -> ModelValidationStatus {
        match self.validate_model(model).await {
            Ok(_) => ModelValidationStatus {
                model_name: model.to_string(),
                available: true,
                message: "Model is available and validated".to_string(),
            },
            Err(e) => ModelValidationStatus {
                model_name: model.to_string(),
                available: false,
                message: format!("Model validation failed: {}", e),
            },
        }
    }

    async fn validate_model(&self, model: &str) -> Result<(), MistralServiceError> {
        info!("Validating model: {}", model);
        let models = self.client.list_models().await?;
        if models.models.iter().any(|m| m == model) {
            debug!("Model validated successfully: {}", model);
            Ok(())
        } else {
            error!("Model not found: {}", model);
            Err(MistralServiceError::UnknownModel(model.to_string()))
        }
    }

    /// Getter methods for model names (used in health checks)
    pub fn generation_model(&self) -> &str {
        &self.generation_model
    }

    pub fn moderation_model(&self) -> Option<&String> {
        self.moderation_model.as_ref()
    }

    pub fn embedding_model(&self) -> &str {
        &self.embedding_model
    }
}

#[derive(Debug, Error)]
pub enum MistralServiceError {
    #[error("mistral client error: {0}")]
    Client(#[from] MistralClientError),
    #[error("configured generation model is unavailable: {0}")]
    UnknownModel(String),
}
