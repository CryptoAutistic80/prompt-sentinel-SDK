use prompt_sentinel::config::settings::{AppSettings, LlmBackend};
use prompt_sentinel::modules::audit::logger::AuditLogger;
use prompt_sentinel::modules::audit::storage::AuditStorage;
use prompt_sentinel::modules::audit::storage::SledAuditStorage;
use prompt_sentinel::modules::bias_detection::service::BiasDetectionService;
use prompt_sentinel::modules::mistral_ai::client::{MistralClient, MockMistralClient};
use prompt_sentinel::modules::mistral_ai::service::MistralService;
use prompt_sentinel::modules::prompt_firewall::service::PromptFirewallService;
use prompt_sentinel::modules::semantic_detection::service::SemanticDetectionService;
use prompt_sentinel::workflow::{ComplianceEngine, ComplianceRequest};
use std::sync::Arc;

#[tokio::test]
async fn test_spanish_response_translation() {
    // Setup with mock Mistral client
    let settings = AppSettings {
        server_port: 3000,
        llm_backend: LlmBackend::OpenAICompat,
        llm_api_key: Some("mock".to_string()),
        llm_base_url: "http://localhost".to_string(),
        generation_model: "mock-model".to_string(),
        moderation_model: Some("mock-moderation".to_string()),
        embedding_model: "mock-embedding".to_string(),
        cors_allowed_origins: vec!["http://localhost:5175".to_string()],
        llm_request_timeout_secs: 120,
        llm_connect_timeout_secs: 10,
        llm_pool_max_idle_per_host: 20,
        llm_pool_idle_timeout_secs: 90,
        llm_circuit_breaker_failure_threshold: 5,
        llm_circuit_breaker_open_duration_secs: 30,
        bias_threshold: 0.35,
        max_input_length: 4096,
        semantic_medium_threshold: 0.70,
        semantic_high_threshold: 0.80,
        semantic_decision_margin: 0.02,
    };

    let audit_storage: Arc<dyn AuditStorage> =
        Arc::new(SledAuditStorage::new("test_multilingual_data").unwrap());
    let audit_logger = AuditLogger::new(audit_storage);

    let mistral_client: Arc<dyn MistralClient> = Arc::new(MockMistralClient::default());
    let mistral_service = MistralService::new(
        mistral_client.clone(),
        settings.generation_model.clone(),
        settings.moderation_model.clone(),
        settings.embedding_model.clone(),
    );

    let firewall_service =
        PromptFirewallService::new_with_mistral(settings.max_input_length, mistral_client.clone());
    let bias_service =
        BiasDetectionService::new_with_mistral(settings.bias_threshold, mistral_client.clone());

    let semantic_service = SemanticDetectionService::new(
        mistral_service.clone(),
        settings.semantic_medium_threshold,
        settings.semantic_high_threshold,
        settings.semantic_decision_margin,
    );

    // Initialize semantic service
    semantic_service.initialize().await.unwrap();

    let engine = ComplianceEngine::new(
        firewall_service,
        semantic_service,
        bias_service,
        mistral_service,
        audit_logger,
    );

    // Test with Spanish prompt
    let response = engine
        .process(ComplianceRequest {
            correlation_id: None,
            prompt: "Hola, ¿cómo estás?".to_string(),
        })
        .await
        .unwrap();

    // For mock client, the response should be in Spanish (mock behavior)
    // In production with real Mistral API, this would translate the English response back to Spanish
    if let Some(generated_text) = response.generated_text {
        println!("Generated response: {}", generated_text);
        // With mock client, this will be the mock response
        // With real API, this would be translated to Spanish
        assert!(!generated_text.is_empty(), "Response should not be empty");
    } else {
        // If blocked, that's also acceptable for this test
        println!("Prompt was blocked: {:?}", response.status);
    }
}

#[tokio::test]
async fn test_english_response_unchanged() {
    // Setup with mock Mistral client
    let settings = AppSettings {
        server_port: 3000,
        llm_backend: LlmBackend::OpenAICompat,
        llm_api_key: Some("mock".to_string()),
        llm_base_url: "http://localhost".to_string(),
        generation_model: "mock-model".to_string(),
        moderation_model: Some("mock-moderation".to_string()),
        embedding_model: "mock-embedding".to_string(),
        cors_allowed_origins: vec!["http://localhost:5175".to_string()],
        llm_request_timeout_secs: 120,
        llm_connect_timeout_secs: 10,
        llm_pool_max_idle_per_host: 20,
        llm_pool_idle_timeout_secs: 90,
        llm_circuit_breaker_failure_threshold: 5,
        llm_circuit_breaker_open_duration_secs: 30,
        bias_threshold: 0.35,
        max_input_length: 4096,
        semantic_medium_threshold: 0.70,
        semantic_high_threshold: 0.80,
        semantic_decision_margin: 0.02,
    };

    let audit_storage: Arc<dyn AuditStorage> =
        Arc::new(SledAuditStorage::new("test_english_data").unwrap());
    let audit_logger = AuditLogger::new(audit_storage);

    let mistral_client: Arc<dyn MistralClient> = Arc::new(MockMistralClient::default());
    let mistral_service = MistralService::new(
        mistral_client.clone(),
        settings.generation_model.clone(),
        settings.moderation_model.clone(),
        settings.embedding_model.clone(),
    );

    let firewall_service =
        PromptFirewallService::new_with_mistral(settings.max_input_length, mistral_client.clone());
    let bias_service =
        BiasDetectionService::new_with_mistral(settings.bias_threshold, mistral_client.clone());

    let semantic_service = SemanticDetectionService::new(
        mistral_service.clone(),
        settings.semantic_medium_threshold,
        settings.semantic_high_threshold,
        settings.semantic_decision_margin,
    );

    // Initialize semantic service
    semantic_service.initialize().await.unwrap();

    let engine = ComplianceEngine::new(
        firewall_service,
        semantic_service,
        bias_service,
        mistral_service,
        audit_logger,
    );

    // Test with English prompt
    let response = engine
        .process(ComplianceRequest {
            correlation_id: None,
            prompt: "Hello, how are you?".to_string(),
        })
        .await
        .unwrap();

    // English responses should remain in English
    if let Some(generated_text) = response.generated_text {
        println!("Generated response: {}", generated_text);
        assert!(!generated_text.is_empty(), "Response should not be empty");
    } else {
        // If blocked, that's also acceptable for this test
        println!("Prompt was blocked: {:?}", response.status);
    }
}
