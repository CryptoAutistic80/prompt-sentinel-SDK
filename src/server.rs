use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{debug, error, info, warn};

use crate::config::settings::{
    AppSettings, DEFAULT_MISTRAL_BASE_URL, DEFAULT_MISTRAL_EMBEDDING_MODEL,
    DEFAULT_MISTRAL_GENERATION_MODEL, DEFAULT_MISTRAL_MODERATION_MODEL, LlmBackend,
};
use crate::modules::audit::logger::AuditLogger;
use crate::modules::audit::storage::{
    AuditStorage, AuditTrailRequest, AuditTrailResponse, SledAuditStorage,
};
use crate::modules::auth::{
    AuthAdminError, AuthError, AuthService, GenerateCredentialCommand, RotateCredentialCommand,
};
use crate::modules::bias_detection::service::BiasDetectionService;
use crate::modules::eu_law_compliance::dtos::{
    ComplianceConfigurationRequest, ComplianceConfigurationResponse, ComplianceReportRequest,
    ComplianceReportResponse,
};
use crate::modules::eu_law_compliance::service::EuLawComplianceService;
use crate::modules::mistral_ai::client::{
    CircuitBreakerConfig, HttpAnthropicCompatClient, HttpClientConfig, HttpMistralClient,
    MistralClient,
};
use crate::modules::mistral_ai::dtos::ModelValidationResponse;
use crate::modules::mistral_ai::service::MistralService;
use crate::modules::prompt_firewall::service::PromptFirewallService;
use crate::modules::semantic_detection::service::SemanticDetectionService;
use crate::modules::telemetry::correlation::generate_correlation_id;
use crate::modules::telemetry::metrics::{RequestTimer, get_metrics};
use crate::modules::telemetry::tracing::{create_span_with_correlation, log_with_correlation};
use crate::workflow::{ComplianceEngine, ComplianceRequest, ComplianceResponse};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ComplianceEngine>,
    pub startup_complete: Arc<AtomicBool>,
    pub auth_service: Arc<AuthService>,
}

/// Telemetry middleware for request tracking
async fn telemetry_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let endpoint = format!("{}:{}", method, path);

    let correlation_id = generate_correlation_id();

    let timer = RequestTimer::new();
    get_metrics().increment_active_requests();
    get_metrics().increment_requests(method.as_str(), &endpoint);

    let mut request = request;
    request.headers_mut().insert(
        "X-Correlation-ID",
        axum::http::HeaderValue::from_str(&correlation_id)
            .expect("correlation ID should be valid header value"),
    );

    let span = create_span_with_correlation(&correlation_id, "request");
    let _enter = span.enter();

    log_with_correlation(
        &correlation_id,
        tracing::Level::INFO,
        &format!("Request started: {} {}", method, path),
    );

    let response = next.run(request).await;

    let duration = timer.elapsed_seconds();
    get_metrics().record_latency(method.as_str(), &endpoint, duration);
    get_metrics().decrement_active_requests();

    log_with_correlation(
        &correlation_id,
        tracing::Level::INFO,
        &format!("Request completed: {} {} in {:.3}s", method, path, duration),
    );

    response
}

/// Adds a secure baseline set of response headers for browser-facing endpoints.
async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; base-uri 'self'"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    response
}

/// Auth middleware for protected API endpoints.
async fn auth_middleware(
    State(state): State<AppState>,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();

    match state
        .auth_service
        .authorize_request(request.headers(), &method, &path)
    {
        Ok(Some(auth_context)) => {
            request.extensions_mut().insert(auth_context);
            next.run(request).await
        }
        Ok(None) => next.run(request).await,
        Err(error) => {
            let (status, code) = match &error {
                AuthError::MissingCredentials
                | AuthError::InvalidCredentials
                | AuthError::ExpiredCredentials
                | AuthError::RevokedCredentials => (StatusCode::UNAUTHORIZED, "unauthorized"),
                AuthError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden"),
                AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
                AuthError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "auth_internal"),
            };

            get_metrics().increment_errors("auth");

            (
                status,
                Json(serde_json::json!({
                    "error": code,
                    "message": error.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// Framework server builder
pub struct PromptSentinelServer {
    config: AppSettings,
    state: AppState,
}

impl PromptSentinelServer {
    /// Create a new server instance
    pub fn new(config: AppSettings, engine: ComplianceEngine) -> Self {
        let auth_service = Arc::new(AuthService::from_settings(&config));
        Self {
            config,
            state: AppState {
                engine: Arc::new(engine),
                startup_complete: Arc::new(AtomicBool::new(true)),
                auth_service,
            },
        }
    }

    fn cors_layer(&self) -> CorsLayer {
        if self
            .config
            .cors_allowed_origins
            .iter()
            .any(|origin| origin == "*")
        {
            return CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any);
        }

        let origins = self
            .config
            .cors_allowed_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect::<Vec<_>>();

        if origins.is_empty() {
            warn!("No valid CORS origins configured; denying cross-origin access");
            return CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any);
        }

        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
    }

    /// Build the axum router with all endpoints
    fn build_router(&self) -> Router {
        let protected_routes = Router::new()
            .route("/api/compliance/check", post(check_compliance))
            .route("/api/mistral/health", get(llm_health_check))
            .route("/api/llm/health", get(llm_health_check))
            .route("/v1/models", get(validate_models))
            .route("/api/auth/keys", get(list_auth_keys))
            .route("/api/auth/keys/generate", post(generate_auth_key))
            .route("/api/auth/keys/rotate", post(rotate_auth_key))
            .route("/api/auth/keys/revoke", post(revoke_auth_key))
            .route("/api/auth/keys/expire", post(expire_auth_key))
            .route("/api/auth/access-log", get(get_auth_access_log))
            .route("/api/audit/trail", post(get_audit_trail))
            .route("/api/compliance/report", post(generate_compliance_report))
            .route("/api/compliance/config", get(get_compliance_config))
            .route("/api/compliance/config", post(update_compliance_config))
            .route_layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                auth_middleware,
            ));

        Router::new()
            .merge(protected_routes)
            .route("/health", get(ready_check))
            .route("/health/live", get(live_check))
            .route("/health/ready", get(ready_check))
            .route("/health/startup", get(startup_check))
            .layer(self.cors_layer())
            .route_layer(axum::middleware::from_fn(security_headers_middleware))
            .route_layer(axum::middleware::from_fn(telemetry_middleware))
            .with_state(self.state.clone())
    }

    /// Start the server
    pub async fn start(self) -> Result<(), std::io::Error> {
        let app = self.build_router();
        let addr = format!("0.0.0.0:{}", self.config.server_port);

        info!("Prompt Sentinel Server starting on {}", addr);
        info!("Using sled for audit storage");
        info!("Framework version: {}", env!("CARGO_PKG_VERSION"));

        let listener = TcpListener::bind(&addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!("Failed to install Ctrl+C signal handler: {error}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        let mut stream =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(stream) => stream,
                Err(error) => {
                    error!("Failed to install SIGTERM handler: {error}");
                    return;
                }
            };
        stream.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received; draining in-flight requests");
    tokio::time::sleep(Duration::from_millis(250)).await;
}

async fn live_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "alive",
        "timestamp": chrono::Utc::now(),
    }))
}

async fn ready_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut dependency_errors = Vec::new();

    if let Err(error) = state.engine.audit_logger().storage().latest_chain_hash() {
        dependency_errors.push(format!("audit_storage: {error}"));
    }

    if let Err(error) = state.engine.mistral_service().health_check().await {
        dependency_errors.push(format!("llm_provider: {error}"));
    }

    if dependency_errors.is_empty() {
        Ok(Json(serde_json::json!({
            "status": "ready",
            "timestamp": chrono::Utc::now(),
        })))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Not ready: {}", dependency_errors.join("; ")),
        ))
    }
}

async fn startup_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if state.startup_complete.load(Ordering::Relaxed) {
        return Ok(Json(serde_json::json!({
            "status": "started",
            "timestamp": chrono::Utc::now(),
        })));
    }

    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "Startup sequence not completed".to_owned(),
    ))
}

async fn llm_health_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let correlation_id = generate_correlation_id();
    log_with_correlation(
        &correlation_id,
        tracing::Level::DEBUG,
        "Received LLM health check request",
    );

    let mistral_service = state.engine.mistral_service();

    match mistral_service.health_check().await {
        Ok(_) => {
            log_with_correlation(
                &correlation_id,
                tracing::Level::INFO,
                "LLM health check passed",
            );
            Ok(Json(serde_json::json!({
                "status": "healthy",
                "message": "LLM provider integration is operational",
                "models": [
                    mistral_service.generation_model(),
                    mistral_service.moderation_model(),
                    mistral_service.embedding_model()
                ]
            })))
        }
        Err(e) => {
            log_with_correlation(
                &correlation_id,
                tracing::Level::ERROR,
                &format!("LLM health check failed: {}", e),
            );
            get_metrics().increment_errors("llm_health_check");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("LLM provider unhealthy: {}", e),
            ))
        }
    }
}

async fn validate_models(
    State(state): State<AppState>,
) -> Result<Json<ModelValidationResponse>, (StatusCode, String)> {
    debug!("Received model validation request");

    let mistral_service = state.engine.mistral_service();
    let response = mistral_service.validate_models_endpoint().await;

    info!("Model validation completed");
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct AuthAccessLogQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RotateAuthKeyRequest {
    old_token: String,
    new_token: String,
    role: Option<String>,
    scopes: Option<Vec<String>>,
    label: Option<String>,
    is_service_account: Option<bool>,
    expires_in_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GenerateAuthKeyRequest {
    role: String,
    scopes: Option<Vec<String>>,
    label: Option<String>,
    is_service_account: Option<bool>,
    expires_in_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct KeyLifecycleRequest {
    key_id: String,
}

async fn list_auth_keys(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credentials = state
        .auth_service
        .list_credentials()
        .map_err(map_auth_admin_error)?;

    Ok(Json(serde_json::json!({
        "count": credentials.len(),
        "credentials": credentials,
    })))
}

async fn rotate_auth_key(
    State(state): State<AppState>,
    Json(request): Json<RotateAuthKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let updated = state
        .auth_service
        .rotate_credential(RotateCredentialCommand {
            old_token: request.old_token,
            new_token: request.new_token,
            role: request.role,
            scopes: request.scopes,
            label: request.label,
            is_service_account: request.is_service_account,
            expires_in_seconds: request.expires_in_seconds,
        })
        .map_err(map_auth_admin_error)?;

    Ok(Json(serde_json::json!({
        "status": "rotated",
        "credential": updated,
    })))
}

async fn generate_auth_key(
    State(state): State<AppState>,
    Json(request): Json<GenerateAuthKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let generated = state
        .auth_service
        .generate_credential(GenerateCredentialCommand {
            role: request.role,
            scopes: request.scopes.unwrap_or_default(),
            label: request.label,
            is_service_account: request.is_service_account.unwrap_or(false),
            expires_in_seconds: request.expires_in_seconds,
        })
        .map_err(map_auth_admin_error)?;

    Ok(Json(serde_json::json!({
        "status": "generated",
        "token": generated.token,
        "credential": generated.credential,
    })))
}

async fn revoke_auth_key(
    State(state): State<AppState>,
    Json(request): Json<KeyLifecycleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credential = state
        .auth_service
        .revoke_credential(&request.key_id)
        .map_err(map_auth_admin_error)?;

    Ok(Json(serde_json::json!({
        "status": "revoked",
        "credential": credential,
    })))
}

async fn expire_auth_key(
    State(state): State<AppState>,
    Json(request): Json<KeyLifecycleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credential = state
        .auth_service
        .expire_credential(&request.key_id)
        .map_err(map_auth_admin_error)?;

    Ok(Json(serde_json::json!({
        "status": "expired",
        "credential": credential,
    })))
}

async fn get_auth_access_log(
    State(state): State<AppState>,
    Query(query): Query<AuthAccessLogQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let events = state
        .auth_service
        .access_events(query.limit)
        .map_err(map_auth_admin_error)?;

    Ok(Json(serde_json::json!({
        "count": events.len(),
        "events": events,
    })))
}

fn map_auth_admin_error(error: AuthAdminError) -> (StatusCode, String) {
    match error {
        AuthAdminError::NotEnabled => (StatusCode::BAD_REQUEST, error.to_string()),
        AuthAdminError::CredentialNotFound => (StatusCode::NOT_FOUND, error.to_string()),
        AuthAdminError::NewTokenAlreadyExists => (StatusCode::CONFLICT, error.to_string()),
        AuthAdminError::TokenGenerationFailed => {
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
        AuthAdminError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, error.to_string()),
        AuthAdminError::StoragePoisoned | AuthAdminError::PersistenceFailed(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
    }
}

async fn get_audit_trail(
    State(state): State<AppState>,
    Json(request): Json<AuditTrailRequest>,
) -> Result<Json<AuditTrailResponse>, (StatusCode, String)> {
    debug!("Received audit trail request");

    let audit_logger = state.engine.audit_logger();
    let storage = audit_logger.storage();

    match storage.get_with_filters(
        request.limit,
        request.offset,
        request.start_time,
        request.end_time,
        request.correlation_id,
    ) {
        Ok(response) => {
            info!("Audit trail retrieved successfully");
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to retrieve audit trail: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve audit trail: {}", e),
            ))
        }
    }
}

async fn generate_compliance_report(
    State(_state): State<AppState>,
    Json(request): Json<ComplianceReportRequest>,
) -> Result<Json<ComplianceReportResponse>, (StatusCode, String)> {
    debug!("Received compliance report generation request");

    let eu_service = EuLawComplianceService;
    let response = eu_service.generate_compliance_report(request);

    info!("Compliance report generated successfully");
    Ok(Json(response))
}

async fn get_compliance_config(
    State(_state): State<AppState>,
) -> Result<Json<ComplianceConfigurationResponse>, (StatusCode, String)> {
    debug!("Received compliance configuration request");

    let eu_service = EuLawComplianceService;
    let response = eu_service.get_current_configuration();

    let config_response = ComplianceConfigurationResponse {
        status: "success".to_string(),
        message: "Current compliance configuration retrieved".to_string(),
        current_configuration: response,
    };

    info!("Compliance configuration retrieved successfully");
    Ok(Json(config_response))
}

async fn update_compliance_config(
    State(_state): State<AppState>,
    Json(request): Json<ComplianceConfigurationRequest>,
) -> Result<Json<ComplianceConfigurationResponse>, (StatusCode, String)> {
    debug!("Received compliance configuration update request");

    let eu_service = EuLawComplianceService;
    let response = eu_service.update_configuration(request);

    info!("Compliance configuration update processed");
    Ok(Json(response))
}

async fn check_compliance(
    State(state): State<AppState>,
    Json(request): Json<ComplianceRequest>,
) -> Result<Json<ComplianceResponse>, (StatusCode, String)> {
    state
        .engine
        .process(request)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Framework configuration for easy setup
pub struct FrameworkConfig {
    pub server_port: u16,
    pub sled_db_path: String,
    pub mistral_api_key: Option<String>,
}

impl Default for FrameworkConfig {
    fn default() -> Self {
        Self {
            server_port: 3000,
            sled_db_path: "prompt_sentinel_data".to_string(),
            mistral_api_key: std::env::var("MISTRAL_API_KEY")
                .or_else(|_| std::env::var("LLM_API_KEY"))
                .ok(),
        }
    }
}

impl FrameworkConfig {
    /// Initialize the framework with default or custom configuration
    pub async fn initialize(self) -> Result<PromptSentinelServer, Box<dyn std::error::Error>> {
        let settings = AppSettings::from_env().unwrap_or_else(|_| AppSettings {
            server_port: self.server_port,
            llm_backend: LlmBackend::OpenAICompat,
            llm_api_key: self.mistral_api_key.clone(),
            llm_base_url: DEFAULT_MISTRAL_BASE_URL.to_string(),
            generation_model: DEFAULT_MISTRAL_GENERATION_MODEL.to_string(),
            moderation_model: Some(DEFAULT_MISTRAL_MODERATION_MODEL.to_string()),
            embedding_model: DEFAULT_MISTRAL_EMBEDDING_MODEL.to_string(),
            cors_allowed_origins: vec![
                "http://localhost:5175".to_string(),
                "http://127.0.0.1:5175".to_string(),
            ],
            llm_request_timeout_secs: 120,
            llm_connect_timeout_secs: 10,
            llm_pool_max_idle_per_host: 20,
            llm_pool_idle_timeout_secs: 90,
            llm_circuit_breaker_failure_threshold: 5,
            llm_circuit_breaker_open_duration_secs: 30,
            auth_enabled: false,
            auth_api_keys: Vec::new(),
            auth_service_tokens: Vec::new(),
            auth_rate_limit_per_minute: 300,
            auth_key_store_path: Some("prompt_sentinel_data/auth_keys.json".to_string()),
            auth_default_key_expiry_secs: None,
            bias_threshold: 0.35,
            max_input_length: 4096,
            semantic_medium_threshold: 0.70,
            semantic_high_threshold: 0.80,
            semantic_decision_margin: 0.02,
        });

        if settings.auth_enabled
            && settings.auth_api_keys.is_empty()
            && settings.auth_service_tokens.is_empty()
        {
            warn!(
                "AUTH_ENABLED=true but no credentials configured; protected routes will reject all requests"
            );
        }

        let audit_storage: Arc<dyn AuditStorage> =
            Arc::new(SledAuditStorage::new(&self.sled_db_path)?);
        let audit_logger = AuditLogger::new(audit_storage);

        let http_config = HttpClientConfig {
            request_timeout: Duration::from_secs(settings.llm_request_timeout_secs),
            connect_timeout: Duration::from_secs(settings.llm_connect_timeout_secs),
            pool_max_idle_per_host: settings.llm_pool_max_idle_per_host,
            pool_idle_timeout: Duration::from_secs(settings.llm_pool_idle_timeout_secs),
            max_retries: 3,
            retry_delay: Duration::from_millis(500),
        };
        let circuit_breaker_config = CircuitBreakerConfig {
            failure_threshold: settings.llm_circuit_breaker_failure_threshold,
            open_duration: Duration::from_secs(settings.llm_circuit_breaker_open_duration_secs),
        };

        let llm_client: Arc<dyn MistralClient> = if settings.llm_api_key.as_deref() == Some("mock")
        {
            Arc::new(crate::modules::mistral_ai::client::MockMistralClient::default())
        } else {
            let api_key = settings.llm_api_key.clone().unwrap_or_default();
            match settings.llm_backend {
                LlmBackend::AnthropicCompat => {
                    Arc::new(HttpAnthropicCompatClient::new_with_config(
                        settings.llm_base_url.clone(),
                        api_key,
                        settings.generation_model.clone(),
                        http_config,
                        circuit_breaker_config,
                    ))
                }
                LlmBackend::OpenAICompat | LlmBackend::Ollama | LlmBackend::Vllm => Arc::new(
                    HttpMistralClient::new_with_config(
                        settings.llm_base_url.clone(),
                        api_key,
                        http_config,
                        circuit_breaker_config,
                    )
                    .with_language_model(settings.generation_model.clone()),
                ),
            }
        };

        let mistral_service = MistralService::new(
            llm_client.clone(),
            settings.generation_model.clone(),
            settings.moderation_model.clone(),
            settings.embedding_model.clone(),
        );

        let firewall_service =
            PromptFirewallService::new_with_mistral(settings.max_input_length, llm_client.clone());
        let bias_service =
            BiasDetectionService::new_with_mistral(settings.bias_threshold, llm_client.clone());

        info!("Validating configured models at startup...");
        mistral_service.validate_all_models().await.map_err(|e| {
            error!("Model validation failed: {}", e);
            Box::new(e) as Box<dyn std::error::Error>
        })?;
        info!("All configured models validated successfully");

        let semantic_service = SemanticDetectionService::new(
            mistral_service.clone(),
            settings.semantic_medium_threshold,
            settings.semantic_high_threshold,
            settings.semantic_decision_margin,
        );
        info!("Initializing semantic detection service...");
        semantic_service.initialize().await.map_err(|e| {
            error!("Semantic detection initialization failed: {}", e);
            Box::new(e) as Box<dyn std::error::Error>
        })?;
        info!("Semantic detection service initialized successfully");

        let engine = ComplianceEngine::new(
            firewall_service,
            semantic_service,
            bias_service,
            mistral_service,
            audit_logger,
        );

        Ok(PromptSentinelServer::new(settings, engine))
    }
}
