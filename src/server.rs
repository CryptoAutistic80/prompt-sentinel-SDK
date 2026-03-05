use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Extension, Query, State},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::settings::{
    AppSettings, DEFAULT_MISTRAL_BASE_URL, DEFAULT_MISTRAL_EMBEDDING_MODEL,
    DEFAULT_MISTRAL_GENERATION_MODEL, DEFAULT_MISTRAL_MODERATION_MODEL, LlmBackend,
};
use crate::modules::audit::logger::AuditLogger;
use crate::modules::audit::policy::{
    AuditStoragePolicyResolver, DEFAULT_AUDIT_STORAGE_POLICY_PATH,
};
use crate::modules::audit::storage::{
    AuditStorage, AuditTrailRequest, AuditTrailResponse, SledAuditStorage,
};
use crate::modules::auth::{
    AuthAdminError, AuthContext, AuthError, AuthService, GenerateCredentialCommand,
    RotateCredentialCommand, TenantScope,
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
use crate::modules::tenant_policy::{DEFAULT_TENANT_POLICY_OVERLAYS_PATH, TenantPolicyResolver};
use crate::workflow::{ComplianceEngine, ComplianceRequest, ComplianceResponse};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ComplianceEngine>,
    pub startup_complete: Arc<AtomicBool>,
    pub auth_service: Arc<AuthService>,
    pub tenant_quota_manager: Option<Arc<TenantQuotaManager>>,
}

const QUOTA_WINDOW_MILLIS: i64 = 60_000;

#[derive(Clone)]
pub struct TenantQuotaManager {
    requests_per_minute: u32,
    max_concurrent_requests: usize,
    concurrency_lease_millis: i64,
    store: Arc<dyn TenantQuotaStore>,
}

impl TenantQuotaManager {
    fn from_settings(settings: &AppSettings) -> Option<Self> {
        let requests_per_minute = settings.tenant_quota_requests_per_minute;
        let max_concurrent_requests = settings.tenant_quota_max_concurrent_requests;

        if requests_per_minute == 0 && max_concurrent_requests == 0 {
            return None;
        }

        let store = build_tenant_quota_store(settings);
        let concurrency_lease_millis =
            i64::try_from(settings.tenant_quota_concurrency_lease_secs.max(1))
                .unwrap_or(120)
                .saturating_mul(1_000);

        Some(Self {
            requests_per_minute,
            max_concurrent_requests,
            concurrency_lease_millis,
            store,
        })
    }

    fn acquire(
        self: &Arc<Self>,
        tenant_scope: &TenantScope,
    ) -> Result<TenantQuotaPermit, TenantQuotaError> {
        let tenant_id = tenant_scope
            .tenant_id
            .as_deref()
            .ok_or(TenantQuotaError::MissingTenantId)?
            .to_string();

        let lease_id = self.store.acquire(
            &tenant_id,
            self.requests_per_minute,
            self.max_concurrent_requests,
            self.concurrency_lease_millis,
        )?;

        Ok(TenantQuotaPermit {
            manager: Arc::clone(self),
            tenant_id,
            lease_id,
            released: false,
        })
    }

    fn release(&self, tenant_id: &str, lease_id: Option<&str>) {
        if let Err(error) = self.store.release(tenant_id, lease_id) {
            warn!("Failed to release tenant quota lease for `{tenant_id}`: {error:?}");
        }
    }

    #[cfg(test)]
    fn for_tests(
        requests_per_minute: u32,
        max_concurrent_requests: usize,
        concurrency_lease_millis: i64,
        store: Arc<dyn TenantQuotaStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            requests_per_minute,
            max_concurrent_requests,
            concurrency_lease_millis,
            store,
        })
    }
}

struct TenantQuotaPermit {
    manager: Arc<TenantQuotaManager>,
    tenant_id: String,
    lease_id: Option<String>,
    released: bool,
}

impl Drop for TenantQuotaPermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.manager
            .release(&self.tenant_id, self.lease_id.as_deref());
        self.released = true;
    }
}

trait TenantQuotaStore: Send + Sync {
    fn acquire(
        &self,
        tenant_id: &str,
        requests_per_minute: u32,
        max_concurrent_requests: usize,
        concurrency_lease_millis: i64,
    ) -> Result<Option<String>, TenantQuotaError>;
    fn release(&self, tenant_id: &str, lease_id: Option<&str>) -> Result<(), TenantQuotaError>;
}

#[derive(Default)]
struct InMemoryTenantQuotaStore {
    state: Mutex<HashMap<String, StoredTenantQuotaState>>,
}

impl TenantQuotaStore for InMemoryTenantQuotaStore {
    fn acquire(
        &self,
        tenant_id: &str,
        requests_per_minute: u32,
        max_concurrent_requests: usize,
        concurrency_lease_millis: i64,
    ) -> Result<Option<String>, TenantQuotaError> {
        let now_ms = Utc::now().timestamp_millis();
        let mut guard = self
            .state
            .lock()
            .map_err(|_| TenantQuotaError::BackendUnavailable {
                detail: "tenant quota in-memory lock poisoned".to_string(),
            })?;
        let state = guard.entry(tenant_id.to_string()).or_default();
        evaluate_and_apply_quota(
            state,
            now_ms,
            requests_per_minute,
            max_concurrent_requests,
            concurrency_lease_millis,
        )
    }

    fn release(&self, tenant_id: &str, lease_id: Option<&str>) -> Result<(), TenantQuotaError> {
        let now_ms = Utc::now().timestamp_millis();
        let mut guard = self
            .state
            .lock()
            .map_err(|_| TenantQuotaError::BackendUnavailable {
                detail: "tenant quota in-memory lock poisoned".to_string(),
            })?;

        let Some(state) = guard.get_mut(tenant_id) else {
            return Ok(());
        };

        release_lease(state, now_ms, lease_id);
        if state.request_times_ms.is_empty() && state.active_leases.is_empty() {
            guard.remove(tenant_id);
        }

        Ok(())
    }
}

struct SledTenantQuotaStore {
    db: sled::Db,
    lock: Mutex<()>,
}

impl SledTenantQuotaStore {
    fn new(path: &str) -> Result<Self, TenantQuotaError> {
        let db = sled::open(path).map_err(|error| TenantQuotaError::BackendUnavailable {
            detail: format!("failed to open tenant quota sled store `{path}`: {error}"),
        })?;
        Ok(Self {
            db,
            lock: Mutex::new(()),
        })
    }

    fn state_key(tenant_id: &str) -> String {
        format!("tenant_quota::{tenant_id}")
    }

    fn load_state(&self, tenant_id: &str) -> Result<StoredTenantQuotaState, TenantQuotaError> {
        let key = Self::state_key(tenant_id);
        let Some(raw) = self
            .db
            .get(key)
            .map_err(|error| TenantQuotaError::BackendUnavailable {
                detail: format!("failed to read tenant quota state: {error}"),
            })?
        else {
            return Ok(StoredTenantQuotaState::default());
        };

        serde_json::from_slice(&raw).map_err(|error| TenantQuotaError::BackendUnavailable {
            detail: format!("failed to parse tenant quota state: {error}"),
        })
    }

    fn write_state(
        &self,
        tenant_id: &str,
        state: &StoredTenantQuotaState,
    ) -> Result<(), TenantQuotaError> {
        let key = Self::state_key(tenant_id);
        if state.request_times_ms.is_empty() && state.active_leases.is_empty() {
            self.db
                .remove(key)
                .map_err(|error| TenantQuotaError::BackendUnavailable {
                    detail: format!("failed to delete tenant quota state: {error}"),
                })?;
        } else {
            let payload = serde_json::to_vec(state).map_err(|error| {
                TenantQuotaError::BackendUnavailable {
                    detail: format!("failed to serialize tenant quota state: {error}"),
                }
            })?;
            self.db
                .insert(key, payload)
                .map_err(|error| TenantQuotaError::BackendUnavailable {
                    detail: format!("failed to write tenant quota state: {error}"),
                })?;
        }

        self.db
            .flush()
            .map_err(|error| TenantQuotaError::BackendUnavailable {
                detail: format!("failed to flush tenant quota state: {error}"),
            })?;
        Ok(())
    }
}

impl TenantQuotaStore for SledTenantQuotaStore {
    fn acquire(
        &self,
        tenant_id: &str,
        requests_per_minute: u32,
        max_concurrent_requests: usize,
        concurrency_lease_millis: i64,
    ) -> Result<Option<String>, TenantQuotaError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| TenantQuotaError::BackendUnavailable {
                detail: "tenant quota sled lock poisoned".to_string(),
            })?;

        let now_ms = Utc::now().timestamp_millis();
        let mut state = self.load_state(tenant_id)?;
        let lease_id = evaluate_and_apply_quota(
            &mut state,
            now_ms,
            requests_per_minute,
            max_concurrent_requests,
            concurrency_lease_millis,
        )?;
        self.write_state(tenant_id, &state)?;
        Ok(lease_id)
    }

    fn release(&self, tenant_id: &str, lease_id: Option<&str>) -> Result<(), TenantQuotaError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| TenantQuotaError::BackendUnavailable {
                detail: "tenant quota sled lock poisoned".to_string(),
            })?;

        let now_ms = Utc::now().timestamp_millis();
        let mut state = self.load_state(tenant_id)?;
        release_lease(&mut state, now_ms, lease_id);
        self.write_state(tenant_id, &state)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredTenantQuotaState {
    request_times_ms: VecDeque<i64>,
    active_leases: HashMap<String, i64>,
}

fn build_tenant_quota_store(settings: &AppSettings) -> Arc<dyn TenantQuotaStore> {
    match settings
        .tenant_quota_backend
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "memory" => Arc::new(InMemoryTenantQuotaStore::default()),
        "sled" => {
            let quota_path = settings.tenant_quota_sled_path.trim();
            let quota_path = if quota_path.is_empty() {
                "prompt_sentinel_data/tenant_quota"
            } else {
                quota_path
            };

            match SledTenantQuotaStore::new(quota_path) {
                Ok(store) => Arc::new(store),
                Err(error) => {
                    warn!(
                        "Failed to initialize sled tenant quota backend, falling back to memory: {error:?}"
                    );
                    Arc::new(InMemoryTenantQuotaStore::default())
                }
            }
        }
        other => {
            warn!(
                "Unknown TENANT_QUOTA_BACKEND `{other}`; expected `memory` or `sled`, falling back to memory"
            );
            Arc::new(InMemoryTenantQuotaStore::default())
        }
    }
}

fn evaluate_and_apply_quota(
    state: &mut StoredTenantQuotaState,
    now_ms: i64,
    requests_per_minute: u32,
    max_concurrent_requests: usize,
    concurrency_lease_millis: i64,
) -> Result<Option<String>, TenantQuotaError> {
    prune_quota_state(state, now_ms);

    if requests_per_minute > 0 && state.request_times_ms.len() as u32 >= requests_per_minute {
        return Err(TenantQuotaError::RequestsPerMinuteExceeded {
            limit: requests_per_minute,
        });
    }

    if max_concurrent_requests > 0 && state.active_leases.len() >= max_concurrent_requests {
        return Err(TenantQuotaError::ConcurrentRequestsExceeded {
            limit: max_concurrent_requests,
        });
    }

    if requests_per_minute > 0 {
        state.request_times_ms.push_back(now_ms);
    }

    if max_concurrent_requests == 0 {
        return Ok(None);
    }

    let lease_id = format!("quota_{}", Uuid::new_v4().simple());
    state.active_leases.insert(
        lease_id.clone(),
        now_ms.saturating_add(concurrency_lease_millis.max(1)),
    );
    Ok(Some(lease_id))
}

fn release_lease(state: &mut StoredTenantQuotaState, now_ms: i64, lease_id: Option<&str>) {
    prune_quota_state(state, now_ms);
    if let Some(lease_id) = lease_id {
        state.active_leases.remove(lease_id);
    }
}

fn prune_quota_state(state: &mut StoredTenantQuotaState, now_ms: i64) {
    let window_floor = now_ms.saturating_sub(QUOTA_WINDOW_MILLIS);
    while let Some(ts) = state.request_times_ms.front() {
        if *ts <= window_floor {
            state.request_times_ms.pop_front();
        } else {
            break;
        }
    }

    state
        .active_leases
        .retain(|_, lease_expiry| *lease_expiry > now_ms);
}

#[derive(Debug)]
enum TenantQuotaError {
    MissingTenantId,
    RequestsPerMinuteExceeded { limit: u32 },
    ConcurrentRequestsExceeded { limit: usize },
    BackendUnavailable { detail: String },
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
            let quota_permit = if let Some(quota_manager) = &state.tenant_quota_manager {
                match quota_manager.acquire(&auth_context.tenant_scope) {
                    Ok(permit) => Some(permit),
                    Err(error) => {
                        let (status, code, message) = match error {
                            TenantQuotaError::MissingTenantId => (
                                StatusCode::FORBIDDEN,
                                "tenant_scope_required",
                                "tenant scope is required for quota enforcement".to_string(),
                            ),
                            TenantQuotaError::RequestsPerMinuteExceeded { limit } => (
                                StatusCode::TOO_MANY_REQUESTS,
                                "tenant_quota_exceeded",
                                format!("tenant request quota exceeded (limit_per_minute={limit})"),
                            ),
                            TenantQuotaError::ConcurrentRequestsExceeded { limit } => (
                                StatusCode::TOO_MANY_REQUESTS,
                                "tenant_concurrency_exceeded",
                                format!("tenant concurrent request quota exceeded (limit={limit})"),
                            ),
                            TenantQuotaError::BackendUnavailable { detail } => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "tenant_quota_internal",
                                format!("tenant quota enforcement is unavailable: {detail}"),
                            ),
                        };

                        get_metrics().increment_errors("tenant_quota");
                        return (
                            status,
                            Json(serde_json::json!({
                                "error": code,
                                "message": message,
                            })),
                        )
                            .into_response();
                    }
                }
            } else {
                None
            };

            request.extensions_mut().insert(auth_context);
            let response = next.run(request).await;
            drop(quota_permit);
            response
        }
        Ok(None) => next.run(request).await,
        Err(error) => {
            let (status, code) = match &error {
                AuthError::MissingCredentials
                | AuthError::InvalidCredentials
                | AuthError::ExpiredCredentials
                | AuthError::RevokedCredentials => (StatusCode::UNAUTHORIZED, "unauthorized"),
                AuthError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden"),
                AuthError::InvalidTenantScope { .. } => {
                    (StatusCode::FORBIDDEN, "tenant_scope_invalid")
                }
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
        let auth_service = Arc::new(
            AuthService::from_settings(&config).with_audit_logger(engine.audit_logger().clone()),
        );
        let tenant_quota_manager = TenantQuotaManager::from_settings(&config).map(Arc::new);
        Self {
            config,
            state: AppState {
                engine: Arc::new(engine),
                startup_complete: Arc::new(AtomicBool::new(true)),
                auth_service,
                tenant_quota_manager,
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
    auth_context: Option<Extension<AuthContext>>,
    Json(mut request): Json<AuditTrailRequest>,
) -> Result<Json<AuditTrailResponse>, (StatusCode, String)> {
    debug!("Received audit trail request");

    if let Some(Extension(context)) = auth_context
        && let Err(detail) = enforce_audit_query_scope(&mut request, &context)
    {
        get_metrics().increment_errors("audit_scope");
        return Err((StatusCode::FORBIDDEN, detail));
    }

    let audit_logger = state.engine.audit_logger();
    let storage = audit_logger.storage();

    match storage.get_with_filters(request) {
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

fn enforce_audit_query_scope(
    request: &mut AuditTrailRequest,
    auth_context: &AuthContext,
) -> Result<(), String> {
    let context_tenant = auth_context.tenant_scope.tenant_id.as_deref();
    let context_workspace = auth_context.tenant_scope.workspace_id.as_deref();

    if let Some(context_tenant) = context_tenant {
        if let Some(request_tenant) = request.tenant_id.as_deref()
            && request_tenant != context_tenant
        {
            return Err("audit query tenant scope does not match authenticated tenant".to_string());
        }
        request.tenant_id = Some(context_tenant.to_string());

        if let Some(context_workspace) = context_workspace {
            if let Some(request_workspace) = request.workspace_id.as_deref()
                && request_workspace != context_workspace
            {
                return Err(
                    "audit query workspace scope does not match authenticated workspace"
                        .to_string(),
                );
            }
            request.workspace_id = Some(context_workspace.to_string());
        }
    }

    Ok(())
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
    auth_context: Option<Extension<AuthContext>>,
    Json(mut request): Json<ComplianceRequest>,
) -> Result<Json<ComplianceResponse>, (StatusCode, String)> {
    if let Some(Extension(context)) = auth_context {
        request.tenant_id = context.tenant_scope.tenant_id;
        request.workspace_id = context.tenant_scope.workspace_id;
    }

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
            mtls_enabled: false,
            mtls_verified_header: "x-client-cert-verified".to_string(),
            mtls_verified_value: "SUCCESS".to_string(),
            mtls_subject_header: "x-client-cert-subject".to_string(),
            mtls_fingerprint_header: "x-client-cert-fingerprint".to_string(),
            mtls_allowed_subjects: vec![],
            mtls_allowed_fingerprints: vec![],
            mtls_role: "service_account".to_string(),
            mtls_scopes: vec![],
            tenant_isolation_enabled: false,
            tenant_id_header: "x-tenant-id".to_string(),
            workspace_id_header: "x-workspace-id".to_string(),
            tenant_require_workspace: false,
            tenant_quota_requests_per_minute: 0,
            tenant_quota_max_concurrent_requests: 0,
            tenant_quota_backend: "memory".to_string(),
            tenant_quota_sled_path: "prompt_sentinel_data/tenant_quota".to_string(),
            tenant_quota_concurrency_lease_secs: 120,
            tenant_policy_overlays_path: "config/tenant_policy_overlays.json".to_string(),
            tenant_policy_overlays_strict: false,
            audit_storage_policy_path: "config/audit_storage_policies.json".to_string(),
            audit_storage_policy_strict: false,
            oidc_enabled: false,
            oidc_provider: "generic".to_string(),
            oidc_issuer_url: None,
            oidc_audience: None,
            oidc_client_id: None,
            oidc_roles_claim: "auto".to_string(),
            oidc_scopes_claim: "auto".to_string(),
            oidc_jwks_url: None,
            oidc_jwks_refresh_interval_secs: 300,
            oidc_clock_skew_secs: 60,
            oidc_allow_insecure_jwt_parse: false,
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

        let tenant_policy_overlay_path = if settings.tenant_policy_overlays_path.trim().is_empty() {
            DEFAULT_TENANT_POLICY_OVERLAYS_PATH
        } else {
            settings.tenant_policy_overlays_path.as_str()
        };

        let tenant_policy_resolver = match TenantPolicyResolver::from_file(
            tenant_policy_overlay_path,
        ) {
            Ok(resolver) => {
                if resolver.is_empty() {
                    info!("No tenant policy overlays loaded from `{tenant_policy_overlay_path}`");
                } else {
                    info!(
                        "Loaded {} tenant policy overlays from `{tenant_policy_overlay_path}`",
                        resolver.len()
                    );
                }
                resolver
            }
            Err(error) => {
                if settings.tenant_policy_overlays_strict {
                    error!("Failed to load tenant policy overlays: {error}");
                    return Err(Box::new(error));
                }

                warn!(
                    "Failed to load tenant policy overlays from `{tenant_policy_overlay_path}`; \
                         continuing without overlays: {error}"
                );
                TenantPolicyResolver::default()
            }
        };

        let audit_storage_policy_path = if settings.audit_storage_policy_path.trim().is_empty() {
            DEFAULT_AUDIT_STORAGE_POLICY_PATH
        } else {
            settings.audit_storage_policy_path.as_str()
        };

        let audit_storage_policy_resolver = match AuditStoragePolicyResolver::from_file(
            audit_storage_policy_path,
        ) {
            Ok(resolver) => {
                if resolver.is_empty() {
                    info!(
                        "No audit storage policy overlays loaded from `{audit_storage_policy_path}`"
                    );
                } else {
                    info!(
                        "Loaded {} tenant audit storage policies from `{audit_storage_policy_path}`",
                        resolver.len()
                    );
                }
                resolver
            }
            Err(error) => {
                if settings.audit_storage_policy_strict {
                    error!("Failed to load audit storage policy file: {error}");
                    return Err(Box::new(error));
                }

                warn!(
                    "Failed to load audit storage policy file from `{audit_storage_policy_path}`; \
                         continuing without policy metadata: {error}"
                );
                AuditStoragePolicyResolver::default()
            }
        };

        let audit_storage: Arc<dyn AuditStorage> =
            Arc::new(SledAuditStorage::new(&self.sled_db_path)?);
        let audit_logger = AuditLogger::new(audit_storage)
            .with_storage_policy_resolver(audit_storage_policy_resolver);

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
        )
        .with_tenant_policy_resolver(tenant_policy_resolver);

        Ok(PromptSentinelServer::new(settings, engine))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn tenant_quota_enforces_requests_per_minute() {
        let manager = TenantQuotaManager::for_tests(
            2,
            0,
            120_000,
            Arc::new(InMemoryTenantQuotaStore::default()),
        );
        let scope = TenantScope {
            tenant_id: Some("tenant-a".to_string()),
            workspace_id: None,
        };

        let _permit_1 = manager.acquire(&scope).expect("first request");
        let _permit_2 = manager.acquire(&scope).expect("second request");

        assert!(matches!(
            manager.acquire(&scope),
            Err(TenantQuotaError::RequestsPerMinuteExceeded { limit: 2 })
        ));
    }

    #[test]
    fn tenant_quota_enforces_concurrency_limits() {
        let manager = TenantQuotaManager::for_tests(
            0,
            1,
            120_000,
            Arc::new(InMemoryTenantQuotaStore::default()),
        );
        let scope = TenantScope {
            tenant_id: Some("tenant-a".to_string()),
            workspace_id: None,
        };

        let permit = manager.acquire(&scope).expect("first request");
        assert!(matches!(
            manager.acquire(&scope),
            Err(TenantQuotaError::ConcurrentRequestsExceeded { limit: 1 })
        ));

        drop(permit);
        assert!(manager.acquire(&scope).is_ok());
    }

    #[test]
    fn tenant_quota_requires_tenant_scope() {
        let manager = TenantQuotaManager::for_tests(
            10,
            10,
            120_000,
            Arc::new(InMemoryTenantQuotaStore::default()),
        );
        let scope = TenantScope {
            tenant_id: None,
            workspace_id: None,
        };

        assert!(matches!(
            manager.acquire(&scope),
            Err(TenantQuotaError::MissingTenantId)
        ));
    }

    #[test]
    fn tenant_quota_recovers_after_lease_expiry_without_release() {
        let manager =
            TenantQuotaManager::for_tests(0, 1, 10, Arc::new(InMemoryTenantQuotaStore::default()));
        let scope = TenantScope {
            tenant_id: Some("tenant-expiry".to_string()),
            workspace_id: None,
        };

        let leaked_permit = manager.acquire(&scope).expect("first request");
        std::mem::forget(leaked_permit);
        sleep(Duration::from_millis(20));

        assert!(manager.acquire(&scope).is_ok());
    }

    #[test]
    fn tenant_quota_sled_backend_persists_rate_window() {
        let db_path = std::env::temp_dir().join(format!(
            "prompt_sentinel_tenant_quota_{}",
            Uuid::new_v4().simple()
        ));
        let db_path_str = db_path.to_string_lossy().to_string();

        let manager = TenantQuotaManager::for_tests(
            1,
            0,
            120_000,
            Arc::new(SledTenantQuotaStore::new(&db_path_str).expect("quota store")),
        );
        let scope = TenantScope {
            tenant_id: Some("tenant-persist".to_string()),
            workspace_id: None,
        };
        let permit = manager.acquire(&scope).expect("first request");
        drop(permit);
        drop(manager);

        let manager_reloaded = TenantQuotaManager::for_tests(
            1,
            0,
            120_000,
            Arc::new(SledTenantQuotaStore::new(&db_path_str).expect("quota store reload")),
        );

        assert!(matches!(
            manager_reloaded.acquire(&scope),
            Err(TenantQuotaError::RequestsPerMinuteExceeded { limit: 1 })
        ));

        let _ = std::fs::remove_dir_all(db_path);
    }
}
