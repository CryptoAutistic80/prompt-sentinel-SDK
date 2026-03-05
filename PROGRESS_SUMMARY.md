# Progress Summary

Date: 2026-03-05
Repo: `prompt-sentinel`
Roadmap Source: `Compliance-SDK-Plan-Forward-v3.md`
Execution Mode: Phase-by-phase production hardening

## Current Stage Outcome

This stage advanced **Phase 2 resource-level authorization scaffolding** by introducing project/environment-aware permission matching with backward-compatible global scope fallback.

### Completed to date in this phase

- Added credential lifecycle operations in auth service:
  - generate credential tokens
  - revoke credentials by `key_id`
  - expire credentials by `key_id`
- Added key expiry + revocation enforcement in request authorization.
- Added default key TTL support for generated credentials (`AUTH_DEFAULT_KEY_EXPIRY_SECS`).
- Added persistent file-backed auth credential storage (`AUTH_KEY_STORE_PATH`) so key lifecycle changes survive restarts.
- Added pluggable OIDC verifier abstraction:
  - provider enum (`generic`, `auth0`, `okta`, `azure_ad`, `keycloak`)
  - verifier trait + principal model for bearer-token auth
  - OIDC verifier builder wired from environment settings
- Added OIDC bearer auth path in middleware-aligned auth flow while preserving API-key compatibility.
- Added production-mode JWT validation against JWKS signing keys (RS256/RS384/RS512) with strict key-id based lookup.
- Added in-memory JWKS cache with refresh interval support and key rotation handling.
- Added OIDC bootstrap settings:
  - `OIDC_ENABLED`
  - `OIDC_PROVIDER`
  - `OIDC_ISSUER_URL`
  - `OIDC_AUDIENCE`
  - `OIDC_CLIENT_ID`
  - `OIDC_ROLES_CLAIM`
  - `OIDC_SCOPES_CLAIM`
  - `OIDC_JWKS_URL`
  - `OIDC_JWKS_REFRESH_INTERVAL_SECS`
  - `OIDC_CLOCK_SKEW_SECS`
  - `OIDC_ALLOW_INSECURE_JWT_PARSE` (dev-only guardrail)
- Added credential metadata state fields:
  - `expires_at`
  - `revoked_at`
  - `active`
- Extended auth admin APIs:
  - `POST /api/auth/keys/generate`
  - `POST /api/auth/keys/revoke`
  - `POST /api/auth/keys/expire`
  - existing `POST /api/auth/keys/rotate` now also accepts `expires_in_seconds`
- Updated server auth error handling for revoked/expired tokens.
- Added auth unit tests for:
  - expiry and revoke enforcement
  - generated key persistence round-trip
  - default expiry behavior
- Added OIDC-focused tests:
  - JWT claims verifier behavior
  - auth service bearer-token authorization via pluggable verifier
- Added durable auth access-event persistence:
  - each allow/deny auth decision is now mirrored from `AuthService` into `AuditLogger`
  - auth events are written as typed audit payloads (`event_type=auth_access`) for filtering/querying
  - request `x-correlation-id` is now captured and propagated into auth audit events
  - fallback correlation IDs are generated for auth events when the request has no correlation header
- Wired server startup to inject the workflow audit logger into `AuthService` so protected endpoint auth events are durable by default.
- Added auth unit test coverage proving auth access events are persisted into audit storage with expected payload shape.
- Updated docs/examples (`README.md`, `.env.example`) for lifecycle endpoints and new env vars.
- Added resource-level permission scaffold:
  - optional request headers `x-project-id` and `x-environment` are normalized into auth resource scope
  - permission evaluation now checks resource-aware candidates first (project+env, project-only, env-only) then global scope fallback
  - both API key and OIDC bearer auth paths now include resource scope in `AuthContext`
  - added tests for matching scope allow, mismatched scope deny, and global fallback behavior
- Updated README with resource-scoped scope formats and header usage.

## Phase Status Dashboard

| Phase | Status | Notes |
|---|---|---|
| Phase 0 - Foundation Hardening | In Progress | Core security/reliability foundations implemented; OTel/Sentry/chaos/contract testing remain. |
| Phase 1 - Provider-Agnostic LLM Support | In Progress | Provider abstraction + backend switching implemented; routing/fallback/cost optimization pending. |
| Phase 2 - Enterprise Auth & Multi-Tenancy | In Progress | API key auth + RBAC + service accounts + rate limiting + key lifecycle + persistence + OIDC JWT/JWKS validation + durable auth access auditing + resource-level permission scaffold implemented; provider-specific onboarding/mTLS/multi-tenant isolation pending. |
| Phase 3 - Comprehensive EU AI Act Coverage | In Progress | Baseline classification exists; full article-by-article depth pending. |
| Phase 4 - Audit Trail & Evidence Management | In Progress | Existing audit trail and proofs active; v2 schema + advanced exports/retention lifecycle pending. |
| Phase 5 - Configuration & Rules Management | In Progress | Env-driven config active; hot reload/staged rollout/rollback/policy-as-code pending. |
| Phase 6 - SDK & Developer Experience | Not Started | Multi-language SDK release workflows pending. |
| Phase 7 - SaaS Platform & Management Console | Not Started | Cloud infra, billing, and management console pending. |
| Phase 8 - Agentic AI Governance | Not Started | Agent workflow governance and MCP controls pending. |
| Phase 9 - Certification & Standards Alignment | Not Started | ISO/SOC2/GDPR certification execution pending. |
| Phase 10 - Ecosystem & Partnerships | Not Started | Ecosystem and partner programs pending. |

## Detailed Mapping: Roadmap Checklist Progress

### Phase 0

- Completed:
  - CORS allowlist lockdown.
  - Security headers middleware.
  - Health probes (`live`, `ready`, `startup`).
  - Graceful shutdown.
  - Connection pooling + timeout controls.
  - Circuit breaker for upstream LLM calls.
  - TLS termination guide.
  - `cargo audit` GitHub Actions workflow.
- Remaining:
  - Secret managers (Vault/AWS/K8s).
  - `cargo-fuzz` harness.
  - OpenTelemetry + tracing exporters.
  - Sentry integration.
  - SLI/SLO dashboard assets.
  - Chaos and contract test infrastructure.

### Phase 1

- Completed:
  - `LLMProvider` trait.
  - OpenAI-compatible backend support.
  - Anthropic-compatible backend support.
  - Config-driven provider switching via env.
- Remaining:
  - Capability router and fallback chains.
  - Cost-aware and region-aware routing.
  - Model pinning policy enforcement.
  - Dedicated Ollama/vLLM local ops workflows.

### Phase 2

- Completed:
  - API key authentication.
  - Service account token support.
  - RBAC route permission checks.
  - Per-key scopes.
  - Per-key rate limiting.
  - Runtime credential generation/rotation/revoke/expire workflows.
  - Credential expiry + revoke enforcement at auth middleware boundary.
  - Persistent file-backed auth key store.
  - OIDC provider abstraction + bearer-token auth integration.
  - JWT signature verification via JWKS with refreshable key cache.
  - Auth access log retrieval.
  - Durable auth access-event persistence into tamper-evident audit storage.
  - Resource-level permission scaffold (project/environment-aware permission candidates + global fallback).
- Remaining:
  - Provider-specific setup flows (Auth0/Okta/Azure AD/Keycloak).
  - mTLS auth support.
  - Full multi-tenant isolation and quotas.

## Validation

Commands run for this stage:

- `cargo fmt` -> pass
- `cargo check` -> pass
- `cargo test` -> pass (all suites green; benchmark test intentionally ignored)

## Files Changed This Stage

- `src/modules/auth/mod.rs`
- `README.md`
- `PROGRESS_SUMMARY.md`

## Next Execution Slice

1. Add provider-specific OIDC onboarding profiles (Auth0/Okta/Azure AD/Keycloak) with tested claim mappings.
2. Add mTLS auth support for service-to-service deployments.
3. Start multi-tenant isolation baseline (tenant/workspace identifiers + quota hooks).
