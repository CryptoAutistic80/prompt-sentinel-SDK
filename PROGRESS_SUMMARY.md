# Progress Summary

Date: 2026-03-05
Repo: `prompt-sentinel`
Roadmap Source: `Compliance-SDK-Plan-Forward-v3.md`
Execution Mode: Phase-by-phase production hardening

## Current Stage Outcome

This stage advanced **Phase 2 runtime fail-closed residency enforcement** by adding deployment-region guardrails that block non-compliant tenant traffic and by tightening audit query policy pinning for region/storage-policy filters.

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
- Added provider-specific OIDC claim mapping profiles:
  - `auth0`: maps scopes from `scope` / `permissions` (including namespaced `*/permissions`) and roles from `roles` / namespaced `*/roles`
  - `okta`: maps scopes from `scp` / `scope` and roles from `groups` / `roles`
  - `azure_ad`: maps scopes from `scp` / `scope` and roles from `roles` / `groups`
  - `keycloak`: maps roles from `realm_access.roles` and `resource_access.{client_id}.roles`, plus `scope` / `scp`
  - `generic`: keeps broad defaults (`scope`/`scp`, `roles`/`groups`)
- Added support for claim selector lists and `auto` profiles (`OIDC_ROLES_CLAIM`, `OIDC_SCOPES_CLAIM`).
- Added OIDC unit tests that verify provider-specific claim mappings for Auth0, Okta, Azure AD, and Keycloak.
- Updated configuration/docs to default OIDC claim selectors to `auto` (`src/config/settings.rs`, `.env.example`, `README.md`).
- Added mTLS auth path for requests without API key/bearer credentials:
  - validates reverse-proxy injected certificate verification header (`MTLS_VERIFIED_HEADER` / `MTLS_VERIFIED_VALUE`)
  - supports allowlisting by client certificate subject and/or SHA-256 fingerprint
  - maps accepted mTLS callers to auth context (`role`, `scopes`) with existing RBAC/resource-scope checks
  - emits explicit auth access outcomes for mTLS allow/deny reasons in audit-access logging
- Added mTLS configuration surface (`MTLS_*`) in settings, `.env.example`, and README.
- Added auth unit tests for mTLS:
  - successful allowlisted subject authorization
  - deny for unlisted subject
  - scope-constrained mTLS principal forbidden path
- Added tenant/workspace scope model to auth context:
  - `TenantScope` carried in `AuthContext`
  - configurable tenant/workspace header names
  - optional strict enforcement when `TENANT_ISOLATION_ENABLED=true`
- Added OIDC tenant-scope reconciliation:
  - validates OIDC tenant claim format
  - denies claim/header tenant mismatches
- Added tenant quota hooks in auth middleware:
  - per-tenant requests/minute (`TENANT_QUOTA_REQUESTS_PER_MINUTE`)
  - per-tenant concurrent in-flight requests (`TENANT_QUOTA_MAX_CONCURRENT_REQUESTS`)
  - explicit tenant quota error responses for protected routes
- Added pluggable tenant quota backend support:
  - `TENANT_QUOTA_BACKEND=memory|sled`
  - `TENANT_QUOTA_SLED_PATH` for durable quota state
  - automatic fallback to in-memory backend if sled init fails
- Added lease-based concurrency tracking for tenant quotas:
  - `TENANT_QUOTA_CONCURRENCY_LEASE_SECS` controls lease TTL
  - stale in-flight slots self-recover after lease expiry (crash-safe behavior)
- Extended compliance workflow request/audit schema:
  - `ComplianceRequest` now carries optional `tenant_id` + `workspace_id`
  - workflow audit events include `tenant_id` + `workspace_id`
  - auth access audit events include `tenant_id` + `workspace_id`
- Added tenant-focused unit tests:
  - auth tenant scope required path
  - auth tenant scope propagation path
  - OIDC tenant mismatch denial
  - tenant quota request + concurrency + missing-scope enforcement
- Added tenant quota backend tests:
  - lease expiry recovery when permits are not released
  - sled-backed rate-window persistence across manager restarts
- Updated docs/examples (`README.md`, `.env.example`) with `TENANT_*` configuration and behavior notes.
- Added tenant/workspace policy overlay subsystem:
  - JSON policy file loader + resolver (`config/tenant_policy_overlays.json`)
  - tenant-level base policy with optional workspace-level overrides
  - normalization/deduplication for patterns and keyword packs
- Added overlay-driven workflow enforcement:
  - tenant firewall overrides (`max_input_length`, additional block patterns)
  - tenant bias threshold overrides
  - tenant EU risk keyword overlays (unacceptable/high/limited additive packs)
  - tenant LLM preferences for generation/moderation model selection and `safe_prompt`
- Added startup controls for overlay config:
  - `TENANT_POLICY_OVERLAYS_PATH`
  - `TENANT_POLICY_OVERLAYS_STRICT`
  - strict mode fails startup on invalid overlay config; non-strict mode fails open to baseline behavior
- Added unit coverage for:
  - tenant policy resolver merge/normalization paths
  - firewall tenant overrides
  - EU keyword overlay risk-tier escalation paths
- Extended audit storage schema with tenant/workspace + residency metadata:
  - `tenant_id`
  - `workspace_id`
  - `data_region`
  - `storage_policy`
  - `retention_days`
- Added audit storage policy resolver:
  - policy file loader for `config/audit_storage_policies.json`
  - default + tenant + workspace override resolution
  - metadata fields for residency evidence and retention policy lineage
- Added audit policy startup controls:
  - `AUDIT_STORAGE_POLICY_PATH`
  - `AUDIT_STORAGE_POLICY_STRICT`
  - strict mode fails startup on invalid policy file
- Extended `AuditTrailRequest` + backend filtering with:
  - `tenant_id`
  - `workspace_id`
  - `data_region`
  - `storage_policy`
- Enforced tenant/workspace audit query scope in the API layer:
  - authenticated tenant-scoped callers are pinned to their own tenant/workspace filters
  - cross-tenant/workspace filter mismatches are denied
- Added audit-focused unit tests:
  - audit storage policy resolver behavior (default, tenant, workspace overrides)
  - in-memory audit filtering by tenant/workspace/region/policy and time window
- Added runtime residency guardrails in the server request path:
  - `RESIDENCY_ENFORCEMENT_ENABLED`
  - `DEPLOYMENT_REGION`
  - fail-closed behavior for compliance requests when tenant-required region differs from deployment region
- Extended audit query scope enforcement:
  - residency policy resolver now pins `data_region` and `storage_policy` filters
  - conflicting region/storage-policy query filters are denied
- Added residency-focused server tests:
  - allow path for matching deployment/tenant region
  - deny path for mismatched deployment/tenant region
  - audit query filter pinning and conflict-denial paths
- Updated docs/examples (`README.md`, `.env.example`) for runtime residency guard configuration.

## Phase Status Dashboard

| Phase | Status | Notes |
|---|---|---|
| Phase 0 - Foundation Hardening | In Progress | Core security/reliability foundations implemented; OTel/Sentry/chaos/contract testing remain. |
| Phase 1 - Provider-Agnostic LLM Support | In Progress | Provider abstraction + backend switching implemented; routing/fallback/cost optimization pending. |
| Phase 2 - Enterprise Auth & Multi-Tenancy | In Progress | API key auth + RBAC + service accounts + rate limiting + key lifecycle + persistence + OIDC JWT/JWKS validation + provider-specific onboarding profiles + mTLS auth + durable auth access auditing + resource-level permission scaffold + tenant/workspace isolation baseline + first-pass tenant quota hooks + pluggable durable tenant quota backend (`memory`/`sled`) + tenant/workspace policy overlays + audit query isolation filters + audit residency metadata + runtime fail-closed residency checks implemented; penetration-test harness pending. |
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
  - Provider-specific OIDC onboarding profiles with tested claim mappings (Auth0/Okta/Azure AD/Keycloak).
  - mTLS service-to-service authentication support (proxy-terminated header validation with subject/fingerprint allowlists).
  - Auth access log retrieval.
  - Durable auth access-event persistence into tamper-evident audit storage.
  - Resource-level permission scaffold (project/environment-aware permission candidates + global fallback).
  - Tenant/workspace scope extraction + enforcement in auth context.
  - OIDC tenant-claim/header mismatch guardrails.
  - First-pass tenant quota hooks (per-tenant request/minute and concurrent in-flight limits).
  - Pluggable tenant quota backend (`memory`/`sled`) with durable sled state.
  - Lease-based tenant concurrency counters with stale-slot recovery window.
  - Tenant/workspace identifiers in workflow audit events and auth access audit events.
  - Tenant/workspace configuration overlays (firewall limits/patterns, bias threshold, EU keyword packs, LLM generation/moderation preferences + safe prompt).
  - Audit trail filter controls for tenant/workspace/region/storage policy.
  - Tenant/workspace scope enforcement on audit-trail queries.
  - Audit storage policy overlays with residency + retention metadata evidence on persisted records.
  - Runtime fail-closed residency guardrails for compliance processing and audit query filter pinning.
- Remaining:
  - Tenant/workspace penetration-test harness and adversarial isolation validation.

## Validation

Commands run for this stage:

- `rustfmt --edition 2024 src/server.rs src/config/settings.rs src/modules/auth/mod.rs tests/multilingual_response_test.rs` -> pass
- `cargo check` -> pass
- `cargo test residency_guard -- --nocapture` -> pass
- `cargo test` -> pass (all suites green; benchmark test intentionally ignored)

## Files Changed This Stage

- `src/server.rs`
- `src/config/settings.rs`
- `src/modules/auth/mod.rs`
- `tests/multilingual_response_test.rs`
- `.env.example`
- `README.md`
- `PROGRESS_SUMMARY.md`

## Next Execution Slice

1. Build tenant/workspace penetration-test harnesses for cross-tenant and cross-region access attempts.
2. Add adversarial isolation regression suites (token replay, header spoofing, mixed-scope audit traversal).
3. Extend residency tests to include end-to-end API-level denial assertions under auth middleware.
