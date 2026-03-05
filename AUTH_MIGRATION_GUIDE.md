# Auth Credential Migration Guide

This guide covers safe migration of legacy unbound credentials to tenant/workspace-bound credentials.

## Goal

Move from credentials that can be reused across tenant headers to credentials pinned to one tenant/workspace identity.

## Prerequisites

- `AUTH_ENABLED=true`
- Admin credential with `auth:read` + `auth:write`
- Tenant isolation enabled in production (`TENANT_ISOLATION_ENABLED=true`)

## 1. Collect Scope Evidence

Allow normal workload traffic to run so auth access events contain recent tenant/workspace usage.

## 2. Generate Migration Plan

Call:

```bash
curl -sS -X GET "http://localhost:3000/api/auth/keys/migration-plan?observation_limit=5" \
  -H "x-api-key: <admin-token>" \
  -H "x-tenant-id: <admin-tenant>" \
  -H "x-workspace-id: <admin-workspace>"
```

Interpret response:

- `plan.unbound_credentials`: how many keys still require migration.
- `suggestions[*].requires_migration`: whether key is unbound.
- `suggestions[*].recommended_tenant_id` and `recommended_workspace_id`: suggested binding when confidence is high.
- `recommendation_reason`:
  - `single_observed_scope`: safe default candidate.
  - `ambiguous_observations`: key used across multiple scopes; requires manual split.
  - `insufficient_observations`: not enough evidence; stage traffic or assign manually.

## 3. Rotate to Bound Credentials

For each unbound key with approved target scope:

```bash
curl -sS -X POST "http://localhost:3000/api/auth/keys/rotate" \
  -H "content-type: application/json" \
  -H "x-api-key: <admin-token>" \
  -H "x-tenant-id: <admin-tenant>" \
  -H "x-workspace-id: <admin-workspace>" \
  -d '{
    "old_token": "<old-token>",
    "new_token": "<new-bound-token>",
    "role": "developer",
    "scopes": ["check:invoke", "audit:read"],
    "tenant_id": "tenant-a",
    "workspace_id": "workspace-prod"
  }'
```

If one legacy key serves multiple scopes, split into separate keys (one key per tenant/workspace).

## 4. Validate Post-Rotation

- Verify old token fails authorization.
- Verify new token succeeds only on bound tenant/workspace.
- Re-run migration plan and confirm reduced `unbound_credentials`.

## 5. Production Gate

Before release:

- Require `plan.unbound_credentials == 0` for production clusters, or track approved exceptions with expiry dates.
- Treat new unbound credentials as release blockers unless explicitly approved.
