# Auth Scope Mismatch Runbook

This runbook covers production response for authorization failures caused by tenant/workspace or resource-scope mismatches across:

- API credentials
- OIDC bearer tokens
- mTLS service principals

## Incident Types

Use this taxonomy when triaging alerts:

- `credential_tenant_scope_mismatch`: Bound API key tenant/workspace differs from request headers.
- `oidc_tenant_scope_mismatch`: OIDC tenant claim differs from request tenant header.
- `oidc_resource_scope_mismatch`: OIDC explicit scopes do not allow requested project/environment.
- `mtls_resource_scope_mismatch`: mTLS principal scopes do not allow requested project/environment.
- `principal_not_allowlisted`: mTLS subject/fingerprint no longer matches allowlist.

## Detection

Primary detection source: auth access events.

### 1. Pull Recent Auth Denials

```bash
curl -sS -X GET "http://localhost:3000/api/auth/access-log?limit=500" \
  -H "x-api-key: <admin-token>" \
  -H "x-tenant-id: <admin-tenant>" \
  -H "x-workspace-id: <admin-workspace>"
```

Key denial outcomes/details to filter:

- `deny_tenant_scope_mismatch`
- `deny_forbidden` with scope candidate details
- `deny_oidc_verification_failed`
- `deny_mtls_subject_not_allowed`
- `deny_mtls_fingerprint_not_allowed`

### 2. Correlate With Audit Trail

Use `correlation_id` from access events to inspect end-to-end request context:

```bash
curl -sS -X POST "http://localhost:3000/api/audit/trail" \
  -H "content-type: application/json" \
  -H "x-api-key: <admin-token>" \
  -H "x-tenant-id: <admin-tenant>" \
  -H "x-workspace-id: <admin-workspace>" \
  -d '{"limit":100,"offset":0,"correlation_id":"<corr-id>"}'
```

## Severity and Escalation

- `SEV-1`: Multi-tenant outage or widespread auth failures on production critical paths.
- `SEV-2`: Single-tenant production impact with degraded operations.
- `SEV-3`: Non-production impact or isolated principal misconfiguration.

Escalate to security/compliance owner for any tenant isolation bypass suspicion.

## Triage Checklist

For each impacted principal:

1. Identify auth mechanism (`api_key`, `oidc`, `mtls`) from access event detail.
2. Identify scope context:
   - tenant/workspace headers
   - project/environment headers
   - required permission candidate
3. Determine root cause:
   - credential binding mismatch
   - missing/incorrect principal scopes
   - claim mapping drift (`OIDC_*_CLAIM`)
   - mTLS allowlist drift (subject/fingerprint)
4. Count impacted tenants/workspaces and request volume.

## Containment

Prefer narrow containment over global auth relaxations:

1. Rotate or revoke the offending credential/principal.
2. If temporary access is required, issue a short-lived replacement credential with exact scope binding.
3. Avoid disabling tenant isolation or enabling insecure JWT parsing in production.

## Recovery Playbooks

### API Credential Mismatch

1. Generate migration evidence:

```bash
curl -sS -X GET "http://localhost:3000/api/auth/keys/migration-plan?observation_limit=5" \
  -H "x-api-key: <admin-token>" \
  -H "x-tenant-id: <admin-tenant>" \
  -H "x-workspace-id: <admin-workspace>"
```

2. Rotate credential with explicit binding:

```bash
curl -sS -X POST "http://localhost:3000/api/auth/keys/rotate" \
  -H "content-type: application/json" \
  -H "x-api-key: <admin-token>" \
  -H "x-tenant-id: <admin-tenant>" \
  -H "x-workspace-id: <admin-workspace>" \
  -d '{
    "old_token":"<old-token>",
    "new_token":"<new-token>",
    "role":"developer",
    "scopes":["check:invoke","audit:read"],
    "tenant_id":"tenant-a",
    "workspace_id":"workspace-prod"
  }'
```

### OIDC Scope Mismatch

1. Validate token claims (`tenant_id`, `scope`, `roles`) from issuer.
2. Validate claim mapping configuration:
   - `OIDC_ROLES_CLAIM`
   - `OIDC_SCOPES_CLAIM`
   - `OIDC_PROVIDER`
3. Correct provider mapping or token-scopes policy, then redeploy.

### mTLS Scope or Allowlist Mismatch

1. Validate certificate subject/fingerprint from ingress.
2. Compare against:
   - `MTLS_ALLOWED_SUBJECTS`
   - `MTLS_ALLOWED_FINGERPRINTS`
   - `MTLS_SCOPES`
3. Update allowlist/scope configuration and redeploy with canary rollout.

## Staged Rollback Controls

If a config rollout causes elevated denials:

1. Rollback recent auth config change in canary first.
2. Re-check denial rate and tenant impact.
3. Rollback global rollout only if denial thresholds remain above SLO.

Recommended trigger thresholds:

- >5% auth denial increase for 5 minutes on critical routes.
- Any cross-tenant access anomaly indicating isolation risk.

## Tenant Impact Triage

For each affected tenant/workspace:

1. Start time and end time of impact window.
2. Affected endpoints and operation type (`check`, `audit`, `auth admin`).
3. Total denied requests and peak denial rate.
4. Confirmed data isolation status (no cross-tenant data exposure).

## Post-Incident Actions

1. Capture root cause and misconfiguration class.
2. Add regression tests for the exact mismatch pattern.
3. Update credential bindings and auth policy baselines.
4. Track follow-up actions with due dates and owners.
