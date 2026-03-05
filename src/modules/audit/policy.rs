use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_AUDIT_STORAGE_POLICY_PATH: &str = "config/audit_storage_policies.json";

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditStoragePolicy {
    pub data_region: Option<String>,
    pub storage_policy: Option<String>,
    pub retention_days: Option<u32>,
}

impl AuditStoragePolicy {
    fn merge(&self, other: &Self) -> Self {
        Self {
            data_region: other
                .data_region
                .clone()
                .or_else(|| self.data_region.clone()),
            storage_policy: other
                .storage_policy
                .clone()
                .or_else(|| self.storage_policy.clone()),
            retention_days: other.retention_days.or(self.retention_days),
        }
    }

    fn normalize(mut self) -> Self {
        self.data_region = normalize_optional_string(self.data_region);
        self.storage_policy = normalize_optional_string(self.storage_policy);
        self.retention_days = self.retention_days.filter(|value| *value > 0);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.data_region.is_none() && self.storage_policy.is_none() && self.retention_days.is_none()
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuditStoragePolicyResolver {
    default_policy: AuditStoragePolicy,
    tenants: HashMap<String, TenantAuditStoragePolicyConfig>,
}

impl AuditStoragePolicyResolver {
    pub fn from_file(path: &str) -> Result<Self, AuditStoragePolicyError> {
        let trimmed_path = path.trim();
        if trimmed_path.is_empty() {
            return Ok(Self::default());
        }

        let file_path = Path::new(trimmed_path);
        if !file_path.exists() {
            return Ok(Self::default());
        }

        let content =
            fs::read_to_string(file_path).map_err(|source| AuditStoragePolicyError::Read {
                path: trimmed_path.to_string(),
                source,
            })?;
        let parsed: AuditStoragePolicyFile =
            serde_json::from_str(&content).map_err(|source| AuditStoragePolicyError::Parse {
                path: trimmed_path.to_string(),
                source,
            })?;

        Ok(Self {
            default_policy: parsed.default.normalize(),
            tenants: normalize_tenant_map(parsed.tenants),
        })
    }

    pub fn resolve(
        &self,
        tenant_id: Option<&str>,
        workspace_id: Option<&str>,
    ) -> AuditStoragePolicy {
        let mut resolved = self.default_policy.clone();

        if let Some(tenant_key) = normalized_lookup_key(tenant_id)
            && let Some(tenant_policy) = self.tenants.get(&tenant_key)
        {
            resolved = resolved.merge(&tenant_policy.policy);

            if let Some(workspace_key) = normalized_lookup_key(workspace_id)
                && let Some(workspace_policy) = tenant_policy.workspaces.get(&workspace_key)
            {
                resolved = resolved.merge(workspace_policy);
            }
        }

        resolved.normalize()
    }

    pub fn len(&self) -> usize {
        self.tenants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.default_policy.is_empty() && self.tenants.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AuditStoragePolicyFile {
    #[serde(default)]
    default: AuditStoragePolicy,
    #[serde(default)]
    tenants: HashMap<String, RawTenantAuditStoragePolicyConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct RawTenantAuditStoragePolicyConfig {
    #[serde(default)]
    data_region: Option<String>,
    #[serde(default)]
    storage_policy: Option<String>,
    #[serde(default)]
    retention_days: Option<u32>,
    #[serde(default)]
    workspaces: HashMap<String, AuditStoragePolicy>,
}

#[derive(Clone, Debug, Default)]
struct TenantAuditStoragePolicyConfig {
    policy: AuditStoragePolicy,
    workspaces: HashMap<String, AuditStoragePolicy>,
}

fn normalize_tenant_map(
    raw: HashMap<String, RawTenantAuditStoragePolicyConfig>,
) -> HashMap<String, TenantAuditStoragePolicyConfig> {
    raw.into_iter()
        .filter_map(|(tenant_key, tenant_policy)| {
            let tenant_key = normalized_key(tenant_key)?;

            let workspaces = tenant_policy
                .workspaces
                .into_iter()
                .filter_map(|(workspace_key, policy)| {
                    let workspace_key = normalized_key(workspace_key)?;
                    Some((workspace_key, policy.normalize()))
                })
                .collect::<HashMap<_, _>>();

            let policy = AuditStoragePolicy {
                data_region: tenant_policy.data_region,
                storage_policy: tenant_policy.storage_policy,
                retention_days: tenant_policy.retention_days,
            }
            .normalize();

            Some((
                tenant_key,
                TenantAuditStoragePolicyConfig { policy, workspaces },
            ))
        })
        .collect()
}

fn normalized_lookup_key(raw: Option<&str>) -> Option<String> {
    let value = raw?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalized_key(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[derive(Debug, Error)]
pub enum AuditStoragePolicyError {
    #[error("failed to read audit storage policy file `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse audit storage policy file `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_resolver() -> AuditStoragePolicyResolver {
        AuditStoragePolicyResolver {
            default_policy: AuditStoragePolicy {
                data_region: Some("global".to_string()),
                storage_policy: Some("standard".to_string()),
                retention_days: Some(365),
            },
            tenants: HashMap::from([(
                "tenant-a".to_string(),
                TenantAuditStoragePolicyConfig {
                    policy: AuditStoragePolicy {
                        data_region: Some("eu-west-1".to_string()),
                        storage_policy: Some("eu_restricted".to_string()),
                        retention_days: Some(730),
                    },
                    workspaces: HashMap::from([(
                        "workspace-prod".to_string(),
                        AuditStoragePolicy {
                            data_region: Some("eu-central-1".to_string()),
                            storage_policy: None,
                            retention_days: Some(1095),
                        },
                    )]),
                },
            )]),
        }
    }

    #[test]
    fn resolves_default_policy_when_tenant_missing() {
        let resolver = policy_resolver();
        let policy = resolver.resolve(None, None);

        assert_eq!(policy.data_region.as_deref(), Some("global"));
        assert_eq!(policy.storage_policy.as_deref(), Some("standard"));
        assert_eq!(policy.retention_days, Some(365));
    }

    #[test]
    fn resolves_tenant_policy() {
        let resolver = policy_resolver();
        let policy = resolver.resolve(Some("tenant-a"), None);

        assert_eq!(policy.data_region.as_deref(), Some("eu-west-1"));
        assert_eq!(policy.storage_policy.as_deref(), Some("eu_restricted"));
        assert_eq!(policy.retention_days, Some(730));
    }

    #[test]
    fn resolves_workspace_policy_as_override() {
        let resolver = policy_resolver();
        let policy = resolver.resolve(Some("tenant-a"), Some("workspace-prod"));

        assert_eq!(policy.data_region.as_deref(), Some("eu-central-1"));
        assert_eq!(policy.storage_policy.as_deref(), Some("eu_restricted"));
        assert_eq!(policy.retention_days, Some(1095));
    }
}
