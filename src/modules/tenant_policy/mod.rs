use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_TENANT_POLICY_OVERLAYS_PATH: &str = "config/tenant_policy_overlays.json";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolvedTenantPolicy {
    pub firewall: TenantFirewallPolicy,
    pub bias: TenantBiasPolicy,
    pub eu_keywords: TenantEuKeywordPolicy,
    pub llm_preferences: TenantLlmPreferencePolicy,
}

impl ResolvedTenantPolicy {
    pub fn is_empty(&self) -> bool {
        self.firewall.is_empty()
            && self.bias.is_empty()
            && self.eu_keywords.is_empty()
            && self.llm_preferences.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TenantPolicyResolver {
    overlays: HashMap<String, TenantOverlayConfig>,
}

impl TenantPolicyResolver {
    pub fn from_file(path: &str) -> Result<Self, TenantPolicyError> {
        let trimmed_path = path.trim();
        if trimmed_path.is_empty() {
            return Ok(Self::default());
        }

        let file_path = Path::new(trimmed_path);
        if !file_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(file_path).map_err(|source| TenantPolicyError::Read {
            path: trimmed_path.to_string(),
            source,
        })?;
        let parsed: TenantPolicyFileConfig =
            serde_json::from_str(&content).map_err(|source| TenantPolicyError::Parse {
                path: trimmed_path.to_string(),
                source,
            })?;

        Ok(Self {
            overlays: normalize_tenant_map(parsed.tenants),
        })
    }

    pub fn resolve(
        &self,
        tenant_id: Option<&str>,
        workspace_id: Option<&str>,
    ) -> Option<ResolvedTenantPolicy> {
        let tenant_id = normalized_lookup_key(tenant_id)?;
        let tenant_overlay = self.overlays.get(&tenant_id)?;

        let mut resolved = tenant_overlay.base.clone();
        if let Some(workspace_key) = normalized_lookup_key(workspace_id)
            && let Some(workspace_overlay) = tenant_overlay.workspaces.get(&workspace_key)
        {
            resolved = resolved.merge(workspace_overlay);
        }

        let resolved = resolved.normalize();
        if resolved.is_empty() {
            None
        } else {
            Some(ResolvedTenantPolicy {
                firewall: resolved.firewall,
                bias: resolved.bias,
                eu_keywords: resolved.eu_keywords,
                llm_preferences: resolved.llm_preferences,
            })
        }
    }

    pub fn len(&self) -> usize {
        self.overlays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.overlays.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct TenantPolicyFileConfig {
    #[serde(default)]
    tenants: HashMap<String, RawTenantOverlayConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct RawTenantOverlayConfig {
    #[serde(default)]
    firewall: TenantFirewallPolicy,
    #[serde(default)]
    bias: TenantBiasPolicy,
    #[serde(default)]
    eu_keywords: TenantEuKeywordPolicy,
    #[serde(default)]
    llm_preferences: TenantLlmPreferencePolicy,
    #[serde(default)]
    workspaces: HashMap<String, TenantPolicyOverlaySlice>,
}

#[derive(Clone, Debug, Default)]
struct TenantOverlayConfig {
    base: TenantPolicyOverlaySlice,
    workspaces: HashMap<String, TenantPolicyOverlaySlice>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct TenantPolicyOverlaySlice {
    #[serde(default)]
    firewall: TenantFirewallPolicy,
    #[serde(default)]
    bias: TenantBiasPolicy,
    #[serde(default)]
    eu_keywords: TenantEuKeywordPolicy,
    #[serde(default)]
    llm_preferences: TenantLlmPreferencePolicy,
}

impl TenantPolicyOverlaySlice {
    fn merge(&self, other: &Self) -> Self {
        Self {
            firewall: self.firewall.merge(&other.firewall),
            bias: self.bias.merge(&other.bias),
            eu_keywords: self.eu_keywords.merge(&other.eu_keywords),
            llm_preferences: self.llm_preferences.merge(&other.llm_preferences),
        }
    }

    fn normalize(mut self) -> Self {
        self.firewall = self.firewall.normalize();
        self.bias = self.bias.normalize();
        self.eu_keywords = self.eu_keywords.normalize();
        self.llm_preferences = self.llm_preferences.normalize();
        self
    }

    fn is_empty(&self) -> bool {
        self.firewall.is_empty()
            && self.bias.is_empty()
            && self.eu_keywords.is_empty()
            && self.llm_preferences.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct TenantFirewallPolicy {
    pub max_input_length: Option<usize>,
    #[serde(default)]
    pub additional_block_patterns: Vec<String>,
}

impl TenantFirewallPolicy {
    fn merge(&self, other: &Self) -> Self {
        let mut merged_patterns = self.additional_block_patterns.clone();
        append_unique_trimmed(&mut merged_patterns, &other.additional_block_patterns);

        Self {
            max_input_length: other.max_input_length.or(self.max_input_length),
            additional_block_patterns: merged_patterns,
        }
    }

    fn normalize(mut self) -> Self {
        self.max_input_length = self.max_input_length.filter(|value| *value > 0);
        self.additional_block_patterns = normalized_unique(self.additional_block_patterns);
        self
    }

    fn is_empty(&self) -> bool {
        self.max_input_length.is_none() && self.additional_block_patterns.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct TenantBiasPolicy {
    pub threshold: Option<f32>,
}

impl TenantBiasPolicy {
    fn merge(&self, other: &Self) -> Self {
        Self {
            threshold: other.threshold.or(self.threshold),
        }
    }

    fn normalize(mut self) -> Self {
        self.threshold = self
            .threshold
            .filter(|value| value.is_finite())
            .map(|value| value.clamp(0.0, 1.0));
        self
    }

    fn is_empty(&self) -> bool {
        self.threshold.is_none()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct TenantEuKeywordPolicy {
    #[serde(default)]
    pub additional_unacceptable_keywords: Vec<String>,
    #[serde(default)]
    pub additional_high_keywords: Vec<String>,
    #[serde(default)]
    pub additional_limited_keywords: Vec<String>,
}

impl TenantEuKeywordPolicy {
    fn merge(&self, other: &Self) -> Self {
        let mut unacceptable = self.additional_unacceptable_keywords.clone();
        append_unique_trimmed(&mut unacceptable, &other.additional_unacceptable_keywords);

        let mut high = self.additional_high_keywords.clone();
        append_unique_trimmed(&mut high, &other.additional_high_keywords);

        let mut limited = self.additional_limited_keywords.clone();
        append_unique_trimmed(&mut limited, &other.additional_limited_keywords);

        Self {
            additional_unacceptable_keywords: unacceptable,
            additional_high_keywords: high,
            additional_limited_keywords: limited,
        }
    }

    fn normalize(mut self) -> Self {
        self.additional_unacceptable_keywords =
            normalized_unique(self.additional_unacceptable_keywords);
        self.additional_high_keywords = normalized_unique(self.additional_high_keywords);
        self.additional_limited_keywords = normalized_unique(self.additional_limited_keywords);
        self
    }

    fn is_empty(&self) -> bool {
        self.additional_unacceptable_keywords.is_empty()
            && self.additional_high_keywords.is_empty()
            && self.additional_limited_keywords.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct TenantLlmPreferencePolicy {
    pub provider_label: Option<String>,
    pub generation_model: Option<String>,
    pub moderation_model: Option<String>,
    pub safe_prompt: Option<bool>,
}

impl TenantLlmPreferencePolicy {
    fn merge(&self, other: &Self) -> Self {
        Self {
            provider_label: other
                .provider_label
                .clone()
                .or_else(|| self.provider_label.clone()),
            generation_model: other
                .generation_model
                .clone()
                .or_else(|| self.generation_model.clone()),
            moderation_model: other
                .moderation_model
                .clone()
                .or_else(|| self.moderation_model.clone()),
            safe_prompt: other.safe_prompt.or(self.safe_prompt),
        }
    }

    fn normalize(mut self) -> Self {
        self.provider_label = normalized_optional_string(self.provider_label);
        self.generation_model = normalized_optional_string(self.generation_model);
        self.moderation_model = normalized_optional_string(self.moderation_model);
        self
    }

    fn is_empty(&self) -> bool {
        self.provider_label.is_none()
            && self.generation_model.is_none()
            && self.moderation_model.is_none()
            && self.safe_prompt.is_none()
    }
}

fn normalize_tenant_map(
    raw: HashMap<String, RawTenantOverlayConfig>,
) -> HashMap<String, TenantOverlayConfig> {
    raw.into_iter()
        .filter_map(|(tenant_key, raw_overlay)| {
            let normalized_tenant_key = normalized_key(tenant_key)?;

            let base = TenantPolicyOverlaySlice {
                firewall: raw_overlay.firewall,
                bias: raw_overlay.bias,
                eu_keywords: raw_overlay.eu_keywords,
                llm_preferences: raw_overlay.llm_preferences,
            };

            let workspaces = raw_overlay
                .workspaces
                .into_iter()
                .filter_map(|(workspace_key, workspace_overlay)| {
                    let workspace_key = normalized_key(workspace_key)?;
                    Some((workspace_key, workspace_overlay))
                })
                .collect::<HashMap<_, _>>();

            Some((
                normalized_tenant_key,
                TenantOverlayConfig { base, workspaces },
            ))
        })
        .collect()
}

fn normalized_key(raw: String) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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

fn normalized_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn append_unique_trimmed(values: &mut Vec<String>, incoming: &[String]) {
    let mut seen = values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<HashSet<_>>();

    for value in incoming {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }

        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            values.push(trimmed.to_string());
        }
    }
}

fn normalized_unique(values: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    append_unique_trimmed(&mut normalized, &values);
    normalized
}

#[derive(Debug, Error)]
pub enum TenantPolicyError {
    #[error("failed to read tenant policy overlay file `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse tenant policy overlay file `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver_with_overlay() -> TenantPolicyResolver {
        let mut tenants = HashMap::new();
        tenants.insert(
            "tenant-a".to_string(),
            RawTenantOverlayConfig {
                firewall: TenantFirewallPolicy {
                    max_input_length: Some(4096),
                    additional_block_patterns: vec!["classified information".to_string()],
                },
                bias: TenantBiasPolicy {
                    threshold: Some(0.40),
                },
                eu_keywords: TenantEuKeywordPolicy {
                    additional_unacceptable_keywords: vec!["live biometric tracking".to_string()],
                    additional_high_keywords: vec!["loan underwriting".to_string()],
                    additional_limited_keywords: vec!["hr chatbot".to_string()],
                },
                llm_preferences: TenantLlmPreferencePolicy {
                    provider_label: Some("tenant-openai".to_string()),
                    generation_model: Some("mistral-large-latest".to_string()),
                    moderation_model: None,
                    safe_prompt: Some(true),
                },
                workspaces: HashMap::from([(
                    "workspace-prod".to_string(),
                    TenantPolicyOverlaySlice {
                        firewall: TenantFirewallPolicy {
                            max_input_length: Some(2048),
                            additional_block_patterns: vec![
                                "customer social scoring".to_string(),
                                "classified information".to_string(),
                            ],
                        },
                        bias: TenantBiasPolicy {
                            threshold: Some(0.25),
                        },
                        eu_keywords: TenantEuKeywordPolicy {
                            additional_unacceptable_keywords: vec![
                                "emotion recognition in exams".to_string(),
                            ],
                            additional_high_keywords: vec!["medical triage automation".to_string()],
                            additional_limited_keywords: vec!["citizen support bot".to_string()],
                        },
                        llm_preferences: TenantLlmPreferencePolicy {
                            provider_label: None,
                            generation_model: None,
                            moderation_model: Some("mistral-moderation-latest".to_string()),
                            safe_prompt: Some(false),
                        },
                    },
                )]),
            },
        );

        TenantPolicyResolver {
            overlays: normalize_tenant_map(tenants),
        }
    }

    #[test]
    fn resolves_tenant_and_workspace_overlays() {
        let resolver = resolver_with_overlay();
        let policy = resolver
            .resolve(Some("tenant-a"), Some("workspace-prod"))
            .expect("tenant policy");

        assert_eq!(policy.firewall.max_input_length, Some(2048));
        assert_eq!(
            policy.firewall.additional_block_patterns,
            vec![
                "classified information".to_string(),
                "customer social scoring".to_string(),
            ]
        );
        assert_eq!(policy.bias.threshold, Some(0.25));
        assert_eq!(
            policy.eu_keywords.additional_unacceptable_keywords,
            vec![
                "live biometric tracking".to_string(),
                "emotion recognition in exams".to_string(),
            ]
        );
        assert_eq!(
            policy.eu_keywords.additional_high_keywords,
            vec![
                "loan underwriting".to_string(),
                "medical triage automation".to_string(),
            ]
        );
        assert_eq!(
            policy.eu_keywords.additional_limited_keywords,
            vec!["hr chatbot".to_string(), "citizen support bot".to_string(),]
        );
        assert_eq!(
            policy.llm_preferences.provider_label.as_deref(),
            Some("tenant-openai")
        );
        assert_eq!(
            policy.llm_preferences.generation_model.as_deref(),
            Some("mistral-large-latest")
        );
        assert_eq!(
            policy.llm_preferences.moderation_model.as_deref(),
            Some("mistral-moderation-latest")
        );
        assert_eq!(policy.llm_preferences.safe_prompt, Some(false));
    }

    #[test]
    fn resolves_tenant_overlay_without_workspace() {
        let resolver = resolver_with_overlay();
        let policy = resolver
            .resolve(Some("tenant-a"), Some("workspace-dev"))
            .expect("tenant policy");

        assert_eq!(policy.firewall.max_input_length, Some(4096));
        assert_eq!(
            policy.firewall.additional_block_patterns,
            vec!["classified information".to_string()]
        );
        assert_eq!(policy.bias.threshold, Some(0.40));
        assert_eq!(
            policy.llm_preferences.provider_label.as_deref(),
            Some("tenant-openai")
        );
        assert_eq!(policy.llm_preferences.safe_prompt, Some(true));
    }

    #[test]
    fn returns_none_for_missing_tenant() {
        let resolver = resolver_with_overlay();
        assert!(resolver.resolve(None, None).is_none());
        assert!(resolver.resolve(Some("unknown"), None).is_none());
    }

    #[test]
    fn normalizes_invalid_values() {
        let mut tenants = HashMap::new();
        tenants.insert(
            " tenant-b ".to_string(),
            RawTenantOverlayConfig {
                firewall: TenantFirewallPolicy {
                    max_input_length: Some(0),
                    additional_block_patterns: vec!["   ".to_string(), "  leak ".to_string()],
                },
                bias: TenantBiasPolicy {
                    threshold: Some(2.0),
                },
                eu_keywords: TenantEuKeywordPolicy {
                    additional_unacceptable_keywords: vec![
                        "".to_string(),
                        "  social scoring ".to_string(),
                    ],
                    additional_high_keywords: vec![],
                    additional_limited_keywords: vec![],
                },
                llm_preferences: TenantLlmPreferencePolicy {
                    provider_label: Some("   ".to_string()),
                    generation_model: Some(" mistral-small-latest ".to_string()),
                    moderation_model: Some("".to_string()),
                    safe_prompt: None,
                },
                workspaces: HashMap::new(),
            },
        );

        let resolver = TenantPolicyResolver {
            overlays: normalize_tenant_map(tenants),
        };
        let policy = resolver
            .resolve(Some("tenant-b"), None)
            .expect("tenant policy");

        assert_eq!(policy.firewall.max_input_length, None);
        assert_eq!(
            policy.firewall.additional_block_patterns,
            vec!["leak".to_string()]
        );
        assert_eq!(policy.bias.threshold, Some(1.0));
        assert_eq!(
            policy.eu_keywords.additional_unacceptable_keywords,
            vec!["social scoring".to_string()]
        );
        assert_eq!(policy.llm_preferences.provider_label, None);
        assert_eq!(
            policy.llm_preferences.generation_model.as_deref(),
            Some("mistral-small-latest")
        );
        assert_eq!(policy.llm_preferences.moderation_model, None);
    }
}
