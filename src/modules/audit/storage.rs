use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sled::Db;
use thiserror::Error;

use super::proof::AuditProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailRequest {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub correlation_id: Option<String>,
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub data_region: Option<String>,
    pub storage_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailResponse {
    pub records: Vec<StoredAuditRecord>,
    pub total_count: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredAuditRecord {
    pub correlation_id: String,
    pub timestamp: DateTime<Utc>,
    pub payload: String,
    pub proof: AuditProof,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub data_region: Option<String>,
    #[serde(default)]
    pub storage_policy: Option<String>,
    #[serde(default)]
    pub retention_days: Option<u32>,
}

pub trait AuditStorage: Send + Sync {
    fn append(&self, record: StoredAuditRecord) -> Result<(), AuditStorageError>;
    fn latest_chain_hash(&self) -> Result<Option<String>, AuditStorageError>;
    fn all(&self) -> Result<Vec<StoredAuditRecord>, AuditStorageError>;
    fn get_with_filters(
        &self,
        request: AuditTrailRequest,
    ) -> Result<AuditTrailResponse, AuditStorageError>;
}

#[derive(Clone, Default)]
pub struct InMemoryAuditStorage {
    inner: Arc<Mutex<Vec<StoredAuditRecord>>>,
}

impl InMemoryAuditStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditStorage for InMemoryAuditStorage {
    fn append(&self, record: StoredAuditRecord) -> Result<(), AuditStorageError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| AuditStorageError::LockPoisoned)?;
        guard.push(record);
        Ok(())
    }

    fn latest_chain_hash(&self) -> Result<Option<String>, AuditStorageError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| AuditStorageError::LockPoisoned)?;
        Ok(guard.last().map(|entry| entry.proof.chain_hash.clone()))
    }

    fn all(&self) -> Result<Vec<StoredAuditRecord>, AuditStorageError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| AuditStorageError::LockPoisoned)?;
        Ok(guard.clone())
    }

    fn get_with_filters(
        &self,
        request: AuditTrailRequest,
    ) -> Result<AuditTrailResponse, AuditStorageError> {
        let all_records = self.all()?;
        let filtered_records = filter_records(all_records, &request);

        let limit = request.limit.unwrap_or(100);
        let offset = request.offset.unwrap_or(0);
        let total_count = filtered_records.len();
        let paginated_records: Vec<StoredAuditRecord> = filtered_records
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        Ok(AuditTrailResponse {
            records: paginated_records,
            total_count,
            limit,
            offset,
        })
    }
}

#[derive(Debug, Error)]
pub enum AuditStorageError {
    #[error("audit storage lock poisoned")]
    LockPoisoned,
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
}

#[derive(Clone)]
pub struct SledAuditStorage {
    db: Db,
}

impl SledAuditStorage {
    pub fn new(db_path: &str) -> Result<Self, AuditStorageError> {
        let db =
            sled::open(db_path).map_err(|e| AuditStorageError::DatabaseError(e.to_string()))?;
        Ok(Self { db })
    }
}

impl AuditStorage for SledAuditStorage {
    fn append(&self, record: StoredAuditRecord) -> Result<(), AuditStorageError> {
        let serialized = serde_json::to_string(&record)
            .map_err(|e| AuditStorageError::SerializationError(e.to_string()))?;

        // Use timestamp-prefixed key for chronological ordering
        // Format: {timestamp_nanos}_{correlation_id}
        let key = format!(
            "{:020}_{}",
            record.timestamp.timestamp_nanos_opt().unwrap_or(0),
            record.correlation_id
        );
        self.db
            .insert(key, serialized.as_bytes())
            .map_err(|e| AuditStorageError::DatabaseError(e.to_string()))?;

        self.db
            .flush()
            .map_err(|e| AuditStorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn latest_chain_hash(&self) -> Result<Option<String>, AuditStorageError> {
        // Iterate in reverse to get the chronologically latest record
        let last_record = self
            .db
            .iter()
            .next_back()
            .transpose()
            .map_err(|e| AuditStorageError::DatabaseError(e.to_string()))?;

        match last_record {
            Some((_, data)) => {
                let record: StoredAuditRecord = serde_json::from_slice(&data)
                    .map_err(|e| AuditStorageError::SerializationError(e.to_string()))?;
                Ok(Some(record.proof.chain_hash))
            }
            None => Ok(None),
        }
    }

    fn all(&self) -> Result<Vec<StoredAuditRecord>, AuditStorageError> {
        let mut records = Vec::new();

        for result in self.db.iter() {
            let (_, data) = result.map_err(|e| AuditStorageError::DatabaseError(e.to_string()))?;
            let record: StoredAuditRecord = serde_json::from_slice(&data)
                .map_err(|e| AuditStorageError::SerializationError(e.to_string()))?;
            records.push(record);
        }

        Ok(records)
    }

    fn get_with_filters(
        &self,
        request: AuditTrailRequest,
    ) -> Result<AuditTrailResponse, AuditStorageError> {
        let all_records = self.all()?;
        let filtered_records = filter_records(all_records, &request);

        let limit = request.limit.unwrap_or(100);
        let offset = request.offset.unwrap_or(0);
        let total_count = filtered_records.len();
        let paginated_records: Vec<StoredAuditRecord> = filtered_records
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        Ok(AuditTrailResponse {
            records: paginated_records,
            total_count,
            limit,
            offset,
        })
    }
}

fn filter_records(
    all_records: Vec<StoredAuditRecord>,
    request: &AuditTrailRequest,
) -> Vec<StoredAuditRecord> {
    let correlation_filter = normalized_filter(request.correlation_id.clone());
    let tenant_filter = normalized_filter(request.tenant_id.clone());
    let workspace_filter = normalized_filter(request.workspace_id.clone());
    let region_filter = normalized_filter(request.data_region.clone());
    let storage_policy_filter = normalized_filter(request.storage_policy.clone());

    all_records
        .into_iter()
        .filter(|record| {
            let in_time_range = request
                .start_time
                .as_ref()
                .map(|start| record.timestamp >= *start)
                .unwrap_or(true)
                && request
                    .end_time
                    .as_ref()
                    .map(|end| record.timestamp <= *end)
                    .unwrap_or(true);

            let matches_correlation = correlation_filter
                .as_ref()
                .map(|cid| record.correlation_id == *cid)
                .unwrap_or(true);
            let matches_tenant = tenant_filter
                .as_ref()
                .map(|tenant| record.tenant_id.as_deref() == Some(tenant.as_str()))
                .unwrap_or(true);
            let matches_workspace = workspace_filter
                .as_ref()
                .map(|workspace| record.workspace_id.as_deref() == Some(workspace.as_str()))
                .unwrap_or(true);
            let matches_region = region_filter
                .as_ref()
                .map(|region| record.data_region.as_deref() == Some(region.as_str()))
                .unwrap_or(true);
            let matches_storage_policy = storage_policy_filter
                .as_ref()
                .map(|policy| record.storage_policy.as_deref() == Some(policy.as_str()))
                .unwrap_or(true);

            in_time_range
                && matches_correlation
                && matches_tenant
                && matches_workspace
                && matches_region
                && matches_storage_policy
        })
        .collect()
}

fn normalized_filter(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn dummy_record(
        correlation_id: &str,
        tenant_id: Option<&str>,
        workspace_id: Option<&str>,
        data_region: Option<&str>,
        storage_policy: Option<&str>,
        timestamp: DateTime<Utc>,
    ) -> StoredAuditRecord {
        StoredAuditRecord {
            correlation_id: correlation_id.to_string(),
            timestamp,
            payload: "{}".to_string(),
            proof: AuditProof {
                algorithm: "sha256".to_string(),
                record_hash: "hash".to_string(),
                chain_hash: "chain".to_string(),
            },
            tenant_id: tenant_id.map(ToOwned::to_owned),
            workspace_id: workspace_id.map(ToOwned::to_owned),
            data_region: data_region.map(ToOwned::to_owned),
            storage_policy: storage_policy.map(ToOwned::to_owned),
            retention_days: Some(365),
        }
    }

    #[test]
    fn in_memory_filters_by_tenant_workspace_and_region() {
        let storage = InMemoryAuditStorage::new();
        let now = Utc::now();

        storage
            .append(dummy_record(
                "corr-1",
                Some("tenant-a"),
                Some("ws-a"),
                Some("eu-west-1"),
                Some("eu_restricted"),
                now,
            ))
            .expect("append");
        storage
            .append(dummy_record(
                "corr-2",
                Some("tenant-b"),
                Some("ws-b"),
                Some("us-east-1"),
                Some("standard"),
                now + Duration::seconds(1),
            ))
            .expect("append");

        let response = storage
            .get_with_filters(AuditTrailRequest {
                limit: Some(10),
                offset: Some(0),
                start_time: None,
                end_time: None,
                correlation_id: None,
                tenant_id: Some("tenant-a".to_string()),
                workspace_id: Some("ws-a".to_string()),
                data_region: Some("eu-west-1".to_string()),
                storage_policy: Some("eu_restricted".to_string()),
            })
            .expect("filtered response");

        assert_eq!(response.total_count, 1);
        assert_eq!(response.records[0].correlation_id, "corr-1");
    }

    #[test]
    fn in_memory_filters_by_time_window() {
        let storage = InMemoryAuditStorage::new();
        let now = Utc::now();

        storage
            .append(dummy_record(
                "corr-old",
                Some("tenant-a"),
                None,
                Some("eu-west-1"),
                Some("standard"),
                now - Duration::minutes(10),
            ))
            .expect("append");
        storage
            .append(dummy_record(
                "corr-new",
                Some("tenant-a"),
                None,
                Some("eu-west-1"),
                Some("standard"),
                now,
            ))
            .expect("append");

        let response = storage
            .get_with_filters(AuditTrailRequest {
                limit: Some(10),
                offset: Some(0),
                start_time: Some(now - Duration::minutes(1)),
                end_time: Some(now + Duration::minutes(1)),
                correlation_id: None,
                tenant_id: Some("tenant-a".to_string()),
                workspace_id: None,
                data_region: None,
                storage_policy: None,
            })
            .expect("filtered response");

        assert_eq!(response.total_count, 1);
        assert_eq!(response.records[0].correlation_id, "corr-new");
    }
}
