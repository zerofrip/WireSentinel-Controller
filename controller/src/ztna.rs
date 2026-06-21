use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaPolicyRecord {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub min_trust_level: String,
    pub min_trust_score: u8,
    pub conditions: Vec<serde_json::Value>,
    pub default_action: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedResourceRecord {
    pub id: String,
    pub name: String,
    pub resource_type: String,
    pub host: String,
    pub port: u16,
    pub path_prefix: Option<String>,
    pub tags: Vec<String>,
    pub published: bool,
    pub access_policy_id: Option<String>,
    pub published_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustRecord {
    pub id: String,
    pub device_id: String,
    pub trust_level: String,
    pub trust_score: u8,
    pub posture: serde_json::Value,
    pub certificate_fingerprint: Option<String>,
    pub last_evaluated_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorRecord {
    pub id: String,
    pub device_id: String,
    pub connector_id: String,
    pub name: String,
    pub endpoint: String,
    pub resource_ids: Vec<String>,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    pub last_seen_at: String,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaHeartbeatSnapshot {
    pub id: String,
    pub device_id: String,
    pub identity_connected: bool,
    pub active_provider: Option<String>,
    pub gateway_active: bool,
    pub connector_count: u32,
    pub healthy_connectors: u32,
    pub avg_trust_score: f64,
    pub published_resource_count: u32,
    pub recent_denials: u32,
    pub reported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaAnalyticsSummary {
    pub devices_reporting: i64,
    pub avg_trust_score: f64,
    pub total_connectors: i64,
    pub healthy_connectors: i64,
    pub total_denials: i64,
    pub published_resources: i64,
    pub gateway_active_devices: i64,
    pub snapshots: Vec<ZtnaHeartbeatSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaDashboardSummary {
    pub policy_count: i64,
    pub published_resource_count: i64,
    pub trusted_devices: i64,
    pub connector_count: i64,
    pub analytics: ZtnaAnalyticsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaHeartbeat {
    pub identity_connected: bool,
    pub active_provider: Option<String>,
    pub gateway_active: bool,
    pub connector_count: Option<u32>,
    pub healthy_connectors: Option<u32>,
    pub avg_trust_score: Option<f64>,
    pub published_resource_count: Option<u32>,
    pub recent_denials: Option<u32>,
    pub trust_level: Option<String>,
    pub trust_score: Option<u8>,
    pub posture: Option<serde_json::Value>,
    pub reported_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorRegistration {
    pub connector_id: String,
    pub name: String,
    pub endpoint: String,
    pub resource_ids: Vec<String>,
    pub healthy: Option<bool>,
    pub latency_ms: Option<u64>,
}

struct PolicyCache {
    policies: HashMap<String, ZtnaPolicyRecord>,
}

pub struct ZtnaManager {
    pool: DbPool,
    cache: RwLock<PolicyCache>,
}

impl ZtnaManager {
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            cache: RwLock::new(PolicyCache {
                policies: HashMap::new(),
            }),
        }
    }

    pub async fn list_policies(&self) -> Result<Vec<ZtnaPolicyRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::ZtnaPolicyRow>(
            "SELECT id, name, enabled, min_trust_level, min_trust_score, conditions_json,
                    default_action, content_json, created_at, updated_at
             FROM ztna_policies ORDER BY updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_policy).collect()
    }

    pub async fn list_resources(&self) -> Result<Vec<PublishedResourceRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::PublishedResourceRow>(
            "SELECT id, name, resource_type, host, port, path_prefix, tags_json, published,
                    access_policy_id, published_at, created_at, updated_at
             FROM published_resources ORDER BY updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_resource).collect()
    }

    pub async fn list_trust(&self) -> Result<Vec<DeviceTrustRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::DeviceTrustRow>(
            "SELECT id, device_id, trust_level, trust_score, posture_json, certificate_fingerprint,
                    last_evaluated_at, created_at, updated_at
             FROM device_trust ORDER BY last_evaluated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_trust).collect()
    }

    pub async fn list_connectors(&self) -> Result<Vec<ConnectorRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::ConnectorRow>(
            "SELECT id, device_id, connector_id, name, endpoint, resource_ids_json, healthy,
                    latency_ms, last_seen_at, registered_at, created_at, updated_at
             FROM connectors ORDER BY last_seen_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_connector).collect()
    }

    pub async fn analytics(&self) -> Result<ZtnaAnalyticsSummary, DbError> {
        let snapshots = self.list_snapshots(Some(100)).await?;
        let devices_reporting = snapshots.len() as i64;
        let avg_trust_score = if devices_reporting == 0 {
            0.0
        } else {
            snapshots.iter().map(|s| s.avg_trust_score).sum::<f64>() / devices_reporting as f64
        };
        let total_connectors: i64 = snapshots.iter().map(|s| i64::from(s.connector_count)).sum();
        let healthy_connectors: i64 =
            snapshots.iter().map(|s| i64::from(s.healthy_connectors)).sum();
        let total_denials: i64 = snapshots.iter().map(|s| i64::from(s.recent_denials)).sum();
        let gateway_active_devices = snapshots.iter().filter(|s| s.gateway_active).count() as i64;

        let published_resources: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM published_resources WHERE published = 1")
                .fetch_one(&self.pool)
                .await?;

        Ok(ZtnaAnalyticsSummary {
            devices_reporting,
            avg_trust_score,
            total_connectors,
            healthy_connectors,
            total_denials,
            published_resources: published_resources.0,
            gateway_active_devices,
            snapshots,
        })
    }

    pub async fn dashboard(&self) -> Result<ZtnaDashboardSummary, DbError> {
        let analytics = self.analytics().await?;
        let policy_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ztna_policies")
            .fetch_one(&self.pool)
            .await?;
        let trusted_devices: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM device_trust WHERE trust_score >= 50")
                .fetch_one(&self.pool)
                .await?;
        let connector_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM connectors")
            .fetch_one(&self.pool)
            .await?;

        Ok(ZtnaDashboardSummary {
            policy_count: policy_count.0,
            published_resource_count: analytics.published_resources,
            trusted_devices: trusted_devices.0,
            connector_count: connector_count.0,
            analytics,
        })
    }

    pub async fn ingest_heartbeat(
        &self,
        device_id: &str,
        hb: &ZtnaHeartbeat,
    ) -> Result<ZtnaHeartbeatSnapshot, DbError> {
        let now = now_iso();
        let reported_at = hb.reported_at.clone().unwrap_or_else(|| now.clone());
        let connector_count = hb.connector_count.unwrap_or(0);
        let healthy_connectors = hb.healthy_connectors.unwrap_or(0);
        let avg_trust_score = hb.avg_trust_score.unwrap_or(0.0);
        let published_resource_count = hb.published_resource_count.unwrap_or(0);
        let recent_denials = hb.recent_denials.unwrap_or(0);
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO ztna_heartbeats (
                id, device_id, identity_connected, active_provider, gateway_active,
                connector_count, healthy_connectors, avg_trust_score, published_resource_count,
                recent_denials, reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(hb.identity_connected)
        .bind(&hb.active_provider)
        .bind(hb.gateway_active)
        .bind(i64::from(connector_count))
        .bind(i64::from(healthy_connectors))
        .bind(avg_trust_score)
        .bind(i64::from(published_resource_count))
        .bind(i64::from(recent_denials))
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        if let (Some(trust_level), Some(trust_score)) = (&hb.trust_level, hb.trust_score) {
            let posture_json = hb
                .posture
                .as_ref()
                .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "{}".into()))
                .unwrap_or_else(|| "{}".into());
            let row_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO device_trust (
                    id, device_id, trust_level, trust_score, posture_json, certificate_fingerprint,
                    last_evaluated_at, created_at, updated_at
                 ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
                 ON CONFLICT(device_id) DO UPDATE SET
                   trust_level = excluded.trust_level,
                   trust_score = excluded.trust_score,
                   posture_json = excluded.posture_json,
                   last_evaluated_at = excluded.last_evaluated_at,
                   updated_at = excluded.updated_at",
            )
            .bind(&row_id)
            .bind(device_id)
            .bind(trust_level)
            .bind(i64::from(trust_score))
            .bind(&posture_json)
            .bind(&reported_at)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(ZtnaHeartbeatSnapshot {
            id,
            device_id: device_id.to_string(),
            identity_connected: hb.identity_connected,
            active_provider: hb.active_provider.clone(),
            gateway_active: hb.gateway_active,
            connector_count,
            healthy_connectors,
            avg_trust_score,
            published_resource_count,
            recent_denials,
            reported_at,
        })
    }

    pub async fn register_connector(
        &self,
        device_id: &str,
        reg: &ConnectorRegistration,
    ) -> Result<ConnectorRecord, DbError> {
        let now = now_iso();
        let row_id = Uuid::new_v4().to_string();
        let resource_ids_json =
            serde_json::to_string(&reg.resource_ids).unwrap_or_else(|_| "[]".into());
        let healthy = reg.healthy.unwrap_or(true);

        sqlx::query(
            "INSERT INTO connectors (
                id, device_id, connector_id, name, endpoint, resource_ids_json, healthy,
                latency_ms, last_seen_at, registered_at, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(device_id, connector_id) DO UPDATE SET
               name = excluded.name,
               endpoint = excluded.endpoint,
               resource_ids_json = excluded.resource_ids_json,
               healthy = excluded.healthy,
               latency_ms = excluded.latency_ms,
               last_seen_at = excluded.last_seen_at,
               updated_at = excluded.updated_at",
        )
        .bind(&row_id)
        .bind(device_id)
        .bind(&reg.connector_id)
        .bind(&reg.name)
        .bind(&reg.endpoint)
        .bind(&resource_ids_json)
        .bind(healthy)
        .bind(reg.latency_ms.map(|v| v as i64))
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(ConnectorRecord {
            id: row_id,
            device_id: device_id.to_string(),
            connector_id: reg.connector_id.clone(),
            name: reg.name.clone(),
            endpoint: reg.endpoint.clone(),
            resource_ids: reg.resource_ids.clone(),
            healthy,
            latency_ms: reg.latency_ms,
            last_seen_at: now.clone(),
            registered_at: now,
        })
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ztna_policies")
            .fetch_one(&self.pool)
            .await?;
        if count.0 > 0 {
            return Ok(());
        }

        let now = now_iso();
        let policy_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO ztna_policies (
                id, name, enabled, min_trust_level, min_trust_score, conditions_json,
                default_action, content_json, created_at, updated_at
             ) VALUES (?, ?, 1, 'medium', 50, '[]', 'deny', '{}', ?, ?)",
        )
        .bind(&policy_id)
        .bind("Default ZTNA Policy")
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        let resource_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO published_resources (
                id, name, resource_type, host, port, path_prefix, tags_json, published,
                access_policy_id, published_at, created_at, updated_at
             ) VALUES (?, ?, 'https', 'internal.example', 443, '/', '[]', 1, ?, ?, ?, ?)",
        )
        .bind(&resource_id)
        .bind("Example Internal App")
        .bind(&policy_id)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub fn cache_policy(&self, policy: ZtnaPolicyRecord) {
        if let Ok(mut cache) = self.cache.write() {
            cache.policies.insert(policy.id.clone(), policy);
        }
    }

    pub fn cached_policy(&self, id: &str) -> Option<ZtnaPolicyRecord> {
        self.cache
            .read()
            .ok()
            .and_then(|c| c.policies.get(id).cloned())
    }

    async fn list_snapshots(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<ZtnaHeartbeatSnapshot>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows = sqlx::query_as::<_, database::models::ZtnaHeartbeatRow>(
            "SELECT id, device_id, identity_connected, active_provider, gateway_active,
                    connector_count, healthy_connectors, avg_trust_score, published_resource_count,
                    recent_denials, reported_at
             FROM ztna_heartbeats ORDER BY reported_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| ZtnaHeartbeatSnapshot {
                id: row.id,
                device_id: row.device_id,
                identity_connected: row.identity_connected != 0,
                active_provider: row.active_provider,
                gateway_active: row.gateway_active != 0,
                connector_count: row.connector_count.max(0) as u32,
                healthy_connectors: row.healthy_connectors.max(0) as u32,
                avg_trust_score: row.avg_trust_score,
                published_resource_count: row.published_resource_count.max(0) as u32,
                recent_denials: row.recent_denials.max(0) as u32,
                reported_at: row.reported_at,
            })
            .collect())
    }
}

fn row_to_policy(row: database::models::ZtnaPolicyRow) -> Result<ZtnaPolicyRecord, DbError> {
    let conditions: Vec<serde_json::Value> =
        serde_json::from_str(&row.conditions_json).unwrap_or_default();
    Ok(ZtnaPolicyRecord {
        id: row.id,
        name: row.name,
        enabled: row.enabled != 0,
        min_trust_level: row.min_trust_level,
        min_trust_score: row.min_trust_score.clamp(0, 100) as u8,
        conditions,
        default_action: row.default_action,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_resource(row: database::models::PublishedResourceRow) -> Result<PublishedResourceRecord, DbError> {
    let tags: Vec<String> = serde_json::from_str(&row.tags_json).unwrap_or_default();
    Ok(PublishedResourceRecord {
        id: row.id,
        name: row.name,
        resource_type: row.resource_type,
        host: row.host,
        port: row.port.max(0) as u16,
        path_prefix: row.path_prefix,
        tags,
        published: row.published != 0,
        access_policy_id: row.access_policy_id,
        published_at: row.published_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_trust(row: database::models::DeviceTrustRow) -> Result<DeviceTrustRecord, DbError> {
    let posture = serde_json::from_str(&row.posture_json).unwrap_or(serde_json::json!({}));
    Ok(DeviceTrustRecord {
        id: row.id,
        device_id: row.device_id,
        trust_level: row.trust_level,
        trust_score: row.trust_score.clamp(0, 100) as u8,
        posture,
        certificate_fingerprint: row.certificate_fingerprint,
        last_evaluated_at: row.last_evaluated_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_connector(row: database::models::ConnectorRow) -> Result<ConnectorRecord, DbError> {
    let resource_ids: Vec<String> = serde_json::from_str(&row.resource_ids_json).unwrap_or_default();
    Ok(ConnectorRecord {
        id: row.id,
        device_id: row.device_id,
        connector_id: row.connector_id,
        name: row.name,
        endpoint: row.endpoint,
        resource_ids,
        healthy: row.healthy != 0,
        latency_ms: row.latency_ms.map(|v| v.max(0) as u64),
        last_seen_at: row.last_seen_at,
        registered_at: row.registered_at,
    })
}
