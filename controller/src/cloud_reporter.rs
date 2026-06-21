use database::{models::now_iso, DbError, DbPool};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudUsageIngest {
    pub tenant_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    pub metric: String,
    pub quantity: f64,
    #[serde(default)]
    pub window_start: Option<String>,
    #[serde(default)]
    pub window_end: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudHealthIngest {
    pub tenant_id: String,
    pub healthy: bool,
    #[serde(default)]
    pub reporting_devices: u32,
    #[serde(default)]
    pub healthy_devices: u32,
    #[serde(default)]
    pub kernel_devices: u32,
    #[serde(default)]
    pub anonymity_score: Option<f64>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub captured_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudLogEntryIngest {
    pub level: String,
    pub message: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub fields: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudLogsIngest {
    pub tenant_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    pub entries: Vec<CloudLogEntryIngest>,
    #[serde(default)]
    pub ingested_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CloudReporterPushSummary {
    pub usage_forwarded: usize,
    pub health_forwarded: usize,
    pub logs_forwarded: usize,
}

struct FederationOutbound {
    tenant_id: String,
    cloud_base_url: String,
    cloud_controller_id: String,
    federation_token: String,
}

pub struct CloudReporter {
    pool: DbPool,
    http: Client,
}

impl CloudReporter {
    pub fn new(pool: DbPool) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { pool, http }
    }

    pub async fn ingest_usage(
        &self,
        device_id: Option<&str>,
        payload: CloudUsageIngest,
    ) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        sqlx::query(
            "INSERT INTO cloud_usage_ingress (id, tenant_id, device_id, payload_json, received_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&payload.tenant_id)
        .bind(device_id)
        .bind(&payload_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn ingest_health(&self, payload: CloudHealthIngest) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        sqlx::query(
            "INSERT INTO cloud_health_ingress (id, tenant_id, payload_json, received_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&payload.tenant_id)
        .bind(&payload_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn ingest_logs(
        &self,
        device_id: Option<&str>,
        payload: CloudLogsIngest,
    ) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        sqlx::query(
            "INSERT INTO cloud_logs_ingress (id, tenant_id, device_id, payload_json, received_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&payload.tenant_id)
        .bind(device_id)
        .bind(&payload_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn federation_outbound(&self) -> Result<Option<FederationOutbound>, DbError> {
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT tenant_id, cloud_base_url, cloud_controller_id, outbound_federation_token
             FROM federated_registration ORDER BY registered_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(
            |(tenant_id, cloud_base_url, cloud_controller_id, token)| {
                let federation_token = token?;
                if federation_token.is_empty() || cloud_base_url.is_empty() {
                    return None;
                }
                Some(FederationOutbound {
                    tenant_id,
                    cloud_base_url: cloud_base_url.trim_end_matches('/').to_string(),
                    cloud_controller_id,
                    federation_token,
                })
            },
        ))
    }

    pub async fn push_pending_to_cloud(&self) -> Result<CloudReporterPushSummary, DbError> {
        let Some(fed) = self.federation_outbound().await? else {
            return Ok(CloudReporterPushSummary::default());
        };

        let mut summary = CloudReporterPushSummary::default();
        summary.usage_forwarded = self.forward_usage_batch(&fed).await?;
        summary.health_forwarded = self.forward_health_batch(&fed).await?;
        summary.logs_forwarded = self.forward_logs_batch(&fed).await?;
        Ok(summary)
    }

    async fn forward_usage_batch(&self, fed: &FederationOutbound) -> Result<usize, DbError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, payload_json FROM cloud_usage_ingress WHERE forwarded_at IS NULL ORDER BY received_at ASC LIMIT 50",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut forwarded = 0usize;
        for (id, payload_json) in rows {
            let body: serde_json::Value =
                serde_json::from_str(&payload_json).unwrap_or(serde_json::json!({}));
            let url = format!("{}/api/v1/cloud/usage", fed.cloud_base_url);
            if self.post_cloud(&url, &fed.federation_token, &body).await {
                let now = now_iso();
                sqlx::query("UPDATE cloud_usage_ingress SET forwarded_at = ? WHERE id = ?")
                    .bind(&now)
                    .bind(&id)
                    .execute(&self.pool)
                    .await?;
                forwarded += 1;
            }
        }
        Ok(forwarded)
    }

    async fn forward_health_batch(&self, fed: &FederationOutbound) -> Result<usize, DbError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, payload_json FROM cloud_health_ingress WHERE forwarded_at IS NULL ORDER BY received_at ASC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut forwarded = 0usize;
        for (id, payload_json) in rows {
            let mut body: serde_json::Value =
                serde_json::from_str(&payload_json).unwrap_or(serde_json::json!({}));
            if let Some(obj) = body.as_object_mut() {
                obj.entry("controller_id")
                    .or_insert_with(|| serde_json::Value::String(fed.cloud_controller_id.clone()));
            }
            let url = format!("{}/api/v1/cloud/health", fed.cloud_base_url);
            if self.post_cloud(&url, &fed.federation_token, &body).await {
                let now = now_iso();
                sqlx::query("UPDATE cloud_health_ingress SET forwarded_at = ? WHERE id = ?")
                    .bind(&now)
                    .bind(&id)
                    .execute(&self.pool)
                    .await?;
                forwarded += 1;
            }
        }
        Ok(forwarded)
    }

    async fn forward_logs_batch(&self, fed: &FederationOutbound) -> Result<usize, DbError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, payload_json FROM cloud_logs_ingress WHERE forwarded_at IS NULL ORDER BY received_at ASC LIMIT 20",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut forwarded = 0usize;
        for (id, payload_json) in rows {
            let mut body: serde_json::Value =
                serde_json::from_str(&payload_json).unwrap_or(serde_json::json!({}));
            if let Some(obj) = body.as_object_mut() {
                obj.entry("controller_id")
                    .or_insert_with(|| serde_json::Value::String(fed.cloud_controller_id.clone()));
            }
            let url = format!("{}/api/v1/cloud/logs", fed.cloud_base_url);
            if self.post_cloud(&url, &fed.federation_token, &body).await {
                let now = now_iso();
                sqlx::query("UPDATE cloud_logs_ingress SET forwarded_at = ? WHERE id = ?")
                    .bind(&now)
                    .bind(&id)
                    .execute(&self.pool)
                    .await?;
                forwarded += 1;
            }
        }
        Ok(forwarded)
    }

    async fn post_cloud(&self, url: &str, token: &str, body: &serde_json::Value) -> bool {
        match self
            .http
            .post(url)
            .header("X-Federation-Token", token)
            .json(body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() || resp.status() == reqwest::StatusCode::ACCEPTED => {
                true
            }
            Ok(resp) => {
                warn!(status = %resp.status(), url, "cloud reporter push rejected");
                false
            }
            Err(e) => {
                warn!(error = %e, url, "cloud reporter push failed");
                false
            }
        }
    }

    pub fn spawn(self: Arc<Self>, mut shutdown: watch::Receiver<bool>, interval_secs: u64) {
        let interval = Duration::from_secs(interval_secs.max(30));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await;
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_ok() && *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = tick.tick() => {
                        match self.push_pending_to_cloud().await {
                            Ok(summary) if summary.usage_forwarded + summary.health_forwarded + summary.logs_forwarded > 0 => {
                                info!(
                                    usage = summary.usage_forwarded,
                                    health = summary.health_forwarded,
                                    logs = summary.logs_forwarded,
                                    "cloud reporter forwarded pending ingress"
                                );
                            }
                            Ok(_) => {}
                            Err(e) => warn!(error = %e, "cloud reporter push cycle failed"),
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use database::setup;

    #[tokio::test]
    async fn ingest_usage_persists_row() {
        let pool = setup("sqlite::memory:").await.expect("db");
        let reporter = CloudReporter::new(pool);
        reporter
            .ingest_usage(
                Some("device-1"),
                CloudUsageIngest {
                    tenant_id: "tenant-a".into(),
                    device_id: Some("device-1".into()),
                    metric: "bandwidth_bytes".into(),
                    quantity: 1024.0,
                    window_start: None,
                    window_end: None,
                    metadata: None,
                },
            )
            .await
            .expect("ingest");

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM cloud_usage_ingress WHERE tenant_id = 'tenant-a'")
                .fetch_one(&reporter.pool)
                .await
                .expect("count");
        assert_eq!(count.0, 1);
    }
}
