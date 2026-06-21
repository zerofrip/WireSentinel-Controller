use database::DbError;
use database::DbPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub devices_active: i64,
    pub devices_pending: i64,
    pub devices_revoked: i64,
    pub policies_active: i64,
    pub audit_events_total: i64,
    pub enrollment_tokens_total: i64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetricsPayload {
    pub device_id: String,
    pub active_tunnels: u32,
    pub active_transports: u32,
    pub blocked_requests: u64,
    pub dns_queries: u64,
    pub open_leak_incidents: u32,
    pub route_changes_24h: u64,
}

pub struct MetricsAggregator {
    pool: DbPool,
    started_at: std::time::Instant,
}

impl MetricsAggregator {
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            started_at: std::time::Instant::now(),
        }
    }

    pub async fn snapshot(&self) -> Result<MetricsSnapshot, DbError> {
        let active: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM devices WHERE status = 'active'")
                .fetch_one(&self.pool)
                .await?;
        let pending: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM devices WHERE status = 'pending'")
                .fetch_one(&self.pool)
                .await?;
        let revoked: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM devices WHERE status = 'revoked'")
                .fetch_one(&self.pool)
                .await?;
        let policies: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM policies WHERE revoked_at IS NULL")
                .fetch_one(&self.pool)
                .await?;
        let audit: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;
        let tokens: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM enrollment_tokens")
            .fetch_one(&self.pool)
            .await?;

        Ok(MetricsSnapshot {
            devices_active: active.0,
            devices_pending: pending.0,
            devices_revoked: revoked.0,
            policies_active: policies.0,
            audit_events_total: audit.0,
            enrollment_tokens_total: tokens.0,
            uptime_seconds: self.started_at.elapsed().as_secs(),
        })
    }

    pub async fn ingest_agent_metrics(
        &self,
        device_id: &str,
        payload: AgentMetricsPayload,
    ) -> Result<(), DbError> {
        let details = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        let _ = sqlx::query(
            "INSERT INTO audit_events (id, source, actor, action, resource_type, resource_id, details, created_at)
             VALUES (?, 'agent', ?, 'metrics_push', 'device', ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(device_id)
        .bind(device_id)
        .bind(details)
        .bind(database::models::now_iso())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub fn to_prometheus(&self, snapshot: &MetricsSnapshot) -> String {
        format!(
            "# HELP ws_controller_devices_active Active enrolled devices\n\
             # TYPE ws_controller_devices_active gauge\n\
             ws_controller_devices_active {}\n\
             # HELP ws_controller_devices_pending Pending devices\n\
             # TYPE ws_controller_devices_pending gauge\n\
             ws_controller_devices_pending {}\n\
             # HELP ws_controller_devices_revoked Revoked devices\n\
             # TYPE ws_controller_devices_revoked gauge\n\
             ws_controller_devices_revoked {}\n\
             # HELP ws_controller_policies_active Active policies\n\
             # TYPE ws_controller_policies_active gauge\n\
             ws_controller_policies_active {}\n\
             # HELP ws_controller_audit_events_total Total audit events\n\
             # TYPE ws_controller_audit_events_total counter\n\
             ws_controller_audit_events_total {}\n\
             # HELP ws_controller_uptime_seconds Controller uptime\n\
             # TYPE ws_controller_uptime_seconds gauge\n\
             ws_controller_uptime_seconds {}\n",
            snapshot.devices_active,
            snapshot.devices_pending,
            snapshot.devices_revoked,
            snapshot.policies_active,
            snapshot.audit_events_total,
            snapshot.uptime_seconds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::MetricsSnapshot;

    #[test]
    fn snapshot_fields_are_serializable() {
        let snap = MetricsSnapshot {
            devices_active: 1,
            devices_pending: 0,
            devices_revoked: 0,
            policies_active: 2,
            audit_events_total: 3,
            enrollment_tokens_total: 1,
            uptime_seconds: 10,
        };
        let json = serde_json::to_string(&snap).expect("serialize metrics");
        assert!(json.contains("devices_active"));
    }
}
