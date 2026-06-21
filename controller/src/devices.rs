use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Active,
    Revoked,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub agent_version: Option<String>,
    pub enrollment_token_id: Option<String>,
    pub status: DeviceStatus,
    pub last_heartbeat_at: Option<String>,
    pub created_at: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub enrollment_token: String,
    pub name: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub agent_version: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHeartbeat {
    pub agent_version: Option<String>,
    pub metadata: Option<Value>,
}

pub struct DeviceManager {
    pool: DbPool,
}

impl DeviceManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn register(
        &self,
        req: RegisterDeviceRequest,
        enrollment: &super::enrollment::EnrollmentToken,
    ) -> Result<Device, DbError> {
        let id = Uuid::new_v4().to_string();
        let created_at = now_iso();
        let metadata = serde_json::to_string(&req.metadata.unwrap_or(Value::Object(Default::default()))
        )
        .unwrap_or_else(|_| "{}".into());

        sqlx::query(
            "INSERT INTO devices (id, name, hostname, os, agent_version, enrollment_token_id, status, last_heartbeat_at, created_at, metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&req.name)
        .bind(&req.hostname)
        .bind(&req.os)
        .bind(&req.agent_version)
        .bind(&enrollment.id)
        .bind(DeviceStatus::Active.as_str())
        .bind(&created_at)
        .bind(&created_at)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        self.get(&id).await
    }

    pub async fn list(&self) -> Result<Vec<Device>, DbError> {
        let rows = sqlx::query_as::<_, database::models::DeviceRow>(
            "SELECT id, name, hostname, os, agent_version, enrollment_token_id, status, last_heartbeat_at, created_at, metadata
             FROM devices ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_device).collect()
    }

    pub async fn get(&self, id: &str) -> Result<Device, DbError> {
        let row = sqlx::query_as::<_, database::models::DeviceRow>(
            "SELECT id, name, hostname, os, agent_version, enrollment_token_id, status, last_heartbeat_at, created_at, metadata
             FROM devices WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("device {id}")))?;

        row_to_device(row)
    }

    pub async fn heartbeat(&self, id: &str, hb: DeviceHeartbeat) -> Result<Device, DbError> {
        let now = now_iso();
        let metadata = hb
            .metadata
            .map(|m| serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));

        if let Some(ref meta) = metadata {
            sqlx::query(
                "UPDATE devices SET last_heartbeat_at = ?, agent_version = COALESCE(?, agent_version), metadata = ?, status = ?
                 WHERE id = ? AND status != 'revoked'",
            )
            .bind(&now)
            .bind(&hb.agent_version)
            .bind(meta)
            .bind(DeviceStatus::Active.as_str())
            .bind(id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE devices SET last_heartbeat_at = ?, agent_version = COALESCE(?, agent_version), status = ?
                 WHERE id = ? AND status != 'revoked'",
            )
            .bind(&now)
            .bind(&hb.agent_version)
            .bind(DeviceStatus::Active.as_str())
            .bind(id)
            .execute(&self.pool)
            .await?;
        }

        self.get(id).await
    }

    pub async fn revoke(&self, id: &str) -> Result<Device, DbError> {
        sqlx::query("UPDATE devices SET status = ? WHERE id = ?")
            .bind(DeviceStatus::Revoked.as_str())
            .bind(id)
            .execute(&self.pool)
            .await?;

        self.get(id).await
    }

    pub async fn count_by_status(&self) -> Result<(i64, i64, i64), DbError> {
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
        Ok((active.0, pending.0, revoked.0))
    }
}

fn row_to_device(row: database::models::DeviceRow) -> Result<Device, DbError> {
    let status = DeviceStatus::from_str(&row.status)
        .ok_or_else(|| DbError::NotFound(format!("unknown status {}", row.status)))?;
    let metadata: Value = serde_json::from_str(&row.metadata).unwrap_or(Value::Object(Default::default()));

    Ok(Device {
        id: row.id,
        name: row.name,
        hostname: row.hostname,
        os: row.os,
        agent_version: row.agent_version,
        enrollment_token_id: row.enrollment_token_id,
        status,
        last_heartbeat_at: row.last_heartbeat_at,
        created_at: row.created_at,
        metadata,
    })
}
