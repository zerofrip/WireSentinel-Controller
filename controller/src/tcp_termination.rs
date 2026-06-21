use chrono::{DateTime, Utc};
use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// When to terminate existing TCP sessions for route reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TcpTerminationMode {
    #[default]
    Disabled,
    OnVpnConnect,
    OnVpnDisconnect,
    OnRouteChange,
    Always,
}

impl TcpTerminationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::OnVpnConnect => "on_vpn_connect",
            Self::OnVpnDisconnect => "on_vpn_disconnect",
            Self::OnRouteChange => "on_route_change",
            Self::Always => "always",
        }
    }

    fn from_str(s: &str) -> Result<Self, DbError> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "on_vpn_connect" => Ok(Self::OnVpnConnect),
            "on_vpn_disconnect" => Ok(Self::OnVpnDisconnect),
            "on_route_change" => Ok(Self::OnRouteChange),
            "always" => Ok(Self::Always),
            other => Err(DbError::NotFound(format!("unknown tcp termination mode: {other}"))),
        }
    }
}

/// Persisted TCP termination settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTerminationSettings {
    #[serde(default)]
    pub mode: TcpTerminationMode,
    pub updated_at: DateTime<Utc>,
}

impl Default for TcpTerminationSettings {
    fn default() -> Self {
        Self {
            mode: TcpTerminationMode::Disabled,
            updated_at: Utc::now(),
        }
    }
}

/// Process-aware TCP reconnect rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTerminationRule {
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Value>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTerminationRulesSummary {
    pub rule_count: i64,
    pub enabled_count: i64,
    pub rules: Vec<TcpTerminationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTcpTerminationSettingsInput {
    pub mode: TcpTerminationMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTcpTerminationRuleInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Value>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTcpTerminationRuleInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_path: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<Option<Uuid>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Option<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

pub struct TcpTerminationManager {
    pool: DbPool,
}

impl TcpTerminationManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let now = now_iso();
        sqlx::query(
            "INSERT OR IGNORE INTO tcp_termination_settings (id, mode, updated_at) VALUES (1, 'disabled', ?)",
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_settings(&self) -> Result<TcpTerminationSettings, DbError> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT mode, updated_at FROM tcp_termination_settings WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((mode, updated_at)) => Ok(TcpTerminationSettings {
                mode: TcpTerminationMode::from_str(&mode)?,
                updated_at: parse_rfc3339(&updated_at)?,
            }),
            None => Ok(TcpTerminationSettings::default()),
        }
    }

    pub async fn set_settings(
        &self,
        input: UpdateTcpTerminationSettingsInput,
    ) -> Result<TcpTerminationSettings, DbError> {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO tcp_termination_settings (id, mode, updated_at) VALUES (1, ?, ?)
             ON CONFLICT(id) DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at",
        )
        .bind(input.mode.as_str())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        self.get_settings().await
    }

    pub async fn list_rules(&self) -> Result<Vec<TcpTerminationRule>, DbError> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                i32,
                String,
                String,
            ),
        >(
            "SELECT id, process_path, process_name, profile_id, route_json, enabled, created_at, updated_at
             FROM tcp_termination_rules ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_rule).collect()
    }

    pub async fn rules_summary(&self) -> Result<TcpTerminationRulesSummary, DbError> {
        let rules = self.list_rules().await?;
        let enabled_count = rules.iter().filter(|r| r.enabled).count() as i64;
        Ok(TcpTerminationRulesSummary {
            rule_count: rules.len() as i64,
            enabled_count,
            rules,
        })
    }

    pub async fn get_rule(&self, id: Uuid) -> Result<TcpTerminationRule, DbError> {
        self.list_rules()
            .await?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| DbError::NotFound(format!("tcp termination rule {id}")))
    }

    pub async fn create_rule(
        &self,
        input: CreateTcpTerminationRuleInput,
    ) -> Result<TcpTerminationRule, DbError> {
        let now = Utc::now();
        let rule = TcpTerminationRule {
            id: Uuid::new_v4(),
            process_path: input.process_path,
            process_name: input.process_name,
            profile_id: input.profile_id,
            route: input.route,
            enabled: input.enabled,
            created_at: now,
            updated_at: now,
        };
        self.insert_rule(&rule).await?;
        Ok(rule)
    }

    pub async fn update_rule(
        &self,
        id: Uuid,
        input: UpdateTcpTerminationRuleInput,
    ) -> Result<TcpTerminationRule, DbError> {
        let mut rule = self.get_rule(id).await?;
        if let Some(v) = input.process_path {
            rule.process_path = v;
        }
        if let Some(v) = input.process_name {
            rule.process_name = v;
        }
        if let Some(v) = input.profile_id {
            rule.profile_id = v;
        }
        if let Some(v) = input.route {
            rule.route = v;
        }
        if let Some(v) = input.enabled {
            rule.enabled = v;
        }
        rule.updated_at = Utc::now();
        self.persist_rule(&rule).await?;
        Ok(rule)
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<(), DbError> {
        let r = sqlx::query("DELETE FROM tcp_termination_rules WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if r.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("tcp termination rule {id}")));
        }
        Ok(())
    }

    async fn insert_rule(&self, rule: &TcpTerminationRule) -> Result<(), DbError> {
        let route_json = rule
            .route
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?;

        sqlx::query(
            "INSERT INTO tcp_termination_rules (id, process_path, process_name, profile_id, route_json, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(rule.id.to_string())
        .bind(&rule.process_path)
        .bind(&rule.process_name)
        .bind(rule.profile_id.map(|id| id.to_string()))
        .bind(route_json)
        .bind(rule.enabled as i32)
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn persist_rule(&self, rule: &TcpTerminationRule) -> Result<(), DbError> {
        let route_json = rule
            .route
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?;

        let r = sqlx::query(
            "UPDATE tcp_termination_rules SET process_path = ?, process_name = ?, profile_id = ?, route_json = ?, enabled = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&rule.process_path)
        .bind(&rule.process_name)
        .bind(rule.profile_id.map(|id| id.to_string()))
        .bind(route_json)
        .bind(rule.enabled as i32)
        .bind(rule.updated_at.to_rfc3339())
        .bind(rule.id.to_string())
        .execute(&self.pool)
        .await?;

        if r.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("tcp termination rule {}", rule.id)));
        }
        Ok(())
    }
}

fn row_to_rule(
    (
        id,
        process_path,
        process_name,
        profile_id,
        route_json,
        enabled,
        created_at,
        updated_at,
    ): (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i32,
        String,
        String,
    ),
) -> Result<TcpTerminationRule, DbError> {
    let route = route_json
        .map(|j| serde_json::from_str::<Value>(&j))
        .transpose()
        .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?;

    Ok(TcpTerminationRule {
        id: Uuid::parse_str(&id)
            .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?,
        process_path,
        process_name,
        profile_id: profile_id
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?,
        route,
        enabled: enabled != 0,
        created_at: parse_rfc3339(&created_at)?,
        updated_at: parse_rfc3339(&updated_at)?,
    })
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, DbError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))
}
