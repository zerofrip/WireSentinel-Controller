use chrono::{DateTime, Utc};
use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Global split-tunnel template application mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TemplateMode {
    #[default]
    Disabled,
    Merge,
    Override,
}

impl TemplateMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Merge => "merge",
            Self::Override => "override",
        }
    }

    fn from_str(s: &str) -> Result<Self, DbError> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "merge" => Ok(Self::Merge),
            "override" => Ok(Self::Override),
            other => Err(DbError::NotFound(format!("unknown template mode: {other}"))),
        }
    }
}

/// Per-application split-tunnel rule within a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub id: Uuid,
    pub app_id: Uuid,
    pub route: Value,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Per-domain split-tunnel rule within a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    pub id: Uuid,
    pub pattern: String,
    pub route: Value,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Reusable global split-tunnel policy template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitTunnelTemplate {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub default_route: Value,
    #[serde(default)]
    pub app_rules: Vec<AppRule>,
    #[serde(default)]
    pub domain_rules: Vec<DomainRule>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Active template mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitTemplateModeSettings {
    #[serde(default)]
    pub mode: TemplateMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_template_id: Option<Uuid>,
    pub updated_at: DateTime<Utc>,
}

impl Default for SplitTemplateModeSettings {
    fn default() -> Self {
        Self {
            mode: TemplateMode::Disabled,
            active_template_id: None,
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitTemplatesSummary {
    pub template_count: i64,
    pub enabled_count: i64,
    pub templates: Vec<SplitTunnelTemplate>,
    pub mode: SplitTemplateModeSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSplitTemplateInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub default_route: Value,
    #[serde(default)]
    pub app_rules: Vec<AppRule>,
    #[serde(default)]
    pub domain_rules: Vec<DomainRule>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSplitTemplateInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_route: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_rules: Option<Vec<AppRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_rules: Option<Vec<DomainRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSplitTemplateModeInput {
    pub mode: TemplateMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_template_id: Option<Uuid>,
}

pub struct SplitTemplateManager {
    pool: DbPool,
}

impl SplitTemplateManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let now = now_iso();
        sqlx::query(
            "INSERT OR IGNORE INTO split_template_mode (id, mode, updated_at) VALUES (1, 'disabled', ?)",
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_templates(&self) -> Result<Vec<SplitTunnelTemplate>, DbError> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                i32,
                String,
                String,
            ),
        >(
            "SELECT id, name, description, default_route_json, app_rules_json, domain_rules_json, enabled, created_at, updated_at
             FROM split_tunnel_templates ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_template).collect()
    }

    pub async fn summary(&self) -> Result<SplitTemplatesSummary, DbError> {
        let templates = self.list_templates().await?;
        let enabled_count = templates.iter().filter(|t| t.enabled).count() as i64;
        let mode = self.get_mode().await?;
        Ok(SplitTemplatesSummary {
            template_count: templates.len() as i64,
            enabled_count,
            templates,
            mode,
        })
    }

    pub async fn get_template(&self, id: Uuid) -> Result<SplitTunnelTemplate, DbError> {
        self.list_templates()
            .await?
            .into_iter()
            .find(|t| t.id == id)
            .ok_or_else(|| DbError::NotFound(format!("split template {id}")))
    }

    pub async fn create_template(
        &self,
        input: CreateSplitTemplateInput,
    ) -> Result<SplitTunnelTemplate, DbError> {
        let now = Utc::now();
        let template = SplitTunnelTemplate {
            id: Uuid::new_v4(),
            name: input.name,
            description: input.description,
            default_route: input.default_route,
            app_rules: input.app_rules,
            domain_rules: input.domain_rules,
            enabled: input.enabled,
            created_at: now,
            updated_at: now,
        };
        self.insert_template(&template).await?;
        Ok(template)
    }

    pub async fn update_template(
        &self,
        id: Uuid,
        input: UpdateSplitTemplateInput,
    ) -> Result<SplitTunnelTemplate, DbError> {
        let mut template = self.get_template(id).await?;
        if let Some(v) = input.name {
            template.name = v;
        }
        if let Some(v) = input.description {
            template.description = v;
        }
        if let Some(v) = input.default_route {
            template.default_route = v;
        }
        if let Some(v) = input.app_rules {
            template.app_rules = v;
        }
        if let Some(v) = input.domain_rules {
            template.domain_rules = v;
        }
        if let Some(v) = input.enabled {
            template.enabled = v;
        }
        template.updated_at = Utc::now();
        self.persist_template(&template).await?;
        Ok(template)
    }

    pub async fn delete_template(&self, id: Uuid) -> Result<(), DbError> {
        let r = sqlx::query("DELETE FROM split_tunnel_templates WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if r.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("split template {id}")));
        }

        let mode = self.get_mode().await?;
        if mode.active_template_id == Some(id) {
            self.set_mode(UpdateSplitTemplateModeInput {
                mode: mode.mode,
                active_template_id: None,
            })
            .await?;
        }
        Ok(())
    }

    pub async fn get_mode(&self) -> Result<SplitTemplateModeSettings, DbError> {
        let row: Option<(String, Option<String>, String)> = sqlx::query_as(
            "SELECT mode, active_template_id, updated_at FROM split_template_mode WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((mode, active_template_id, updated_at)) => Ok(SplitTemplateModeSettings {
                mode: TemplateMode::from_str(&mode)?,
                active_template_id: active_template_id
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?,
                updated_at: parse_rfc3339(&updated_at)?,
            }),
            None => Ok(SplitTemplateModeSettings::default()),
        }
    }

    pub async fn set_mode(
        &self,
        input: UpdateSplitTemplateModeInput,
    ) -> Result<SplitTemplateModeSettings, DbError> {
        if let Some(id) = input.active_template_id {
            self.get_template(id).await?;
        }

        let now = Utc::now();
        sqlx::query(
            "INSERT INTO split_template_mode (id, mode, active_template_id, updated_at) VALUES (1, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET mode = excluded.mode, active_template_id = excluded.active_template_id, updated_at = excluded.updated_at",
        )
        .bind(input.mode.as_str())
        .bind(input.active_template_id.map(|id| id.to_string()))
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        self.get_mode().await
    }

    async fn insert_template(&self, template: &SplitTunnelTemplate) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO split_tunnel_templates (id, name, description, default_route_json, app_rules_json, domain_rules_json, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(template.id.to_string())
        .bind(&template.name)
        .bind(&template.description)
        .bind(json_string(&template.default_route)?)
        .bind(json_string(&template.app_rules)?)
        .bind(json_string(&template.domain_rules)?)
        .bind(template.enabled as i32)
        .bind(template.created_at.to_rfc3339())
        .bind(template.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn persist_template(&self, template: &SplitTunnelTemplate) -> Result<(), DbError> {
        let r = sqlx::query(
            "UPDATE split_tunnel_templates SET name = ?, description = ?, default_route_json = ?, app_rules_json = ?, domain_rules_json = ?, enabled = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&template.name)
        .bind(&template.description)
        .bind(json_string(&template.default_route)?)
        .bind(json_string(&template.app_rules)?)
        .bind(json_string(&template.domain_rules)?)
        .bind(template.enabled as i32)
        .bind(template.updated_at.to_rfc3339())
        .bind(template.id.to_string())
        .execute(&self.pool)
        .await?;

        if r.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("split template {}", template.id)));
        }
        Ok(())
    }
}

fn json_string<T: Serialize>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))
}

fn row_to_template(
    (
        id,
        name,
        description,
        default_route_json,
        app_rules_json,
        domain_rules_json,
        enabled,
        created_at,
        updated_at,
    ): (
        String,
        String,
        String,
        String,
        String,
        String,
        i32,
        String,
        String,
    ),
) -> Result<SplitTunnelTemplate, DbError> {
    Ok(SplitTunnelTemplate {
        id: Uuid::parse_str(&id)
            .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?,
        name,
        description,
        default_route: serde_json::from_str(&default_route_json)
            .map_err(|e| DbError::Sqlx(sqlx::Error::Decode(Box::new(e))))?,
        app_rules: serde_json::from_str(&app_rules_json).unwrap_or_default(),
        domain_rules: serde_json::from_str(&domain_rules_json).unwrap_or_default(),
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
