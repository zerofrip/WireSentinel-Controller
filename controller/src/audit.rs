use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub source: String,
    pub actor: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub details: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestAuditEvent {
    pub source: String,
    pub actor: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub action: Option<String>,
    pub source: Option<String>,
}

pub struct AuditCollector {
    pool: DbPool,
}

impl AuditCollector {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn ingest(&self, event: IngestAuditEvent) -> Result<AuditEvent, DbError> {
        let id = Uuid::new_v4().to_string();
        let created_at = now_iso();
        let details = serde_json::to_string(&event.details.unwrap_or(Value::Object(Default::default())))
            .unwrap_or_else(|_| "{}".into());

        sqlx::query(
            "INSERT INTO audit_events (id, source, actor, action, resource_type, resource_id, details, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&event.source)
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(&event.resource_id)
        .bind(&details)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        Ok(AuditEvent {
            id,
            source: event.source,
            actor: event.actor,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            details: serde_json::from_str(&details).unwrap_or(Value::Object(Default::default())),
            created_at,
        })
    }

    pub async fn list(&self, query: AuditQuery) -> Result<Vec<AuditEvent>, DbError> {
        let limit = query.limit.unwrap_or(100).clamp(1, 1000);
        let offset = query.offset.unwrap_or(0).max(0);

        let rows = if query.action.is_some() || query.source.is_some() {
            let mut sql = String::from(
                "SELECT id, source, actor, action, resource_type, resource_id, details, created_at
                 FROM audit_events WHERE 1=1",
            );
            if query.action.is_some() {
                sql.push_str(" AND action = ?");
            }
            if query.source.is_some() {
                sql.push_str(" AND source = ?");
            }
            sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

            let mut q = sqlx::query_as::<_, database::models::AuditEventRow>(&sql);
            if let Some(ref action) = query.action {
                q = q.bind(action);
            }
            if let Some(ref source) = query.source {
                q = q.bind(source);
            }
            q.bind(limit).bind(offset).fetch_all(&self.pool).await?
        } else {
            sqlx::query_as::<_, database::models::AuditEventRow>(
                "SELECT id, source, actor, action, resource_type, resource_id, details, created_at
                 FROM audit_events ORDER BY created_at DESC LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(row_to_event).collect()
    }

    pub async fn count(&self) -> Result<i64, DbError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0)
    }
}

fn row_to_event(row: database::models::AuditEventRow) -> Result<AuditEvent, DbError> {
    Ok(AuditEvent {
        id: row.id,
        source: row.source,
        actor: row.actor,
        action: row.action,
        resource_type: row.resource_type,
        resource_id: row.resource_id,
        details: serde_json::from_str(&row.details).unwrap_or(Value::Object(Default::default())),
        created_at: row.created_at,
    })
}
