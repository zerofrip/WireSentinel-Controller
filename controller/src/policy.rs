use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyScope {
    Global,
    Group,
    Device,
}

impl PolicyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Group => "group",
            Self::Device => "device",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "global" => Some(Self::Global),
            "group" => Some(Self::Group),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub scope: PolicyScope,
    pub scope_target: Option<String>,
    pub content: Value,
    pub version: i64,
    pub pushed_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub scope: PolicyScope,
    pub scope_target: Option<String>,
    pub content: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPolicyRequest {
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokePolicyRequest {
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePolicyBundle {
    pub device_id: String,
    pub policies: Vec<Policy>,
    pub policy_json: Value,
    pub locked_keys: Vec<String>,
    pub version: u32,
}

fn merge_policy_content(target: &mut Value, content: &Value) {
    match (target, content) {
        (Value::Object(dst), Value::Object(src)) => {
            if let Some(inner) = src.get("policy_json").and_then(|v| v.as_object()) {
                for (k, v) in inner {
                    dst.insert(k.clone(), v.clone());
                }
            }
            for (k, v) in src {
                if k != "locked_keys" && k != "policy_json" {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
        (dst, src) => *dst = src.clone(),
    }
}

pub struct PolicyDistributor {
    pool: DbPool,
}

impl PolicyDistributor {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreatePolicyRequest) -> Result<Policy, DbError> {
        if req.scope != PolicyScope::Global && req.scope_target.is_none() {
            return Err(DbError::NotFound(
                "scope_target required for group/device policies".into(),
            ));
        }

        let id = Uuid::new_v4().to_string();
        let created_at = now_iso();
        let content = serde_json::to_string(&req.content).unwrap_or_else(|_| "{}".into());

        sqlx::query(
            "INSERT INTO policies (id, name, scope, scope_target, content, version, created_at)
             VALUES (?, ?, ?, ?, ?, 1, ?)",
        )
        .bind(&id)
        .bind(&req.name)
        .bind(req.scope.as_str())
        .bind(&req.scope_target)
        .bind(&content)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        self.get(&id).await
    }

    pub async fn list(&self) -> Result<Vec<Policy>, DbError> {
        let rows = sqlx::query_as::<_, database::models::PolicyRow>(
            "SELECT id, name, scope, scope_target, content, version, pushed_at, revoked_at, created_at
             FROM policies ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_policy).collect()
    }

    pub async fn get(&self, id: &str) -> Result<Policy, DbError> {
        let row = sqlx::query_as::<_, database::models::PolicyRow>(
            "SELECT id, name, scope, scope_target, content, version, pushed_at, revoked_at, created_at
             FROM policies WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("policy {id}")))?;

        row_to_policy(row)
    }

    pub async fn push(&self, req: PushPolicyRequest) -> Result<Policy, DbError> {
        let pushed_at = now_iso();
        sqlx::query(
            "UPDATE policies SET pushed_at = ?, revoked_at = NULL, version = version + 1 WHERE id = ?",
        )
        .bind(&pushed_at)
        .bind(&req.policy_id)
        .execute(&self.pool)
        .await?;

        self.get(&req.policy_id).await
    }

    pub async fn revoke(&self, req: RevokePolicyRequest) -> Result<Policy, DbError> {
        let revoked_at = now_iso();
        sqlx::query("UPDATE policies SET revoked_at = ? WHERE id = ?")
            .bind(&revoked_at)
            .bind(&req.policy_id)
            .execute(&self.pool)
            .await?;

        self.get(&req.policy_id).await
    }

    pub async fn effective_for_device(&self, device_id: &str) -> Result<Vec<Policy>, DbError> {
        let all = self.list().await?;
        Ok(all
            .into_iter()
            .filter(|p| {
                p.revoked_at.is_none()
                    && p.pushed_at.is_some()
                    && (p.scope == PolicyScope::Global
                        || (p.scope == PolicyScope::Device
                            && p.scope_target.as_deref() == Some(device_id)))
            })
            .collect())
    }

    pub async fn device_bundle(&self, device_id: &str) -> Result<DevicePolicyBundle, DbError> {
        let policies = self.effective_for_device(device_id).await?;
        let mut policy_json = serde_json::json!({});
        let mut locked_keys = Vec::new();
        let mut version = 0u32;

        for policy in &policies {
            version = version.saturating_add(policy.version as u32);
            merge_policy_content(&mut policy_json, &policy.content);
            if let Some(keys) = policy.content.get("locked_keys").and_then(|v| v.as_array()) {
                for key in keys {
                    if let Some(s) = key.as_str() {
                        if !locked_keys.iter().any(|k: &String| k == s) {
                            locked_keys.push(s.to_string());
                        }
                    }
                }
            }
        }

        Ok(DevicePolicyBundle {
            device_id: device_id.to_string(),
            policies,
            policy_json,
            locked_keys,
            version: version.max(1),
        })
    }

    pub async fn global_bundle(&self) -> Result<DevicePolicyBundle, DbError> {
        let all = self.list().await?;
        let policies: Vec<Policy> = all
            .into_iter()
            .filter(|p| p.revoked_at.is_none() && p.scope == PolicyScope::Global)
            .collect();
        let mut policy_json = serde_json::json!({});
        let mut locked_keys = Vec::new();
        let mut version = 0u32;
        for policy in &policies {
            version = version.saturating_add(policy.version as u32);
            merge_policy_content(&mut policy_json, &policy.content);
            if let Some(keys) = policy.content.get("locked_keys").and_then(|v| v.as_array()) {
                for key in keys {
                    if let Some(s) = key.as_str() {
                        if !locked_keys.iter().any(|k: &String| k == s) {
                            locked_keys.push(s.to_string());
                        }
                    }
                }
            }
        }
        Ok(DevicePolicyBundle {
            device_id: "global".into(),
            policies,
            policy_json,
            locked_keys,
            version: version.max(1),
        })
    }

    pub async fn count_active(&self) -> Result<i64, DbError> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM policies WHERE revoked_at IS NULL")
                .fetch_one(&self.pool)
                .await?;
        Ok(count.0)
    }
}

fn row_to_policy(row: database::models::PolicyRow) -> Result<Policy, DbError> {
    let scope = PolicyScope::from_str(&row.scope)
        .ok_or_else(|| DbError::NotFound(format!("unknown scope {}", row.scope)))?;
    let content: Value =
        serde_json::from_str(&row.content).unwrap_or(Value::Object(Default::default()));

    Ok(Policy {
        id: row.id,
        name: row.name,
        scope,
        scope_target: row.scope_target,
        content,
        version: row.version,
        pushed_at: row.pushed_at,
        revoked_at: row.revoked_at,
        created_at: row.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_strings() {
        assert_eq!(PolicyScope::Global.as_str(), "global");
    }
}
