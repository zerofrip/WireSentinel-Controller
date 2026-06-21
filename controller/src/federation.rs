use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::enrollment::hash_token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedRegistration {
    pub id: String,
    pub cloud_controller_id: String,
    pub tenant_id: String,
    pub cloud_base_url: String,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFromCloudRequest {
    pub token: String,
    pub tenant_id: String,
    pub cloud_base_url: String,
}

pub struct FederationService {
    pool: DbPool,
}

impl FederationService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn register_from_cloud(
        &self,
        token: &str,
        tenant_id: &str,
        cloud_base_url: &str,
    ) -> Result<FederatedRegistration, DbError> {
        if token.is_empty() || tenant_id.is_empty() || cloud_base_url.is_empty() {
            return Err(DbError::NotFound("invalid federation registration payload".into()));
        }

        let token_hash = hash_token(token);
        let now = now_iso();
        let cloud_controller_id = Uuid::new_v4().to_string();
        let registration_id = Uuid::new_v4().to_string();
        let link_id = Uuid::new_v4().to_string();
        let cloud_base_url = cloud_base_url.trim_end_matches('/').to_string();

        sqlx::query("DELETE FROM federated_registration")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "INSERT INTO federated_registration (id, cloud_controller_id, tenant_id, federation_token_hash, cloud_base_url, registered_at, outbound_federation_token)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&registration_id)
        .bind(&cloud_controller_id)
        .bind(tenant_id)
        .bind(&token_hash)
        .bind(&cloud_base_url)
        .bind(&now)
        .bind(token)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "INSERT INTO cloud_controller_links (id, tenant_id, cloud_base_url, federation_token_hash, registered_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&link_id)
        .bind(tenant_id)
        .bind(&cloud_base_url)
        .bind(&token_hash)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(FederatedRegistration {
            id: registration_id,
            cloud_controller_id,
            tenant_id: tenant_id.to_string(),
            cloud_base_url,
            registered_at: now,
        })
    }

    pub async fn validate_cloud_request(&self, token: &str) -> Result<FederatedRegistration, DbError> {
        let token_hash = hash_token(token);
        let row = sqlx::query_as::<_, database::models::FederatedRegistrationRow>(
            "SELECT id, cloud_controller_id, tenant_id, federation_token_hash, cloud_base_url, registered_at, outbound_federation_token
             FROM federated_registration WHERE federation_token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound("invalid federation token".into()))?;

        Ok(row_to_registration(row))
    }

    pub async fn get_registration(&self) -> Result<Option<FederatedRegistration>, DbError> {
        let row = sqlx::query_as::<_, database::models::FederatedRegistrationRow>(
            "SELECT id, cloud_controller_id, tenant_id, federation_token_hash, cloud_base_url, registered_at, outbound_federation_token
             FROM federated_registration ORDER BY registered_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(row_to_registration))
    }

    pub async fn push_sync_bundle(&self, bundle_json: &str, tenant_id: Option<&str>) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        sqlx::query(
            "INSERT INTO federation_sync_bundles (id, tenant_id, bundle_json, pushed_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(bundle_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn pull_sync_bundle(&self, tenant_id: Option<&str>) -> Result<Option<Value>, DbError> {
        let row = if let Some(tid) = tenant_id {
            sqlx::query_as::<_, database::models::FederationSyncBundleRow>(
                "SELECT id, tenant_id, bundle_json, pushed_at FROM federation_sync_bundles
                 WHERE tenant_id = ? ORDER BY pushed_at DESC LIMIT 1",
            )
            .bind(tid)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, database::models::FederationSyncBundleRow>(
                "SELECT id, tenant_id, bundle_json, pushed_at FROM federation_sync_bundles
                 ORDER BY pushed_at DESC LIMIT 1",
            )
            .fetch_optional(&self.pool)
            .await?
        };

        Ok(row.and_then(|r| serde_json::from_str(&r.bundle_json).ok()))
    }
}

fn row_to_registration(row: database::models::FederatedRegistrationRow) -> FederatedRegistration {
    FederatedRegistration {
        id: row.id,
        cloud_controller_id: row.cloud_controller_id,
        tenant_id: row.tenant_id,
        cloud_base_url: row.cloud_base_url,
        registered_at: row.registered_at,
    }
}
