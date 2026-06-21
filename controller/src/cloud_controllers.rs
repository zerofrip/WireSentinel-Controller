use database::{models::now_iso, DbError, DbPool};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use crate::enrollment::hash_token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudControllerLink {
    pub id: String,
    pub tenant_id: String,
    pub cloud_base_url: String,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCloudControllerRequest {
    pub tenant_id: String,
    pub cloud_base_url: String,
    pub federation_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudControllerJobStub {
    pub job_id: String,
    pub controller_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudControllerDiagnosticsStub {
    pub controller_id: String,
    pub reachable: bool,
    pub federation_registered: bool,
    pub last_sync_at: Option<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudControllerBackupStub {
    pub backup_id: String,
    pub controller_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudControllerRestoreStub {
    pub restore_id: String,
    pub controller_id: String,
    pub status: String,
}

pub struct CloudControllerManager {
    pool: DbPool,
    http: Client,
}

impl CloudControllerManager {
    pub fn new(pool: DbPool) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { pool, http }
    }

    pub async fn list(&self) -> Result<Vec<CloudControllerLink>, DbError> {
        let rows = sqlx::query_as::<_, database::models::CloudControllerLinkRow>(
            "SELECT id, tenant_id, cloud_base_url, federation_token_hash, registered_at
             FROM cloud_controller_links ORDER BY registered_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(row_to_link).collect())
    }

    pub async fn get(&self, id: &str) -> Result<CloudControllerLink, DbError> {
        let row = sqlx::query_as::<_, database::models::CloudControllerLinkRow>(
            "SELECT id, tenant_id, cloud_base_url, federation_token_hash, registered_at
             FROM cloud_controller_links WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("cloud controller {id}")))?;

        Ok(row_to_link(row))
    }

    pub async fn create(&self, req: CreateCloudControllerRequest) -> Result<CloudControllerLink, DbError> {
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        let token_hash = hash_token(&req.federation_token);
        let cloud_base_url = req.cloud_base_url.trim_end_matches('/').to_string();

        sqlx::query(
            "INSERT INTO cloud_controller_links (id, tenant_id, cloud_base_url, federation_token_hash, registered_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&req.tenant_id)
        .bind(&cloud_base_url)
        .bind(&token_hash)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(CloudControllerLink {
            id,
            tenant_id: req.tenant_id,
            cloud_base_url,
            registered_at: now,
        })
    }

    async fn federation_token_for_tenant(&self, tenant_id: &str) -> Option<String> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT outbound_federation_token FROM federated_registration WHERE tenant_id = ? ORDER BY registered_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .ok()?;
        row.and_then(|(t,)| t.filter(|s| !s.is_empty()))
    }

    pub async fn provision(&self, id: &str) -> Result<CloudControllerJobStub, DbError> {
        let link = self.get(id).await?;
        let job_id = Uuid::new_v4().to_string();
        let endpoint_url = std::env::var("CONTROLLER_PUBLIC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".into());

        let mut status = "queued".to_string();
        let mut message = "provision request queued".to_string();

        if let Some(token) = self.federation_token_for_tenant(&link.tenant_id).await {
            let url = format!("{}/api/v1/federation/controllers", link.cloud_base_url);
            let body = serde_json::json!({
                "tenant_id": link.tenant_id,
                "name": format!("controller-{}", &link.id[..8.min(link.id.len())]),
                "endpoint_url": endpoint_url.trim_end_matches('/'),
                "api_key": token,
            });
            match self
                .http
                .post(&url)
                .header("X-Federation-Token", &token)
                .json(&body)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    status = "submitted".into();
                    message = "provision request accepted by cloud".into();
                }
                Ok(resp) => {
                    message = format!("cloud provision returned {}", resp.status());
                }
                Err(e) => {
                    message = format!("cloud provision unreachable: {e}");
                }
            }
        } else {
            message = "no federation token — provision not sent to cloud".into();
        }

        Ok(CloudControllerJobStub {
            job_id,
            controller_id: link.id,
            status,
            message,
        })
    }

    pub async fn diagnostics(&self, id: &str) -> Result<CloudControllerDiagnosticsStub, DbError> {
        let link = self.get(id).await?;
        let last_sync: Option<(String,)> = sqlx::query_as(
            "SELECT pushed_at FROM federation_sync_bundles WHERE tenant_id = ? ORDER BY pushed_at DESC LIMIT 1",
        )
        .bind(&link.tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let federation_registered = self
            .federation_token_for_tenant(&link.tenant_id)
            .await
            .is_some();

        let health_url = format!("{}/health", link.cloud_base_url);
        let reachable = match self.http.get(&health_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        };

        let notes = if reachable {
            "cloud health endpoint reachable".into()
        } else {
            format!("cloud health check failed for {health_url}")
        };

        Ok(CloudControllerDiagnosticsStub {
            controller_id: link.id,
            reachable,
            federation_registered,
            last_sync_at: last_sync.map(|r| r.0),
            notes,
        })
    }

    pub async fn backup(&self, id: &str) -> Result<CloudControllerBackupStub, DbError> {
        let link = self.get(id).await?;
        let backup_id = Uuid::new_v4().to_string();
        let mut status = "queued".to_string();

        if let Some(token) = self.federation_token_for_tenant(&link.tenant_id).await {
            let bundle = self.latest_sync_bundle(&link.tenant_id).await?;
            let url = format!("{}/api/v1/cloud/sync", link.cloud_base_url);
            if self
                .post_sync_bundle(&url, &token, &link.tenant_id, &bundle)
                .await
            {
                status = "uploaded".into();
            }
        }

        Ok(CloudControllerBackupStub {
            backup_id,
            controller_id: link.id,
            status,
        })
    }

    pub async fn restore(&self, id: &str) -> Result<CloudControllerRestoreStub, DbError> {
        let link = self.get(id).await?;
        let restore_id = Uuid::new_v4().to_string();
        let mut status = "queued".to_string();

        if let Some(token) = self.federation_token_for_tenant(&link.tenant_id).await {
            let url = format!(
                "{}/api/v1/federation/sync?tenant_id={}",
                link.cloud_base_url, link.tenant_id
            );
            match self
                .http
                .get(&url)
                .header("X-Federation-Token", &token)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let bundle_json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
                        let now = now_iso();
                        sqlx::query(
                            "INSERT INTO federation_sync_bundles (id, tenant_id, bundle_json, pushed_at) VALUES (?, ?, ?, ?)",
                        )
                        .bind(Uuid::new_v4().to_string())
                        .bind(&link.tenant_id)
                        .bind(&bundle_json)
                        .bind(&now)
                        .execute(&self.pool)
                        .await?;
                        status = "restored".into();
                    }
                }
                Ok(resp) => {
                    status = format!("cloud_restore_{}", resp.status().as_u16());
                }
                Err(_) => {
                    status = "cloud_unreachable".into();
                }
            }
        }

        Ok(CloudControllerRestoreStub {
            restore_id,
            controller_id: link.id,
            status,
        })
    }

    async fn latest_sync_bundle(&self, tenant_id: &str) -> Result<serde_json::Value, DbError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT bundle_json FROM federation_sync_bundles WHERE tenant_id = ? ORDER BY pushed_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .and_then(|(json,)| serde_json::from_str(&json).ok())
            .unwrap_or(serde_json::json!({})))
    }

    async fn post_sync_bundle(
        &self,
        url: &str,
        token: &str,
        tenant_id: &str,
        bundle: &serde_json::Value,
    ) -> bool {
        match self
            .http
            .post(url)
            .header("X-Federation-Token", token)
            .json(&serde_json::json!({
                "tenant_id": tenant_id,
                "bundle": bundle,
            }))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success() || resp.status() == reqwest::StatusCode::NO_CONTENT,
            Err(_) => false,
        }
    }
}

fn row_to_link(row: database::models::CloudControllerLinkRow) -> CloudControllerLink {
    CloudControllerLink {
        id: row.id,
        tenant_id: row.tenant_id,
        cloud_base_url: row.cloud_base_url,
        registered_at: row.registered_at,
    }
}
