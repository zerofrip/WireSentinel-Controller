use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub id: String,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnrollmentTokenRequest {
    pub label: Option<String>,
    pub expires_in_hours: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateEnrollmentTokenResponse {
    pub id: String,
    pub token: String,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

pub struct EnrollmentManager {
    pool: DbPool,
}

impl EnrollmentManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create_token(
        &self,
        req: CreateEnrollmentTokenRequest,
    ) -> Result<(EnrollmentToken, String), DbError> {
        let id = Uuid::new_v4().to_string();
        let raw_token = format!("wset_{}", Uuid::new_v4());
        let token_hash = hash_token(&raw_token);
        let created_at = now_iso();
        let expires_at = req.expires_in_hours.map(|h| {
            (chrono::Utc::now() + chrono::Duration::hours(h)).to_rfc3339()
        });

        sqlx::query(
            "INSERT INTO enrollment_tokens (id, token_hash, label, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&token_hash)
        .bind(&req.label)
        .bind(&created_at)
        .bind(&expires_at)
        .execute(&self.pool)
        .await?;

        Ok((
            EnrollmentToken {
                id,
                label: req.label,
                created_at,
                expires_at,
                revoked_at: None,
            },
            raw_token,
        ))
    }

    pub async fn list_tokens(&self) -> Result<Vec<EnrollmentToken>, DbError> {
        let rows = sqlx::query_as::<_, database::models::EnrollmentTokenRow>(
            "SELECT id, token_hash, label, created_at, expires_at, revoked_at FROM enrollment_tokens ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EnrollmentToken {
                id: r.id,
                label: r.label,
                created_at: r.created_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            })
            .collect())
    }

    pub async fn revoke_token(&self, id: &str) -> Result<EnrollmentToken, DbError> {
        let revoked_at = now_iso();
        let result = sqlx::query(
            "UPDATE enrollment_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(&revoked_at)
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("enrollment token {id}")));
        }

        self.get_token(id).await
    }

    pub async fn rotate_token(
        &self,
        id: &str,
    ) -> Result<RotateEnrollmentTokenResponse, DbError> {
        let existing = self.get_token(id).await?;
        self.revoke_token(id).await?;

        let (new_token, raw) = self
            .create_token(CreateEnrollmentTokenRequest {
                label: existing.label.clone(),
                expires_in_hours: None,
            })
            .await?;

        Ok(RotateEnrollmentTokenResponse {
            id: new_token.id,
            token: raw,
            label: new_token.label,
            created_at: new_token.created_at,
            expires_at: new_token.expires_at,
        })
    }

    pub async fn validate_raw_token(&self, raw: &str) -> Result<EnrollmentToken, DbError> {
        let token_hash = hash_token(raw);
        let row = sqlx::query_as::<_, database::models::EnrollmentTokenRow>(
            "SELECT id, token_hash, label, created_at, expires_at, revoked_at FROM enrollment_tokens WHERE token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound("invalid enrollment token".into()))?;

        if row.revoked_at.is_some() {
            return Err(DbError::NotFound("enrollment token revoked".into()));
        }

        if let Some(ref exp) = row.expires_at {
            if let Some(dt) = database::models::parse_iso(exp) {
                if dt < chrono::Utc::now() {
                    return Err(DbError::NotFound("enrollment token expired".into()));
                }
            }
        }

        Ok(EnrollmentToken {
            id: row.id,
            label: row.label,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        })
    }

    async fn get_token(&self, id: &str) -> Result<EnrollmentToken, DbError> {
        let row = sqlx::query_as::<_, database::models::EnrollmentTokenRow>(
            "SELECT id, token_hash, label, created_at, expires_at, revoked_at FROM enrollment_tokens WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("enrollment token {id}")))?;

        Ok(EnrollmentToken {
            id: row.id,
            label: row.label,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        })
    }
}

pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_stable() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("def"));
    }
}
