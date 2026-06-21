use chrono::{Duration, Utc};
use database::{models::now_iso, DbError, DbPool};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn can_manage_users(self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_manage_enrollment(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }

    pub fn can_manage_devices(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }

    pub fn can_manage_policies(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }

    pub fn can_ingest_audit(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }

    pub fn can_read(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: Role,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
    pub role: Role,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct ControllerSecurityPolicy {
    pub jwt_secret: String,
    pub token_ttl_hours: i64,
    pub bcrypt_cost: u32,
    pub require_https: bool,
    pub max_login_attempts: u32,
}

impl Default for ControllerSecurityPolicy {
    fn default() -> Self {
        Self {
            jwt_secret: std::env::var("WS_CONTROLLER_JWT_SECRET")
                .unwrap_or_else(|_| "dev-insecure-secret-change-me".into()),
            token_ttl_hours: 24,
            bcrypt_cost: 12,
            require_https: false,
            max_login_attempts: 5,
        }
    }
}

pub struct AuthService {
    pool: DbPool,
    policy: ControllerSecurityPolicy,
}

impl AuthService {
    pub fn new(pool: DbPool, policy: ControllerSecurityPolicy) -> Self {
        Self { pool, policy }
    }

    pub fn policy(&self) -> &ControllerSecurityPolicy {
        &self.policy
    }

    pub async fn ensure_default_admin(&self) -> Result<(), DbError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;

        if count.0 == 0 {
            let id = Uuid::new_v4().to_string();
            let hash = bcrypt::hash("admin", self.policy.bcrypt_cost)
                .map_err(|e| DbError::NotFound(e.to_string()))?;
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind("admin")
            .bind(&hash)
            .bind(Role::Admin.as_str())
            .bind(now_iso())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn login(&self, req: LoginRequest) -> Result<LoginResponse, AuthError> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT id, password_hash, role FROM users WHERE username = ?",
        )
        .bind(&req.username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let (user_id, password_hash, role_str) =
            row.ok_or(AuthError::InvalidCredentials)?;

        let valid = bcrypt::verify(&req.password, &password_hash)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if !valid {
            return Err(AuthError::InvalidCredentials);
        }

        let role = Role::from_str(&role_str).ok_or(AuthError::InvalidRole)?;
        let token = self.issue_token(&user_id, &req.username, role)?;

        Ok(LoginResponse {
            token: token.token,
            expires_at: token.expires_at,
            role,
            username: req.username,
        })
    }

    pub fn issue_token(
        &self,
        user_id: &str,
        username: &str,
        role: Role,
    ) -> Result<IssuedToken, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.policy.token_ttl_hours);
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.policy.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(IssuedToken {
            token,
            expires_at: exp.to_rfc3339(),
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.policy.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(data.claims)
    }

    pub fn authorize(&self, claims: &Claims, required: Role) -> Result<(), AuthError> {
        if role_level(claims.role) >= role_level(required) {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssuedToken {
    token: String,
    expires_at: String,
}

fn role_level(role: Role) -> u8 {
    match role {
        Role::Admin => 3,
        Role::Operator => 2,
        Role::Viewer => 1,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid token")]
    InvalidToken,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid role")]
    InvalidRole,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DbError> for AuthError {
    fn from(value: DbError) -> Self {
        Self::Internal(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_hierarchy() {
        assert!(Role::Admin.can_manage_users());
        assert!(!Role::Viewer.can_manage_policies());
        assert!(Role::Operator.can_manage_devices());
    }
}
