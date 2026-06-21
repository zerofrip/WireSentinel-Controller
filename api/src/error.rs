use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use controller::auth::AuthError;
use database::DbError;

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    Unauthorized,
    Forbidden,
    BadRequest(String),
    Internal(String),
}

impl From<DbError> for ApiError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::NotFound(msg) => Self::NotFound(msg),
            DbError::Sqlx(e) => Self::Internal(e.to_string()),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::InvalidCredentials | AuthError::InvalidToken => Self::Unauthorized,
            AuthError::Forbidden => Self::Forbidden,
            AuthError::InvalidRole => Self::Internal("invalid role".into()),
            AuthError::Internal(msg) => Self::Internal(msg),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
