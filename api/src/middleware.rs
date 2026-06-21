use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use controller::Claims;

use crate::{error::ApiError, routes::AppState};

#[derive(Clone)]
pub struct AuthUser {
    pub claims: Claims,
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    let claims = state.auth.validate_token(token).map_err(ApiError::from)?;
    req.extensions_mut().insert(AuthUser { claims });
    Ok(next.run(req).await)
}

pub async fn extract_auth_user(req: &Request) -> Result<AuthUser, StatusCode> {
    req.extensions()
        .get::<AuthUser>()
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)
}

mod extractor {
    use super::{AuthUser, extract_auth_user};
    use axum::extract::{FromRequestParts, Request};
    use axum::http::request::Parts;

    impl<S> FromRequestParts<S> for AuthUser
    where
        S: Send + Sync,
    {
        type Rejection = axum::http::StatusCode;

        async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
            parts
                .extensions
                .get::<AuthUser>()
                .cloned()
                .ok_or(axum::http::StatusCode::UNAUTHORIZED)
        }
    }

    #[allow(dead_code)]
    async fn _from_request(req: Request) -> Result<AuthUser, axum::http::StatusCode> {
        extract_auth_user(&req).await
    }
}
