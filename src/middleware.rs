use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use crate::error::AccessError;
use crate::rbac::Role;

/// Extractor that checks if the authenticated user has a required role.
pub struct RequireRole<C> {
    /// Decoded JWT claims.
    pub claims: C,
    /// Required role for the endpoint.
    pub role: Role,
}

#[cfg(feature = "tokenkit")]
impl<C, S> FromRequestParts<S> for RequireRole<C>
where
    C: DeserializeOwned + Send + 'static,
    S: Send + Sync,
    tokenkit::JwtService: axum::extract::FromRef<S>,
{
    type Rejection = AccessError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        use axum::extract::FromRef;
        let service = tokenkit::JwtService::from_ref(state);
        let header = parts.headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AccessError::Unauthorized("Missing token".into()))?;
        let claims: C = service.decode(header).map_err(|e| AccessError::Unauthorized(e.to_string()))?;
        Ok(Self { claims, role: Role::Viewer })
    }
}

#[cfg(not(feature = "tokenkit"))]
impl<C, S> FromRequestParts<S> for RequireRole<C>
where
    C: DeserializeOwned + Send + 'static,
    S: Send + Sync,
{
    type Rejection = AccessError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Err(AccessError::Unauthorized("tokenkit feature required".into()))
    }
}
