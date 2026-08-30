use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::Deserialize;

use crate::error::AccessError;
use crate::rbac::RoleHierarchy;

/// Extractor that requires the authenticated user to have a specific role.
///
/// Generic over the claims type `C`. The claims must contain a `role` field
/// that maps to a role name in the configured `RoleHierarchy`.
///
/// # Example
///
/// ```ignore
/// async fn admin_only(
///     RequireRole(claims): RequireRole<MyClaims>,
/// ) -> impl IntoResponse {
///     format!("Hello, admin {}", claims.sub)
/// }
/// ```
pub struct RequireRole<C>(pub C);

/// Claims type that contains role information.
///
/// Implement this trait for your claims struct to use with `RequireRole`.
pub trait HasRole {
    /// Returns the role name associated with these claims.
    fn role_name(&self) -> &str;
}

impl<C, S> FromRequestParts<S> for RequireRole<C>
where
    C: Deserialize<serde_json::Value> + HasRole + Send,
    S: Send + Sync,
{
    type Rejection = AccessError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the Authorization header
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AccessError::Unauthorized)?;

        let _token = header
            .strip_prefix("Bearer ")
            .ok_or(AccessError::Unauthorized)?;

        // In a real implementation, decode the JWT and extract claims.
        // For now, return unauthorized as placeholder.
        Err(AccessError::Unauthorized)
    }
}

/// Middleware that checks whether the authenticated principal has a required role.
///
/// This is a function-based middleware suitable for use with `axum::middleware::from_fn`.
pub async fn require_role_middleware(
    axum::extract::State(hierarchy): axum::extract::State<std::sync::Arc<RoleHierarchy>>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AccessError> {
    // Extract the role from the request (e.g., from JWT claims in extensions)
    let role_name = req
        .extensions()
        .get::<String>()
        .ok_or(AccessError::Unauthorized)?;

    if !hierarchy.resolve_permissions(role_name).is_empty() {
        Ok(next.run(req).await)
    } else {
        Err(AccessError::Forbidden)
    }
}
