use std::marker::PhantomData;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use crate::error::AccessError;
use crate::rbac::Role;

/// Trait for role requirements used as type parameters.
///
/// Implementations map a marker type to the required [`Role`].
pub trait RoleMarker: Send + Sync + 'static {
    /// Returns the role this marker requires.
    fn required_role() -> Role;
}

/// Marker indicating the Viewer role (or higher) is required.
pub struct IsViewer;
impl RoleMarker for IsViewer {
    fn required_role() -> Role {
        Role::Viewer
    }
}

/// Marker indicating the Editor role (or higher) is required.
pub struct IsEditor;
impl RoleMarker for IsEditor {
    fn required_role() -> Role {
        Role::Editor
    }
}

/// Marker indicating the Admin role is required.
pub struct IsAdmin;
impl RoleMarker for IsAdmin {
    fn required_role() -> Role {
        Role::Admin
    }
}

/// Trait for claims that carry a [`Role`].
///
/// Implement this on your JWT claims struct so that [`RequireRole`] can
/// extract the user's role and enforce the required privilege level.
///
/// # Example
///
/// ```ignore
/// #[derive(Deserialize)]
/// struct MyClaims {
///     sub: String,
///     role: Role,
/// }
///
/// impl HasRole for MyClaims {
///     fn role(&self) -> Role {
///         self.role
///     }
/// }
/// ```
pub trait HasRole {
    /// Returns the role of the authenticated principal.
    fn role(&self) -> Role;
}

/// Extractor that checks if the authenticated user has a required role.
///
/// The required role is specified via the `R` type parameter, which must
/// implement [`RoleMarker`]. The claims type `C` must implement [`HasRole`]
/// so the extractor can compare the user's actual role against the
/// requirement.
///
/// # Security
///
/// The extractor **enforces** that `user_role >= required_role` using
/// [`Role::has_at_least`]. Requests with insufficient privileges are
/// rejected with `403 Forbidden`.
///
/// # Example
///
/// ```ignore
/// // Requires Admin role
/// async fn admin_handler(
///     RequireRole { claims, .. }: RequireRole<MyClaims, IsAdmin>,
/// ) -> impl IntoResponse { ... }
///
/// // Requires Editor role (or higher)
/// async fn editor_handler(
///     RequireRole { claims, .. }: RequireRole<MyClaims, IsEditor>,
/// ) -> impl IntoResponse { ... }
/// ```
pub struct RequireRole<C, R: RoleMarker = IsViewer> {
    /// Decoded JWT claims.
    pub claims: C,
    /// Required role for the endpoint.
    pub role: Role,
    _marker: PhantomData<R>,
}

#[cfg(feature = "tokenkit")]
impl<C, S, R: RoleMarker> FromRequestParts<S> for RequireRole<C, R>
where
    C: DeserializeOwned + HasRole + Send + 'static,
    S: Send + Sync,
    tokenkit::service::JwtService: axum::extract::FromRef<S>,
{
    type Rejection = AccessError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        use axum::extract::FromRef;
        let service = tokenkit::service::JwtService::from_ref(state);
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AccessError::Unauthorized("Missing token".into()))?;
        let claims: C = service
            .decode(header)
            .map_err(|e| AccessError::Unauthorized(e.to_string()))?;

        let required = R::required_role();
        if !claims.role().has_at_least(&required) {
            return Err(AccessError::Forbidden(format!(
                "Role {} does not meet the required {}",
                claims.role(),
                required,
            )));
        }

        Ok(Self {
            claims,
            role: required,
            _marker: PhantomData,
        })
    }
}

#[cfg(not(feature = "tokenkit"))]
impl<C, S, R: RoleMarker> FromRequestParts<S> for RequireRole<C, R>
where
    C: DeserializeOwned + HasRole + Send + 'static,
    S: Send + Sync,
{
    type Rejection = AccessError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Err(AccessError::Unauthorized(
            "tokenkit feature required".into(),
        ))
    }
}
