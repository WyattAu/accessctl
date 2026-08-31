use thiserror::Error;

/// Errors that can occur in access control operations.
#[derive(Debug, Error)]
pub enum AccessError {
    /// The request lacks valid authentication.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    /// The authenticated principal lacks required permissions.
    #[error("Forbidden: {0}")]
    Forbidden(String),
    /// Failed to parse a Cedar policy.
    #[error("Policy parse error: {0}")]
    PolicyParse(String),
    /// The Cedar schema is invalid.
    #[error("Schema invalid: {0}")]
    SchemaInvalid(String),
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AccessError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;
        use serde_json::json;
        let (status, message) = match &self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
