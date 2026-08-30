use thiserror::Error;

/// Errors that can occur in access control operations.
#[derive(Debug, Error)]
pub enum AccessError {
    /// The request lacks valid authentication.
    #[error("unauthorized")]
    Unauthorized,

    /// The authenticated principal lacks required permissions.
    #[error("forbidden")]
    Forbidden,

    /// Failed to parse a Cedar policy.
    #[error("policy parse error: {0}")]
    PolicyParse(String),

    /// The Cedar schema is invalid.
    #[error("invalid schema: {0}")]
    SchemaInvalid(String),
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AccessError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::PolicyParse(_) | Self::SchemaInvalid(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = axum::Json(serde_json::json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}
