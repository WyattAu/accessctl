#![forbid(unsafe_code)]

//! Role-based access control for Rust.
//!
//! `accessctl` provides a typed role system backed by Cedar policy engine,
//! with optional Axum middleware integration.

pub mod cedar;
pub mod error;
pub mod rbac;

#[cfg(feature = "axum")]
pub mod middleware;

use cedar_policy::{Authorizer, Schema};
pub use error::AccessError;
pub use rbac::{PolicySet, Role};

/// Core access control structure holding the Cedar authorizer and schema.
pub struct AccessCtl {
    authorizer: Authorizer,
    schema: Schema,
    roles: Vec<Role>,
}

impl AccessCtl {
    /// Creates a new `AccessCtl` instance from a set of roles.
    pub fn new(roles: Vec<Role>) -> Result<Self, AccessError> {
        let schema = cedar::generate_schema(&roles)?;
        let authorizer = Authorizer::new();

        Ok(Self {
            authorizer,
            schema,
            roles,
        })
    }

    /// Returns a reference to the Cedar authorizer.
    pub fn authorizer(&self) -> &Authorizer {
        &self.authorizer
    }

    /// Returns a reference to the Cedar schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Returns the configured roles.
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }
}
