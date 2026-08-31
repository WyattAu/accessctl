#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(dead_code)]

//! Role-based access control for Rust with Cedar policy engine integration.

mod error;
mod rbac;
mod cedar;

pub use error::AccessError;
pub use rbac::{Role, RoleHierarchy, PolicySet};

/// Axum middleware for role-based access control.
#[cfg(feature = "axum")]
pub mod middleware;
