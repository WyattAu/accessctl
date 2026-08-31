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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ordering() {
        assert!(Role::Viewer < Role::Editor);
        assert!(Role::Editor < Role::Admin);
        assert!(Role::Viewer < Role::Admin);
        assert!(Role::Viewer == Role::Viewer);
    }

    #[test]
    fn cedar_type_names() {
        assert_eq!(Role::Viewer.cedar_type_name(), "ViewerRole");
        assert_eq!(Role::Editor.cedar_type_name(), "EditorRole");
        assert_eq!(Role::Admin.cedar_type_name(), "AdminRole");
    }

    #[test]
    fn has_at_least() {
        assert!(Role::Admin.has_at_least(&Role::Viewer));
        assert!(Role::Admin.has_at_least(&Role::Editor));
        assert!(Role::Admin.has_at_least(&Role::Admin));
        assert!(Role::Editor.has_at_least(&Role::Viewer));
        assert!(!Role::Viewer.has_at_least(&Role::Editor));
        assert!(!Role::Viewer.has_at_least(&Role::Admin));
    }

    #[test]
    fn role_hierarchy_permission_admin() {
        let h = RoleHierarchy::new();
        assert!(h.check_permission(&Role::Admin, "delete"));
        assert!(h.check_permission(&Role::Admin, "view"));
        assert!(h.check_permission(&Role::Admin, "anything"));
    }

    #[test]
    fn role_hierarchy_permission_viewer() {
        let h = RoleHierarchy::new();
        assert!(h.check_permission(&Role::Viewer, "view"));
        assert!(!h.check_permission(&Role::Viewer, "delete"));
        assert!(!h.check_permission(&Role::Viewer, "edit"));
    }

    #[test]
    fn access_error_display() {
        let e = AccessError::Unauthorized("missing token".into());
        assert!(e.to_string().contains("Unauthorized"));
        assert!(e.to_string().contains("missing token"));

        let e = AccessError::Forbidden("insufficient role".into());
        assert!(e.to_string().contains("Forbidden"));
        assert!(e.to_string().contains("insufficient role"));
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_role() -> impl Strategy<Value = Role> {
        prop_oneof![
            Just(Role::Viewer),
            Just(Role::Editor),
            Just(Role::Admin),
        ]
    }

    proptest! {
        #[test]
        fn role_ordering(a in arb_role(), b in arb_role()) {
            // Reflexivity: every role has_at_least itself
            prop_assert!(a.has_at_least(&a));
            // If a > b, then a has_at_least b
            if a > b {
                prop_assert!(a.has_at_least(&b));
            }
            // Consistency with PartialOrd
            prop_assert_eq!(a > b, a.has_at_least(&b) && a != b);
        }

        #[test]
        fn role_cedar_type_name(role in arb_role()) {
            let name = role.cedar_type_name();
            prop_assert!(!name.is_empty());
            prop_assert!(name.ends_with("Role"));
        }

        #[test]
        fn policy_set_creation(_dummy in 0..1u32) {
            let result = PolicySet::from_default_hierarchy();
            prop_assert!(result.is_ok());
        }
    }
}
