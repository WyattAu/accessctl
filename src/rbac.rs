use std::fmt;

/// Roles in the RBAC system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Role {
    /// Read-only access.
    Viewer,
    /// Read and write access.
    Editor,
    /// Full administrative access.
    Admin,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Viewer => write!(f, "Viewer"),
            Role::Editor => write!(f, "Editor"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

impl Role {
    /// Returns true if `self` has at least the privileges of `other`.
    pub fn has_at_least(&self, other: &Role) -> bool {
        self >= other
    }

    /// Cedar entity type name for this role.
    pub fn cedar_type_name(&self) -> &'static str {
        match self {
            Role::Viewer => "ViewerRole",
            Role::Editor => "EditorRole",
            Role::Admin => "AdminRole",
        }
    }
}

/// Role hierarchy with permission resolution.
#[allow(dead_code)]
pub struct RoleHierarchy {
    roles: Vec<Role>,
}

impl Default for RoleHierarchy {
    fn default() -> Self {
        Self { roles: vec![Role::Viewer, Role::Editor, Role::Admin] }
    }
}

impl RoleHierarchy {
    /// Creates a new role hierarchy with default roles.
    pub fn new() -> Self { Self::default() }

    /// Check if a role has permission for an action.
    pub fn check_permission(&self, role: &Role, action: &str) -> bool {
        match (role, action) {
            (Role::Admin, _) => true,
            (Role::Editor, "view" | "edit" | "create") => true,
            (Role::Viewer, "view") => true,
            _ => false,
        }
    }
}

/// Cedar policy set generated from role hierarchy.
pub struct PolicySet {
    inner: cedar_policy::PolicySet,
}

impl PolicySet {
    /// Create a policy set from the default role hierarchy.
    pub fn from_default_hierarchy() -> Result<Self, crate::AccessError> {
        let mut ps = cedar_policy::PolicySet::new();

        // Admin can do everything
        let admin_policy = cedar_policy::Policy::parse(
            Some(cedar_policy::PolicyId::new("admin-permit")),
            r#"permit(principal in AdminRole::"", action, resource);"#,
        ).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;
        ps.add(admin_policy).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;

        // Editor can view, edit, create
        let editor_policy = cedar_policy::Policy::parse(
            Some(cedar_policy::PolicyId::new("editor-permit")),
            r#"permit(principal in EditorRole::"", action in [Action::"view", Action::"edit", Action::"create"], resource);"#,
        ).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;
        ps.add(editor_policy).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;

        // Viewer can only view
        let viewer_policy = cedar_policy::Policy::parse(
            Some(cedar_policy::PolicyId::new("viewer-permit")),
            r#"permit(principal in ViewerRole::"", action == Action::"view", resource);"#,
        ).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;
        ps.add(viewer_policy).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;

        Ok(Self { inner: ps })
    }

    /// Returns the inner Cedar policy set.
    pub fn inner(&self) -> &cedar_policy::PolicySet { &self.inner }
}
