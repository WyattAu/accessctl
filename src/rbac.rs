use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A role in the access control system with associated permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier for this role (e.g., "admin", "editor", "viewer").
    pub name: String,
    /// Permissions granted by this role (e.g., "read", "write", "delete").
    pub permissions: Vec<String>,
    /// Optional parent roles this role inherits from.
    pub parents: Vec<String>,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Role {
    /// Creates a new role with no parents.
    pub fn new(name: impl Into<String>, permissions: Vec<String>) -> Self {
        Self {
            name: name.into(),
            permissions,
            parents: Vec::new(),
        }
    }

    /// Sets the parent roles for inheritance.
    pub fn with_parents(mut self, parents: Vec<String>) -> Self {
        self.parents = parents;
        self
    }
}

/// Role hierarchy for resolving inherited permissions.
pub struct RoleHierarchy {
    roles: HashMap<String, Role>,
}

impl RoleHierarchy {
    /// Creates a new role hierarchy from a list of roles.
    pub fn new(roles: Vec<Role>) -> Self {
        let roles_map = roles.into_iter().map(|r| (r.name.clone(), r)).collect();
        Self { roles: roles_map }
    }

    /// Resolves all permissions for a role, including inherited permissions.
    pub fn resolve_permissions(&self, role_name: &str) -> Vec<String> {
        let mut permissions = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.resolve_permissions_inner(role_name, &mut permissions, &mut visited);
        permissions.sort();
        permissions.dedup();
        permissions
    }

    fn resolve_permissions_inner(
        &self,
        role_name: &str,
        permissions: &mut Vec<String>,
        visited: &mut std::collections::HashSet<String>,
    ) {
        if !visited.insert(role_name.to_string()) {
            return;
        }

        if let Some(role) = self.roles.get(role_name) {
            permissions.extend(role.permissions.clone());
            for parent in &role.parents {
                self.resolve_permissions_inner(parent, permissions, visited);
            }
        }
    }

    /// Checks whether a role has a specific permission (including inherited).
    pub fn has_permission(&self, role_name: &str, permission: &str) -> bool {
        self.resolve_permissions(role_name)
            .iter()
            .any(|p| p == permission)
    }
}

/// A policy set for Cedar policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    policies: Vec<String>,
}

impl PolicySet {
    /// Creates an empty policy set.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Creates a policy set from existing Cedar policy strings.
    pub fn from_policies(policies: Vec<String>) -> Self {
        Self { policies }
    }

    /// Adds a Cedar policy to the set.
    pub fn add_policy(&mut self, policy: String) {
        self.policies.push(policy);
    }

    /// Generates Cedar policy strings from a role hierarchy.
    ///
    /// Each role becomes a Cedar policy allowing its permissions on its entity.
    pub fn from_role_hierarchy(hierarchy: &RoleHierarchy, roles: &[Role]) -> Self {
        let mut policies = Vec::new();

        for role in roles {
            let permissions = hierarchy.resolve_permissions(&role.name);
            for perm in &permissions {
                policies.push(format!(
                    r#"permit(principal == Role::"{role}", action == Action::"{perm}", resource);"#
                ));
            }
        }

        Self { policies }
    }

    /// Returns the policy strings.
    pub fn policies(&self) -> &[String] {
        &self.policies
    }
}

impl Default for PolicySet {
    fn default() -> Self {
        Self::new()
    }
}
