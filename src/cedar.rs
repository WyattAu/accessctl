use cedar_policy::{Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request};
use std::str::FromStr;
use std::collections::{HashMap, HashSet};

use crate::rbac::Role;

#[allow(dead_code)]
/// Generate Cedar schema string for the RBAC model.
pub fn generate_schema() -> &'static str {
    r#"
    namespace AccessCtl {
        entity AdminRole {};
        entity EditorRole {};
        entity ViewerRole {};
        entity User {
            role: AdminRole | EditorRole | ViewerRole,
        };
        entity Resource {};
        action "view" appliesTo {
            principal: [AdminRole, EditorRole, ViewerRole],
            resource: Resource,
        };
        action "edit" appliesTo {
            principal: [AdminRole, EditorRole],
            resource: Resource,
        };
        action "create" appliesTo {
            principal: [AdminRole, EditorRole],
            resource: Resource,
        };
        action "delete" appliesTo {
            principal: [AdminRole],
            resource: Resource,
        };
    }
    "#
}

/// Create Cedar entities for a user with a role.
pub fn create_entities(user_id: &str, role: &Role) -> Result<Entities, crate::AccessError> {
    let role_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(role.cedar_type_name())
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        EntityId::from_str(user_id)
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
    );

    let user_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User")
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        EntityId::from_str(user_id)
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
    );

    let mut parents = HashSet::new();
    parents.insert(role_uid);

    let user_entity = Entity::new(user_uid, HashMap::new(), parents)
        .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?;

    let role_entity = Entity::new(
        EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(role.cedar_type_name())
                .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
            EntityId::from_str(user_id)
                .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        ),
        HashMap::new(),
        HashSet::new(),
    ).map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?;

    let resource_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Resource")
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        EntityId::from_str("*")
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
    );
    let resource_entity = Entity::new(resource_uid, HashMap::new(), HashSet::new())
        .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?;

    Entities::from_entities(
        vec![user_entity, role_entity, resource_entity],
        None,
    ).map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))
}

/// Authorize a request against the policy set.
pub fn authorize(
    user_id: &str,
    role: &Role,
    action: &str,
    resource_id: &str,
    policy_set: &crate::rbac::PolicySet,
) -> Result<bool, crate::AccessError> {
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User")
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        EntityId::from_str(user_id)
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
    );
    let action_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action")
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        EntityId::from_str(action)
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
    );
    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Resource")
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
        EntityId::from_str(resource_id)
            .map_err(|e| crate::AccessError::SchemaInvalid(e.to_string()))?,
    );

    let request = Request::new(
        principal,
        action_uid,
        resource,
        Context::empty(),
        None,
    ).map_err(|e| crate::AccessError::PolicyParse(e.to_string()))?;

    let entities = create_entities(user_id, role)?;

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, policy_set.inner(), &entities);

    Ok(matches!(response.decision(), Decision::Allow))
}
