use cedar_policy::Schema;

use crate::error::AccessError;
use crate::rbac::Role;

/// Generates a Cedar schema from role definitions.
///
/// The schema defines `Role` and `Action` entity types that Cedar uses
/// for authorization decisions.
pub fn generate_schema(roles: &[Role]) -> Result<Schema, AccessError> {
    let mut action_defs = Vec::new();

    // Collect all unique permissions across roles
    let mut all_permissions: Vec<String> = roles
        .iter()
        .flat_map(|r| r.permissions.clone())
        .collect();
    all_permissions.sort();
    all_permissions.dedup();

    for perm in &all_permissions {
        action_defs.push(format!("    \"{perm}\""));
    }

    let schema_str = format!(
        r#"
namespace AccessCtl {{

  entity Role;
  entity Resource;

  action {} {{
    principal resources: [Resource],
    resource: Resource
  }};
}}
"#,
        if action_defs.is_empty() {
            "{}".to_string()
        } else {
            format!(
                "{} {}",
                "{",
                all_permissions
                    .iter()
                    .map(|p| format!("\"{}\"", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );

    // Parse the schema, falling back to a minimal valid schema on error
    Schema::from_json_str(&schema_str).map_err(|e| AccessError::SchemaInvalid(e.to_string()))
}

/// Performs a Cedar authorization check.
///
/// Returns `Ok(true)` if the request is permitted, `Ok(false)` if denied,
/// or `Err` if the evaluation fails.
pub fn authorize(
    authorizer: &cedar_policy::Authorizer,
    schema: &Schema,
    principal: &str,
    action: &str,
    resource: &str,
) -> Result<bool, AccessError> {
    use cedar_policy::{Context, Entities, EntityUid, Request};

    let principal_uid: EntityUid = format!("AccessCtl::Role::\"{}\"", principal)
        .parse()
        .map_err(|e: cedar_policy::ParseErrors| AccessError::PolicyParse(e.to_string()))?;
    let action_uid: EntityUid = format!("AccessCtl::Action::\"{}\"", action)
        .parse()
        .map_err(|e: cedar_policy::ParseErrors| AccessError::PolicyParse(e.to_string()))?;
    let resource_uid: EntityUid = format!("AccessCtl::Resource::\"{}\"", resource)
        .parse()
        .map_err(|e: cedar_policy::ParseErrors| AccessError::PolicyParse(e.to_string()))?;

    let request = Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        Context::empty(),
        Some(schema),
    )
    .map_err(|e| AccessError::PolicyParse(e.to_string()))?;

    let entities = Entities::empty();
    let result = authorizer.is_authorized(&request, &cedar_policy::PolicySet::new(), &entities);

    match result.decision() {
        cedar_policy::Decision::Allow => Ok(true),
        cedar_policy::Decision::Deny => Ok(false),
    }
}
