# accessctl

Role-based access control for Rust — Cedar policy engine integration with typed roles and Axum middleware.

## Purpose

`accessctl` provides a typed RBAC system backed by the [Cedar](https://www.cedarpolicy.com/) policy engine.
It lets you define roles with hierarchical permissions, generate Cedar policies automatically,
and enforce access control in Axum applications via middleware and extractors.

## Cedar Integration

Cedar is an open-source policy language for authorization. `accessctl` generates Cedar schemas
from your Rust role definitions, allowing you to:

- Define roles as Rust types (not strings)
- Automatically generate Cedar policies from role hierarchies
- Evaluate authorization decisions using Cedar's authorizer
- Leverage Cedar's formal verification guarantees

## Features

- **`cedar`** (default) — Cedar policy engine integration
- **`axum`** — Axum middleware and extractors (`RequireRole`)
- **`tokenkit`** — Integration with the `tokenkit` crate

## Usage

### Define Roles

```rust
use accessctl::rbac::{Role, RoleHierarchy};

let roles = vec![
    Role::new("admin", vec!["read".into(), "write".into(), "delete".into()]),
    Role::new("editor", vec!["read".into(), "write".into()])
        .with_parents(vec!["viewer".into()]),
    Role::new("viewer", vec!["read".into()]),
];

let hierarchy = RoleHierarchy::new(roles);

assert!(hierarchy.has_permission("admin", "delete"));
assert!(hierarchy.has_permission("editor", "read")); // inherited from viewer
assert!(!hierarchy.has_permission("viewer", "write"));
```

### Authorize with Cedar

```rust
use accessctl::AccessCtl;

let access_ctl = AccessCtl::new(roles)?;
let allowed = accessctl::cedar::authorize(
    access_ctl.authorizer(),
    access_ctl.schema(),
    "admin",
    "read",
    "document-1",
)?;

assert!(allowed);
```

### Generate Policies

```rust
use accessctl::rbac::{PolicySet, RoleHierarchy};

let policies = PolicySet::from_role_hierarchy(&hierarchy, &roles);
for policy in policies.policies() {
    println!("{}", policy);
}
```

### Axum Middleware

```rust
use accessctl::middleware::require_role_middleware;

let router = Router::new()
    .route("/admin", get(admin_handler))
    .layer(middleware::from_fn_with_state(
        Arc::new(hierarchy),
        require_role_middleware,
    ));
```

## License

MIT OR Apache-2.0
