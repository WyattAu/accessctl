use criterion::{criterion_group, criterion_main, Criterion};
use accessctl::{Role, RoleHierarchy, PolicySet};

fn bench_role_ordering(c: &mut Criterion) {
    c.bench_function("role_ordering", |b| {
        b.iter(|| {
            let _ = Role::Viewer < Role::Editor;
            let _ = Role::Editor < Role::Admin;
            let _ = Role::Viewer < Role::Admin;
        });
    });
}

fn bench_role_has_at_least(c: &mut Criterion) {
    c.bench_function("role_has_at_least", |b| {
        b.iter(|| {
            let _ = Role::Admin.has_at_least(&Role::Viewer);
            let _ = Role::Admin.has_at_least(&Role::Editor);
            let _ = Role::Viewer.has_at_least(&Role::Admin);
        });
    });
}

fn bench_role_cedar_type_name(c: &mut Criterion) {
    c.bench_function("role_cedar_type_name", |b| {
        b.iter(|| {
            let _ = Role::Viewer.cedar_type_name();
            let _ = Role::Editor.cedar_type_name();
            let _ = Role::Admin.cedar_type_name();
        });
    });
}

fn bench_role_hierarchy_creation(c: &mut Criterion) {
    c.bench_function("role_hierarchy_creation", |b| {
        b.iter(|| RoleHierarchy::new());
    });
}

fn bench_role_hierarchy_check_permission(c: &mut Criterion) {
    let h = RoleHierarchy::new();
    c.bench_function("role_hierarchy_check_permission", |b| {
        b.iter(|| {
            let _ = h.check_permission(&Role::Admin, "delete");
            let _ = h.check_permission(&Role::Editor, "edit");
            let _ = h.check_permission(&Role::Viewer, "view");
        });
    });
}

fn bench_policy_set_creation(c: &mut Criterion) {
    c.bench_function("policy_set_creation", |b| {
        b.iter(|| PolicySet::from_default_hierarchy().unwrap());
    });
}

fn bench_policy_set_inner(c: &mut Criterion) {
    let policy_set = PolicySet::from_default_hierarchy().unwrap();
    c.bench_function("policy_set_inner", |b| {
        b.iter(|| policy_set.inner());
    });
}

fn bench_role_display(c: &mut Criterion) {
    c.bench_function("role_display", |b| {
        b.iter(|| {
            let _ = format!("{}", Role::Viewer);
            let _ = format!("{}", Role::Editor);
            let _ = format!("{}", Role::Admin);
        });
    });
}

fn bench_role_serialize(c: &mut Criterion) {
    c.bench_function("role_serialize", |b| {
        b.iter(|| {
            let _ = serde_json::to_string(&Role::Admin).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_role_ordering,
    bench_role_has_at_least,
    bench_role_cedar_type_name,
    bench_role_hierarchy_creation,
    bench_role_hierarchy_check_permission,
    bench_policy_set_creation,
    bench_policy_set_inner,
    bench_role_display,
    bench_role_serialize,
);
criterion_main!(benches);
