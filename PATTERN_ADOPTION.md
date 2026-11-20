# Pattern adoption

Declaration format: pattern-standards `references/adoption-format.md`.
Validated by `pattern-standards/scripts/adoption-check.py`.

| Pattern | Status | Evidence |
|---|---|---|
| T13 | adopted | src/lib.rs (rbac/cedar pure cores; middleware is the imperative shell) |
| X5 | partial | src/grants.rs (six conservation-spanning operators; ADR-0001 pilot, criteria 1-2 green) |
| T36 | partial | .github/workflows/nightly-soak.yml (nightly property soak wired; deterministic seeds) |
| P41 | n/a | canon baseline line names this repo; code shows no implementation of P41: a policy library (src/rbac.rs, src/cedar.rs, src/grants.rs, src/middleware.rs) with no tenant scope, RLS binding, or database surface; tenant scope injection is a consumer concern |
