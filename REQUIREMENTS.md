# Requirements — accessctl

Numbered, testable requirements. Every requirement maps to at least one named
test or doc-comment contract; security-relevant items cite threat-model rows.

Scope: Cedar-policy-backed access control (`accessctl`) — allow/deny decisions over typed principals, actions, resources; Cedar engine is feature-gated

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-AC-001 | Policy evaluation returns Allow/Deny deterministically for a fixed policy set and request | MUST |
| REQ-AC-002 | Evaluation errors (malformed policy, unknown entity) return typed errors, never panics | MUST |
| REQ-AC-003 | The Cedar integration compiles only with the `cedar` feature; default builds pass without it | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-AC-100 | Deny-by-default when policies fail to load or evaluate (fail-closed) | MUST |
| REQ-AC-101 | Principal/action/resource identifiers enter Cedar as validated entity identifiers, never interpolated into policy text | MUST |

## Observability & API hygiene

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-AC-900 | All fallible public APIs return typed errors; production `unwrap`/`expect` is denied or explicitly justified with an invariant comment | MUST |
| REQ-AC-901 | Public items carry doc comments with runnable examples where practical | SHOULD |
