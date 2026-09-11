# Threat Model — accessctl

Reference: STRIDE. Scope: the crate's public API surface. Trust boundary:
(1) bytes/inputs entering public constructors and parsers, (2) concurrent
callers sharing interior state. accessctl is an in-process library — it opens
no sockets and inherits the embedding process's trust domain.

Purpose: Cedar-policy-backed access control (`accessctl`) — allow/deny decisions over typed principals, actions, resources; Cedar engine is feature-gated

## Assets

| ID | Asset | Exposed via |
|----|-------|-------------|
| A1 | correctness of Allow/Deny decisions | hostile input, concurrent callers |
| A2 | integrity of the loaded policy set | hostile input, concurrent callers |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Residual risk |
|---|--------|----------|---------|------------|---------------|
| T1 | Over-permissive decision on policy load failure | Tampering/DoS | `policy load path` | fail-closed: load errors disable evaluation rather than falling back to an empty policy set | documented |
| T2 | Hostile identifiers smuggled into policy scope | Spoofing | `entity inputs` | identifiers passed as Cedar entity IDs; no string interpolation into policy text | documented |
| T3 | DoS via pathological policies/requests | DoS | `evaluation entry` | Cedar engine expression-size and evaluation-step limits apply | documented |

## Repudiation

The crate keeps no audit trail; attribution of calls to callers is out of
scope for an in-process library.

## Out of Scope

- Network transport security (the crate never opens sockets).
- Storage-host compromise: an attacker who controls the host can bypass all
  in-process mitigations.
- Denial of service via resource exhaustion of the host process beyond the
  bounds enforced above.

Reviewed: 2026-09-11
