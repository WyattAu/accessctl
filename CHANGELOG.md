# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/); versions follow [semver](https://semver.org).

## [Unreleased]

## 0.2.0 - 2026-11-16

- X5 pilot (ADR-0001, pattern-standards): `grants` module — a conservation-spanning
  ledger with exactly six mutating operators (issue, split, transfer,
  attenuate, revoke, merge), no setters, and a mechanically checked
  invariant `sum(active) == issued - revoked - attenuated`. Proptest
  walks (512 seeds x 250 ops) + 10,000-step deterministic soak assert
  the invariant after every step. Ships `authorize(subject, required)`
  as the first feature on the operator surface. Version bump: new pub API.

## [0.1.0] - 2026-09-01

### Added
- Role-based access control; Cedar policy engine integration.
- Published to crates.io (2026-09-01).
