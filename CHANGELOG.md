# Changelog

## [1.2.0] - 2026-08-30

### Added

- A pinned-key-signed production E2E gate required before any `PRODUCTION_READY` verdict.
- Exact E2E bindings for source, deployment, target, environment, accounts, and clients.

All notable changes to Echo Certification Forge are documented here. Versions follow Semantic
Versioning; dates use ISO 8601.

## [Unreleased]

### Added

- Return secret-safe public target and production-E2E projections plus the canonical environment
  identity from the public verification endpoint, bind each projection to a dedicated digest in
  the signed verdict, and fail the public result closed on any serialization mismatch.
- Publish only signed aggregate production-E2E outcomes; raw accounts, private repository samples,
  credential routes, and client fingerprints remain in the private evidence record.
- Require a bounded, credential-free HTTPS canonical target for generic production-E2E proofs.
- Reject credential-bearing Git source URLs before acquisition, and add exact three-account
  Autonomy plus four-client Continuity production-E2E profiles.

### Changed

- Allow operators to select a validated 128 MiB to 4 GiB journey cgroup while preserving no-swap
  containment, and record the effective memory, CPU, PID, and scratch limits in journey evidence.
- Bind the exact sandbox image digest and resource profile into the certification environment identity.

## [1.1.0] - 2026-08-09

### Added

- Fail-closed, deterministic SVG repository certificate rendering.
- Exact bindings to the source commit, signed Cert Forge evidence, and 8/8 GitHub App Suite receipt.
- Self-contained premium certificate art with visual ECHO OMEGA PRIME and Bob McWilliams II sign-offs.
- Machine-readable integrity manifests carrying canonical payload and rendered-graphic SHA-256 values.
- `echo-cert-graphic` command and negative-path coverage for incomplete or malformed evidence.
- Repository-level opt-in for all eight ECHO GitHub Apps and a drift-tested 60-capability SDK manifest.

## [1.0.0] - 2026-08-08

### Added

- Production Certification Forge service, signed verdicts, evidence custody, strict release gate,
  subscriber governance, exact-source product readiness, and staging-first deployment support.
