# P3 Production Evidence Custody and Signing

## Phase result

- `completed_phase_gate`: `P3`
- `run_outcome`: `COMPLETE`
- `release_verdict`: `NOT_READY`
- Real FORGE acceptance: passed
- P3 closure verifier: passed

P3 establishes production-oriented trust-domain separation for evidence custody, independent evidence-root anchoring, isolated verdict signing, and public-key lifecycle verification. It does not upgrade the complete Certification Forge product to production readiness.

## Evidence custody

The P3 custody service accepts authenticated run-scoped evidence bound to P2 runner credentials and leases. It validates tenant, run, runner, sequence, artifact identity, declared purpose, media type, size, and SHA-256. Manifests, chunks, finalizations, retention events, legal-hold events, and audits are append-only. Resumable uploads, missing chunks, duplicate chunks, sequence rollback, cross-run injection, cross-tenant reads, storage interruption, and post-anchor byte modification are tested fail-closed.

Evidence visibility is explicit: `RAW`, `REDACTED`, `PUBLIC`, or `RESTRICTED`. The accepted artifact is `RESTRICTED` and has an active legal hold.

## Independent anchoring

The anchor provider uses storage separate from the custody SQLite database. It writes signed receipts and an append-only JSONL chain, supports idempotent duplicate requests, supersession and invalidation linkage, detects altered receipts and chain state, and recovers a receipt-written/log-interrupted window. Verification requires only public material.

Accepted anchor identity (re-certified 2026-07-18 after signer image-identity fix):

- Provider: `anchor.p3.acceptance`
- Public-key ID: `ed25519:1deacb149700b3240831959d9ecf1ea6`
- Receipt ID: `anchor.3d49d3001351aba6eb62c0a397e40a83`
- Receipt SHA-256: `860b43dfef222302a186a6c1c0935c8db62dffc712d42ce70173ac1d0e5cffe4`
- Statement SHA-256: `ad78a7f1d50f5a95fb732e5c3cb48aeba3635d8da86884646b77177aa25d1bb5`
- Anchor chain tip: `0d8e27ea82e60311ef96672954c2f2bb3d0e758893024fcc6fd90405df7e8b88`

## Isolated verdict signing

The verdict signer is a separate runtime trust domain. It requires a short-lived control-plane authorization and exact run, tenant, target, environment, policy, mandatory-rule, Merkle-root, anchor-receipt, lifecycle, key, issue, and expiration identities. It refuses runner, model, Desktop, and ordinary-worker requests; replay; conflicting idempotency; unknown, revoked, expired, or compromised keys; altered roots; target/environment/policy mismatch; incomplete mandatory rules; invalid lifecycle; and unavailable key material.

The real acceptance used a pinned general-purpose Python-capable image solely as acceptance evidence:

`ghcr.io/home-assistant/home-assistant@sha256:f73512ba4fe06bb4d57636fe3578d0820cdec46f81e8f837ab59e451662ff3cb`

It ran non-root with read-only root, network `none`, all capabilities dropped, `no-new-privileges`, seccomp, AppArmor, CPU/memory/PID limits, read-only source and input mounts, and no Docker socket. This does not prove a purpose-built signer-image supply chain.

Public identities:

- Verdict key: `ed25519:d4e68fd22fab12c91a146a55a24eaa95`
- Signing-authorization key: `ed25519:3c88f9b6b9b77a1e7ac465df685522f3`
- Anchor key: `ed25519:1deacb149700b3240831959d9ecf1ea6`

The domains are distinct. Historical verification succeeds through planned rotation overlap; compromise invalidates the verdict. No private key is persisted in the signing database, evidence, public bundle, service logs, runner mounts, or repository.

## Real FORGE acceptance

Authoritative imported artifact (re-run 2026-07-18 under corrected `scripts/p3_forge_acceptance.py`):

- Path: `artifacts/p3_forge_acceptance.json`
- Bytes: `27322`
- SHA-256: `e805e6b9913a8a3712fee4710aec5d6b180b149ed2e729723bb178e7327a1ee6`
- Source identity for acceptance script: `dc733b6af0b8b7589c3e2a9c2d1d1e7e8e819bab434dae9f32e5edd2eddccc94`
- Checks: `34/34` passed
- Owned signer containers: `6/6` removed
- Unrelated containers: `22` before and `22` after; exact IDs preserved
- Custody and anchor services: stopped cleanly
- Ephemeral anchor and verdict private-key files: removed

Public-only offline material is stored in `artifacts/p3_offline_bundle/`. `scripts/verify_p3.py` validates its exact hashes and performs real offline anchor and verdict verification.

## Rootful Docker distinction

FORGE uses a rootful Docker Engine. P2 and P3 prove hardened non-root container execution and exact ownership-based cleanup on that engine. They do not prove rootless Docker, gVisor, Firecracker, or a purpose-built hostile-runner supply chain.

## Remaining product blockers

The product remains `NOT_READY` pending P4 hostile-runner and purpose-built image supply-chain qualification, trustworthy GS343/R2D2 applied-adapter identity and quality qualification, central `echo.certforge.*` registration, real deployment-path enforcement, subscriber governance and commercial controls, and resolution of hosted CI startup failure.

Hosted CI remains classified:

`CI STARTUP BLOCKER — ROOT CAUSE UNRESOLVED`
