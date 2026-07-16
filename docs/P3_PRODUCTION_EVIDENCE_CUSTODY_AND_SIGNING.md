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

Accepted anchor identity:

- Provider: `anchor.p3.acceptance`
- Public-key ID: `ed25519:cdad8d031374653b7c1489feaf39c4ef`
- Receipt ID: `anchor.095f5d407cb768340fd52b065cba56e6`
- Receipt SHA-256: `f3bdb7a16993924cc7a1145b023d9f5ac69d2c5aef1a62b1b604b1f897dcd3ac`
- Statement SHA-256: `eb96857e35e64e68c949fda668fdee8a5d68cadf3b1b901f97fc40b19301ef72`
- Anchor chain tip: `4b59c9b24ec0557da6e865c57ad16fe7662e0a5e9deff45fb34294983c3aa82a`

## Isolated verdict signing

The verdict signer is a separate runtime trust domain. It requires a short-lived control-plane authorization and exact run, tenant, target, environment, policy, mandatory-rule, Merkle-root, anchor-receipt, lifecycle, key, issue, and expiration identities. It refuses runner, model, Desktop, and ordinary-worker requests; replay; conflicting idempotency; unknown, revoked, expired, or compromised keys; altered roots; target/environment/policy mismatch; incomplete mandatory rules; invalid lifecycle; and unavailable key material.

The real acceptance used a pinned general-purpose Python-capable image solely as acceptance evidence:

`ghcr.io/home-assistant/home-assistant@sha256:f73512ba4fe06bb4d57636fe3578d0820cdec46f81e8f837ab59e451662ff3cb`

It ran non-root with read-only root, network `none`, all capabilities dropped, `no-new-privileges`, seccomp, AppArmor, CPU/memory/PID limits, read-only source and input mounts, and no Docker socket. This does not prove a purpose-built signer-image supply chain.

Public identities:

- Verdict key: `ed25519:a574dd0fee97965ad65b6777d3efe137`
- Signing-authorization key: `ed25519:96b682f0c3aee75a5ef97db427062900`
- Anchor key: `ed25519:cdad8d031374653b7c1489feaf39c4ef`

The domains are distinct. Historical verification succeeds through planned rotation overlap; compromise invalidates the verdict. No private key is persisted in the signing database, evidence, public bundle, service logs, runner mounts, or repository.

## Real FORGE acceptance

Authoritative imported artifact:

- Path: `artifacts/p3_forge_acceptance.json`
- Bytes: `27332`
- SHA-256: `189cea8a577c7d60fbc57f3b30e49335ff619d182d76c50a252ef9aebdc53d27`
- Checks: `34/34` passed
- Owned signer containers: `6/6` removed
- Unrelated containers: `21` before and `21` after; exact IDs preserved
- Custody and anchor services: stopped cleanly
- Ephemeral anchor and verdict private-key files: removed

Public-only offline material is stored in `artifacts/p3_offline_bundle/`. `scripts/verify_p3.py` validates its exact hashes and performs real offline anchor and verdict verification.

## Rootful Docker distinction

FORGE uses a rootful Docker Engine. P2 and P3 prove hardened non-root container execution and exact ownership-based cleanup on that engine. They do not prove rootless Docker, gVisor, Firecracker, or a purpose-built hostile-runner supply chain.

## Remaining product blockers

The product remains `NOT_READY` pending P4 hostile-runner and purpose-built image supply-chain qualification, trustworthy GS343/R2D2 applied-adapter identity and quality qualification, central `echo.certforge.*` registration, real deployment-path enforcement, subscriber governance and commercial controls, and resolution of hosted CI startup failure.

Hosted CI remains classified:

`CI STARTUP BLOCKER — ROOT CAUSE UNRESOLVED`
