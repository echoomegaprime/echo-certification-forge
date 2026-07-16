# Echo Certification Forge

Echo Certification Forge is a deterministic, evidence-backed release authority for EchoForge. It begins every run at `NOT_READY`, verifies exact target and environment identity, validates append-only evidence, and issues a signed verdict only through deterministic policy.

## Current phase

This repository contains the completed P1 deterministic foundation and the evidence-backed P2 runner/transport foundation:

- immutable target and environment identity;
- separate `run_outcome` and `release_verdict` contracts;
- durable SQLite run state and append-only state events;
- append-only evidence records with SHA-256, hash chaining, and Merkle roots;
- versioned mandatory-rule manifests;
- deterministic verdict calculation;
- Ed25519 signed verdict envelopes with trusted-public-key verification;
- expiration, revocation, invalidation, and supersession checks;
- exact-digest deployment-gate evaluation;
- tenant-scoped read API contracts;
- adversarial tests for missing, altered, forged, revoked, and mismatched evidence;
- short-lived Ed25519 run credentials separated from verdict signing;
- authenticated typed runner requests and signed responses;
- nonce replay prevention, idempotent retries, leases, heartbeats, cancellation, and orphan reaping;
- append-only resumable evidence chunks;
- safe archive extraction and symlink rejection;
- immutable-image container policy with non-root execution, read-only root, network denial, capability dropping, seccomp, AppArmor, and cgroup quotas;
- real FORGE acceptance for CPU, PID, disk, file-size, timeout, cancellation, crash, hostile install, tenant, archive, and evidence-interruption behavior.

This foundation does **not** claim that the full product is production-ready. The verified P2 execution plane currently uses equivalent hardened non-root containers on a rootful Docker Engine. Production signing separation, external evidence-root anchoring, hostile-runner production qualification, adapter breadth and GS343/R2D2 routing proof, central `echo.certforge.*` registration, real deployment enforcement, and subscriber productization remain gated phases.

## Development

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python scripts\p1_acceptance.py
.\.venv\Scripts\python scripts\verify_p2.py
```

## Run the read-only control-plane API

```powershell
$env:ECHO_CERTFORGE_DB = "$PWD\var\certforge.sqlite3"
$env:ECHO_CERTFORGE_EVIDENCE_ROOT = "$PWD\var\evidence"
.\.venv\Scripts\python -m uvicorn echo_certification_forge.app:app --host 127.0.0.1 --port 8400
```

The API intentionally exposes no signing-key material and no generic command execution surface.
