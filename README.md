# Echo Certification Forge

Echo Certification Forge is a deterministic, evidence-backed release authority for EchoForge. It begins every run at `NOT_READY`, verifies exact target and environment identity, validates append-only evidence, and issues a signed verdict only through deterministic policy.

## Current phase

This repository contains the hardened foundation gate:

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
- adversarial tests for missing, altered, forged, revoked, and mismatched evidence.

This foundation does **not** claim that the full product is production-ready. Isolated runner execution, authenticated worker transport, adapter breadth, GS343/R2D2 qualification, external evidence-root anchoring, and subscriber productization remain gated phases.

## Development

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python scripts\p1_acceptance.py
```

## Run the read-only control-plane API

```powershell
$env:ECHO_CERTFORGE_DB = "$PWD\var\certforge.sqlite3"
$env:ECHO_CERTFORGE_EVIDENCE_ROOT = "$PWD\var\evidence"
.\.venv\Scripts\python -m uvicorn echo_certification_forge.app:app --host 127.0.0.1 --port 8400
```

The API intentionally exposes no signing-key material and no generic command execution surface.
