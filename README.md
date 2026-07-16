# Echo Certification Forge

Echo Certification Forge is a deterministic, evidence-backed release authority for EchoForge. Every run begins at `NOT_READY`. Exact target, environment, policy, evidence, anchor, key, and lifecycle identities must verify before any signed verdict can be trusted.

## Current phase

P1, P2, and P3 are complete:

- **P1:** immutable target/environment identity, append-only evidence, Merkle roots, deterministic verdicts, signed verdict envelopes, lifecycle checks, and exact-digest deploy-gate evaluation.
- **P2:** short-lived run credentials, authenticated transport, replay prevention, leases, heartbeats, resumable chunks, safe archive handling, hardened non-root runner containers, and real FORGE resource/timeout/crash acceptance.
- **P3:** authenticated append-only evidence custody, visibility and legal-hold controls, independent signed root anchoring, isolated verdict signing, public-key publication/rotation/revocation/compromise behavior, public-only offline verification material, and real FORGE failure/recovery acceptance.

Authoritative state:

```text
completed_phase_gate: P3
run_outcome: COMPLETE
release_verdict: NOT_READY
```

The complete product is not production-ready. P4 hostile-runner and purpose-built image supply-chain qualification, GS343/R2D2 applied-adapter identity and quality proof, central `echo.certforge.*` registration, real deployment-path enforcement, subscriber governance, and hosted CI resolution remain blockers.

The verified execution plane uses hardened non-root containers on a **rootful Docker Engine**. This is not a claim of rootless Docker or microVM isolation.

## P3 evidence

- Exact real-FORGE report: `artifacts/p3_forge_acceptance.json`
- Deterministic summary: `artifacts/p3_forge_acceptance.summary.json`
- Public-only offline verification bundle: `artifacts/p3_offline_bundle/`
- Evidence index: `artifacts/p3_evidence_index.json`
- Closure report: `artifacts/p3_verification_report.json`
- Phase contract: `docs/P3_PRODUCTION_EVIDENCE_CUSTODY_AND_SIGNING.md`

The full acceptance report is 27,332 bytes with SHA-256 `189cea8a577c7d60fbc57f3b30e49335ff619d182d76c50a252ef9aebdc53d27`.

## Development and verification

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q --cov=echo_certification_forge --cov-branch --cov-report=term-missing
.\.venv\Scripts\python scripts\verify_p2.py
.\.venv\Scripts\python scripts\verify_p3.py
```

## Run the read-only control-plane API

```powershell
$env:ECHO_CERTFORGE_DB = "$PWD\var\certforge.sqlite3"
$env:ECHO_CERTFORGE_EVIDENCE_ROOT = "$PWD\var\evidence"
.\.venv\Scripts\python -m uvicorn echo_certification_forge.app:app --host 127.0.0.1 --port 8400
```

The API intentionally exposes no signing-key material and no generic command-execution surface.
