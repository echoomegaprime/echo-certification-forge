# Echo Certification Forge

Echo Certification Forge is a deterministic, evidence-backed release authority for EchoForge. Every run begins at `NOT_READY`. Exact target, environment, policy, evidence, anchor, key, and lifecycle identities must verify before any signed verdict can be trusted.

## Current phase

P1, P2, P3, and P4 are complete:

- **P1:** immutable target/environment identity, append-only evidence, Merkle roots, deterministic verdicts, signed verdict envelopes, lifecycle checks, and exact-digest deploy-gate evaluation.
- **P2:** short-lived run credentials, authenticated transport, replay prevention, leases, heartbeats, resumable chunks, safe archive handling, hardened non-root runner containers, and real FORGE resource/timeout/crash acceptance.
- **P3:** authenticated append-only evidence custody, visibility and legal-hold controls, independent signed root anchoring, isolated verdict signing, public-key publication/rotation/revocation/compromise behavior, public-only offline verification material, and real FORGE failure/recovery acceptance.
- **P4:** purpose-built role images, sealed twelve-image supply-chain identities, independent builds, vulnerability/malware scans, signatures, hostile runtime matrix, service lifecycle, public-only verifier containment, and purpose-built signer regression on FORGE.

Authoritative state:

```text
completed_phase_gate: P4
run_outcome: COMPLETE
release_verdict: NOT_READY
```

The complete product is not production-ready. GS343/R2D2 applied-adapter identity and quality proof, central `echo.certforge.*` registration, real deployment-path enforcement, subscriber governance, and hosted CI resolution remain blockers.

The verified execution plane uses hardened non-root containers on a **rootful Docker Engine**. This is not a claim of rootless Docker or microVM isolation.

## P3 evidence

- Exact real-FORGE report: `artifacts/p3_forge_acceptance.json`
- Deterministic summary: `artifacts/p3_forge_acceptance.summary.json`
- Public-only offline verification bundle: `artifacts/p3_offline_bundle/`
- Evidence index: `artifacts/p3_evidence_index.json`
- Closure report: `artifacts/p3_verification_report.json`
- Phase contract: `docs/P3_PRODUCTION_EVIDENCE_CUSTODY_AND_SIGNING.md`

The full acceptance report is 27,322 bytes with SHA-256 `e805e6b9913a8a3712fee4710aec5d6b180b149ed2e729723bb178e7327a1ee6` (re-certified 2026-07-18 after signer image-identity fix).

## P4 evidence

- Exact real-FORGE hostile acceptance (rerun6): `artifacts/p4_forge_acceptance.json`
- Sealed twelve-image manifest: `artifacts/p4_images/manifest.json`
- Evidence index: `artifacts/p4_evidence_index.json`
- Hardening verification: `artifacts/p4_hardening_verification.json`
- Closure report: `artifacts/p4_verification_report.json`
- Rerun result write-up: `docs/P4_RERUN6_RESULT.md`
- Phase contract: `docs/P4_HOSTILE_RUNNER_AND_IMAGE_SUPPLY_CHAIN.md`

The rerun6 acceptance report is 124,342 bytes with SHA-256 `c7b5031265883386b7b0df6409600dd51a622a796ccdd75abd221c0e373b4c56`.
The sealed image manifest SHA-256 is `bc86b3ce849d7da82a4378cc2d3693d44e04604d2b1288d740c066408c802c8a`.

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
