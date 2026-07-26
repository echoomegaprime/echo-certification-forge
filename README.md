# Echo Certification Forge

Echo Certification Forge is a deterministic, evidence-backed release authority for EchoForge. Every run begins at `NOT_READY`. Exact target, environment, policy, evidence, anchor, key, and lifecycle identities must verify before any signed verdict can be trusted.

## Release state

P1 through P7, the 60-capability SDK contract, and the SPEC §48 master-acceptance
implementation are present in this repository:

- **P1:** immutable target/environment identity, append-only evidence, Merkle roots, deterministic verdicts, signed verdict envelopes, lifecycle checks, and exact-digest deploy-gate evaluation.
- **P2:** short-lived run credentials, authenticated transport, replay prevention, leases, heartbeats, resumable chunks, safe archive handling, hardened non-root runner containers, and real FORGE resource/timeout/crash acceptance.
- **P3:** authenticated append-only evidence custody, visibility and legal-hold controls, independent signed root anchoring, isolated verdict signing, public-key publication/rotation/revocation/compromise behavior, public-only offline verification material, and real FORGE failure/recovery acceptance.
- **P4:** purpose-built role images, sealed twelve-image supply-chain identities, independent builds, vulnerability/malware scans, signatures, hostile runtime matrix, service lifecycle, public-only verifier containment, and purpose-built signer regression on FORGE.
- **P7:** tenant-isolated organizations/projects/users, role-and-scope authorization, API-key and resource revocation, plan quotas and global abuse controls, billing/subscription enforcement, append-only hash-chained audit, governed intake, and versioned subscriber policy/contract.
- **Master acceptance:** a committed deliberately imperfect multi-service target exercises discovery,
  classified defects, an ephemeral repaired test harness, real Docker execution, evidence custody,
  and an independently verified signed `NOT_READY` verdict for the target.

Whole-product readiness is never hard-coded. The public `/v1/status` surface returns
`NOT_READY` unless `scripts/master_acceptance.py` has verified every phase, the exact 60-capability
SDK contract, successful hosted CI for the exact source SHA, and the real Docker master journey,
then signed a non-expired attestation for that same SHA. Production loads only the public trust
root and rejects missing, stale, tampered, untrusted, or wrong-commit reports.

The authoritative deployed state is always:

```text
GET https://cert-api.echosforge.com/v1/status
```

The verified execution plane uses hardened non-root containers on a **rootful Docker Engine**. This is not a claim of rootless Docker or microVM isolation.

## Final master acceptance

`scripts/master_acceptance.py` consumes the exact phase, adapter, SDK, and hosted-CI evidence,
runs `acceptance/master-imperfect-app` in Docker, and emits `product-readiness.json`. The deploy
gate independently verifies that signed report against the fetched commit before staging starts;
staging and production smoke both require the exact-source `PRODUCTION_READY` state.

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

## P7 evidence

- Executable acceptance: `python scripts/p7_acceptance.py`
- Acceptance report: `artifacts/p7_acceptance_report.json`
- Subscriber policy: `policies/subscriber-governance.v1.json`
- Subscriber API/authorization contract: `contracts/subscriber-governance.v1.json`
- Targeted suite: `tests/test_p7_subscriber_governance.py`

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

## SDK capability contract

The checked contract at `contracts/certforge-sdk-capabilities.v1.json` covers all 60
Certification Forge SDK actions. Each action has a closed, command-bearing input schema
and a production-route output schema. Regenerate and verify it after any API or router
change:

```powershell
python scripts/generate_certforge_sdk_contract.py --write
python scripts/generate_certforge_sdk_contract.py
python -m pytest tests/test_sdk_capability_contract.py -q
```

`deploy/deploy_forge.sh` applies the four idempotent capability registrations and the
generated schema synchronization in one PostgreSQL transaction. This happens only after
the candidate passes staging smoke, production smoke, and—when adapters are required—the
real subscriber-to-dispatcher customer journey. Capability-surface drift, a missing cap,
a missing `command`, or an empty output schema aborts deployment and preserves the prior
production release.
