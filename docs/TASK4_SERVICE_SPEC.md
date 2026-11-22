# Task 4 — Certification Forge Service + `echo.certforge.*` Caps + Review Upgrades

> SPEC-first phase plan for the full run-intake/orchestration service. Every phase ships a **real
> acceptance test** (runs against real deps) and is marked `[T4.Pn COMPLETE]` **in git ONLY after a
> verifier confirms the acceptance test passed** — the builder never self-signs a phase marker.
> Branch continues `feat/certforge-r5-negative-controls`. Baseline: `python -m pytest -q` = **190 passed**.

## Grounding — what already exists (verified 2026-07-20, do NOT rebuild)

The domain model, persistence, and deploy gate are substantially complete:

| Surface | Module | State |
|---|---|---|
| Domain vocab (`TargetIdentity.identity_digest`, `VerdictDecision.expires_at`, `VerdictLifecycleEvent{REVOKED,INVALIDATED,SUPERSEDED}`) | `models.py` | ✅ built |
| Fail-closed run state machine (17 states + exceptional) | `state_machine.py` | ✅ built |
| Durable tenant-scoped store: `runs`, `state_events`, `evidence_artifacts`, `rule_results`, `findings`, `signed_verdicts`, `verdict_lifecycle_events` + Merkle `verify_evidence` | `evidence.py` | ✅ built |
| Verdict calc (`expires_at = issued_at + verdict_ttl`) | `verdict.py` | ✅ built |
| Signing + trusted-key verify | `signing.py`, `signing_service.py`, `signer_cli.py` | ✅ built |
| **Deploy gate — enforces immutable target binding, env binding, rule-manifest binding, expiration, REVOKED/SUPERSEDED/INVALIDATED lifecycle, signature, evidence-root match** | `deploy_gate.py` | ✅ built (upgrades 1–4 enforced) |
| Evidence custody + external anchoring primitives | `custody.py`, `anchor.py` | ✅ built (needs mandatory-gate wiring, upgrade 6) |
| Hostile runner + image supply-chain gate (P4 GREEN) | `hostile.py`, `supply_chain.py`, `runner.py` | ✅ built (needs run-path wiring, upgrades 7,8) |
| R5 adapter-identity negative controls (live 409/503, gate-verified) | `family_r5.py`, `certforge_r5_core.py`, `certification_forge_r5_router.py` | ✅ built (needs async gate path) |
| HTTP surface: `/healthz`, `POST /v1/release-gates/evaluate` | `service.py` | ✅ built (2 of 9 caps) |
| Cap contract for 9 `echo.certforge.*` caps (schemas complete) | `contracts/certforge-capabilities.v1.json` | ✅ designed, `mapped_endpoint_complete=false` |

**Therefore Task 4 is primarily: (a) map the 7 unbuilt cap endpoints onto existing store methods, (b) add
idempotency + tenant auth at intake, (c) wire hostile/supply-chain/anchoring into the run path as gates,
(d) build the not-yet-built upgrades, (e) register the caps.**

## The 9 caps → endpoint → backing store method

| Cap | Method / Path | Tier | Backing (existing) |
|---|---|---|---|
| `echo.certforge.health` | GET `/healthz` | 0 | ✅ live — extend body to `{status,version,custody,anchor,signing}` |
| `echo.certforge.submit` | POST `/v1/certifications` | 1 | `store.register_run` + idempotency (T4.P1) |
| `echo.certforge.status` | GET `/v1/certifications/{run_id}` | 0 | `store.get_run` (T4.P1) |
| `echo.certforge.cancel` | POST `/v1/certifications/{run_id}/cancel` | 1 | `store.transition_state`→CANCELLED (T4.P2) |
| `echo.certforge.findings` | GET `/v1/certifications/{run_id}/findings` | 0 | `store.blocking_findings`/findings list (T4.P2) |
| `echo.certforge.evidence` | GET `/v1/certifications/{run_id}/evidence` | 1 | evidence index (redacted) (T4.P2) |
| `echo.certforge.verify` | POST `/v1/certifications/{run_id}/verify` | 0 | `store.verify_evidence` (T4.P2) |
| `echo.certforge.verdict` | GET `/v1/certifications/{run_id}/verdict` | 0 | `store.latest_signed_verdict` (T4.P2) |
| `echo.certforge.deploy_gate` | POST `/v1/release-gates/evaluate` | 2 | ✅ live — `DeployGate.evaluate` |

---

## Phases

### T4.P1 — Run intake: submit + status endpoints, idempotency-key binding
**Goal.** `POST /v1/certifications` creates a durable `CertificationRun` (CREATED→QUEUED) bound to an
immutable `TargetIdentity.identity_digest`; `GET /v1/certifications/{run_id}` returns it. `Idempotency-Key`
is bound to the exact target+environment+policy digest.
**Deliverables.** intake models (submit request → `schemas/certification-submit.v1.json`), idempotency table
+ replay logic, tenant principal extraction (`X-Tenant-ID` + signed request stub), response conforming to
`schemas/certification-run.v1.json`.
**Acceptance test** (`tests/test_t4p1_intake.py`, real FastAPI TestClient + real sqlite store):
1. submit target T with key K → 201, run_id R, state QUEUED, `target_identity_digest` == `TargetIdentity(...).identity_digest`.
2. submit **same** target T + **same** key K → 200, **same** run_id R (idempotent replay, no new run).
3. submit **different** target T' + same key K → 409 `idempotency_conflict`.
4. `GET /v1/certifications/{R}` with tenant → run record; re-open store from disk (new process sim) → record still present (durable).

### T4.P2 — Read surface: status/cancel/findings/evidence/verify/verdict + tenant isolation
**Goal.** All read/cancel caps mapped and **tenant-fail-closed**: tenant B cannot observe tenant A's run.
**Deliverables.** the 5 read endpoints + cancel; evidence endpoint returns redacted index only (never raw
secret evidence); verify returns `VerificationReport`; verdict returns signed envelope or 404.
**Acceptance test** (`tests/test_t4p2_read_surface.py`):
1. cross-tenant: tenant B `GET`/`cancel`/`verdict` on tenant A's run → **404** (not 403 — no existence leak).
2. cancel a QUEUED run → CANCELLED; second cancel → idempotent/409 fail-closed (never silently re-open).
3. verify with a tampered artifact hash → `valid:false` with the offending id.
4. verdict before one is signed → 404 `verdict_not_available`; after → schema-valid signed envelope.

### T4.P3 — Signer/control-plane separation (upgrade 5) + mandatory external anchoring (upgrade 6)
**Goal.** The control-plane API process **cannot read private signing key material** (KMS/HSM-style boundary
— signer is a separate `signing_service`/`signer_cli` invocation holding the key); a run **cannot reach a
non-BLOCK verdict under the prod policy without a verified external anchor receipt**.
**Deliverables.** `SignerBoundary` abstraction (control-plane holds only public keys + a sign-request channel);
anchoring made a hard gate in `verdict.py`/finalization for prod policy.
**Acceptance test** (`tests/test_t4p3_signer_anchor.py`):
1. control-plane `ServiceContext` exposes **no** private key attribute/file-handle; signing goes through the boundary; a direct private-key read from the API process path fails.
2. finalize a run with **no** anchor receipt under prod policy → verdict forced `NOT_READY` + reason `external_anchor_missing`.
3. finalize with a **forged** anchor receipt → rejected `anchor_receipt_invalid`.

### T4.P4 — Runner↔control-plane narrow protocol (9) + adapter maturity states (10)
**Goal.** Control-plane and runner communicate over a **narrow, signed, schema-validated** message contract
(no arbitrary command passthrough); adapters carry maturity `EXPERIMENTAL|BETA|STABLE` and only STABLE
adapters may justify a `PRODUCTION_READY` verdict.
**Acceptance test** (`tests/test_t4p4_protocol_maturity.py`):
1. an out-of-schema / unsigned runner message → rejected, run → INFRASTRUCTURE_FAILURE, no execution.
2. a run whose READY rests on an EXPERIMENTAL/BETA adapter → downgraded to CONDITIONALLY_READY with reason `adapter_not_stable`.

### T4.P5 — Billing-failure semantics (11) + data-retention (12) + hostile/supply-chain in run path (7,8)
**Goal.** A billing/entitlement failure **halts to an explicit state** (never a silent pass); evidence carries a
retention class + purge honors it; every source/archive target passes through `hostile.py` archive checks and
every image/dep target through `supply_chain.py` before build.
**Acceptance test** (`tests/test_t4p5_billing_retention_supplychain.py`):
1. submit under an exhausted entitlement → run halts `INFRASTRUCTURE_FAILURE`/`BILLING_BLOCKED`, verdict BLOCK, no target execution.
2. a hostile archive (zip-slip/symlink escape fixture) → refused pre-build with a blocking finding.
3. retention purge removes only expired-class evidence; signed verdict + manifest root remain intact.

### T4.P6 — Cap registration + R5 async run_id/poll gate path + independent bootstrap cert (13)
**Goal.** Register all 9 `echo.certforge.*` caps (signed rows in `arcanum_sdk.sdk_capabilities` + **FULL**
`systemctl restart echo-workers`) mapped to the now-real endpoints; add an async `run_id`/poll path so a full
R5 run survives the gate proxy timeout; the forge **certifies itself via an independent bootstrap path** whose
signer differs from the run signer.
**Acceptance test** (verified through the **real gate** `POST http://localhost:8000/sdk/invoke`, evidence captured):
1. each of the 9 caps invoked through the live gate returns a schema-valid response at `result.body`; `health_status=green`.
2. an R5 full run submitted async returns `run_id` immediately, then `status` polls to a terminal `r5_gate` verdict (no proxy timeout).
3. bootstrap cert emits a signed self-verdict whose `signing_key_id` ≠ the run-signer key id.

### T4.P7 (= Task 6) — Real end-to-end certification run
**Goal.** One real target certified end-to-end through the live service → signed, independently-verifiable
verdict + evidence bundle; hostile/tamper/supply-chain cases **actually refused**.
**Acceptance test:** a benign real repo → CONDITIONALLY_READY/PRODUCTION_READY with a verifiable bundle
(`echo.certforge.verify` green independently); a tampered/hostile variant → BLOCK with the correct blocking finding.

---

## Discipline
- **Marker rule:** append `[T4.Pn COMPLETE]` to `docs/PHASE_LEDGER.md` **only** after the phase's acceptance
  test passes AND a verifier (grok-4.5 review lane / independent re-run) confirms — commit that in git.
- **No regressions:** every phase keeps `python -m pytest -q` green (≥190) and re-runs prior phases' acceptance tests.
- **Library-first:** `echo.functions.search` before writing any new function (repo CLAUDE.md enforces).
- **Register-after-real:** caps register (T4.P6) only after endpoints are real, schema-complete, authorized, healthy, acceptance-tested (per `contracts/certforge-capability-readiness.v1.json`).
- **Ledger blockers to product readiness remain:** P5 GS343/R2D2 adapter identity+quality, P6 deploy enforcement, P7 subscriber governance, hosted-CI resolution (account billing, out of critical path).
