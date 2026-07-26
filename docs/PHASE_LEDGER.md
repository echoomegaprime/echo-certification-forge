# Certification Forge Phase Ledger

| Phase | State | Evidence | Product verdict |
|---|---|---|---|
| P1 deterministic evidence/verdict foundation | COMPLETE | `artifacts/p1_verification_report.json` | NOT_READY |
| P2 runner and authenticated transport foundation | COMPLETE | `artifacts/p2_forge_acceptance.json`, `artifacts/p2_forge_acceptance.summary.json`, `artifacts/p2_verification_report.json` | NOT_READY |
| P3 production evidence custody, anchoring, and signing | COMPLETE | `artifacts/p3_forge_acceptance.json`, `artifacts/p3_forge_acceptance.summary.json`, `artifacts/p3_offline_bundle/`, `artifacts/p3_verification_report.json` | NOT_READY |
| P4 hostile runner, signer image, and supply-chain qualification | COMPLETE | FORGE gate `passed=True, run_outcome=COMPLETE` — `p4-runs/p4-8c6b30d-rerun7c/p4_hostile_result.json` (2026-07-20, commit 8c6b30d) | NOT_READY |
| P5 adapter breadth and service modes | COMPLETE | `artifacts/p5-adapter-bundle-20260723/adapter-acceptance-report.json`: adapter gate GO; GS343 and R2D2 both STABLE; 240/240 cases each; zero critical failures. Production bundle re-verified on FORGE. | GATE COMPLETE |
| P6 deployment enforcement and platform integration | COMPLETE | `artifacts/p6_acceptance.summary.json`: 12/12 executable checks pass, including staging-first promotion, rollback, ledger enforcement, and exact-image isolation. | GATE COMPLETE |
| P7 subscriber productization and governance | COMPLETE | `artifacts/p7_acceptance_report.json`: all tenant, billing, lease, quota, audit, and dispatch scenarios pass fail-closed. | GATE COMPLETE |
| SDK final contract | COMPLETE | `contracts/certforge-sdk-capabilities.v1.json`: exactly 60 unique closed-schema Certification Forge capabilities. | GATE COMPLETE |
| Master whole-product acceptance | SIGNED EXACT-SOURCE GATE | `scripts/master_acceptance.py` + `acceptance/master-imperfect-app/`: real Docker journey, classified defects, ephemeral generated harness, signed target refusal, evidence-chain verification, exact-source CI binding, and signed product-readiness attestation. | Runtime attestation decides |

## Task 4 — Certification Forge service + `echo.certforge.*` caps (sub-track)

> **LIVE END-TO-END PROVEN (2026-07-21):** a real target was certified through the full pipeline on
> FORGE. The key-holding **run-worker** (`run_worker.py`, separate from the key-less :8309 API —
> preserves the T4.P3 signer/control-plane separation) acquired a target (`acquisition.py`, hooks
> disabled + file:// denied), executed it, and produced a **PRODUCTION_READY signed verdict**. Read
> back through the live SDK gate caps: `echo.certforge.status`=COMPLETE/PRODUCTION_READY ·
> `echo.certforge.verdict`=signed (run-signer `ed25519:a07f417e…`) · `echo.certforge.verify`=valid
> (11 artifacts) · `echo.certforge.deploy_gate` (tier-2 HMAC)=**allowed, `exact_certification_valid`**.
> The run-signer PUBLIC key is in the API's trust store; the PRIVATE key is worker-only. Commit 8ee64fc.
> **SELF-SERVICE RUN CAP SHIPPED (2026-07-21, commit c7b47cc):** `echo.certforge.run` is LIVE + green.
> The **isolated execution sandbox** (`sandbox.py::DockerSandbox`, SPEC 14.2 Level-2 container) confines
> the untrusted critical-journey: `--network none`, memory/cpu/pids quotas, `--read-only` + noexec tmpfs,
> `--user nobody`, `--cap-drop ALL`, `no-new-privileges`, source mounted `:ro`, pinned `@sha256` image.
> **Real-Docker test on FORGE PASSED** — benign journeys run, network egress is blocked. The cap
> (additive `certforge_run_router.py`) sovereign-auths, launches the KEY-HOLDING worker detached with
> `--sandbox` (no shell → no injection); poll via `echo.certforge.status`. Untrusted code runs ONLY in
> the container; acquire/scan/sign never execute target code. **Live E2E:** `echo.certforge.run` (local
> target) → worker ran journey in Docker (`journey_isolation: docker`) → COMPLETED PRODUCTION_READY
> signed → gate `status`/`verdict`/`verify` green + `deploy_gate`=**allowed**. **12 `echo.certforge.*`
> caps green.** Full suite **228 passed** (+1 docker-gated skip on HAMMER, passes on FORGE).
>
> **FABLE ADVERSARIAL REVIEW (2026-07-21, commit f651805) — SHIP-WITH-FIXES, all applied.** No HIGH
> holes (no tenant bypass, no shell injection, no fail-open authz, bootstrap independence sound). 4 MEDs
> fixed + regression tests: **(1)** executor no longer rubber-stamps rules — 8 mandatory rules now from
> REAL checks (live cross-tenant probe, verify_evidence, entitlement, digest binding, subprocess reap);
> the 2 architectural controls require EXPLICIT trusted attestation (default fail-closed) supplied by the
> run-worker. **(2)** verdict engine no longer crashes on a declared (intake) run shape → NOT_READY
> `target_identity_not_reconciled`. **(3)** `verify_evidence` joins `evidence_retention.purged_at` so a
> policy purge no longer reads as tamper. **(4)** R5 async `status()` finalizes COMPLETE only on
> `forge_verify.all_ok` (never exit-0 alone). + LOWs: idempotency-race → clean 200 replay; stray files
> removed. Re-verified live post-fix: worker → PRODUCTION_READY (honest), gate `deploy_gate`=allowed.
> Full suite **223 passed**.


Service-build sub-track (SPEC: `docs/TASK4_SERVICE_SPEC.md`). A completed T4 phase does **not** upgrade
the whole-product verdict (still NOT_READY); central `echo.certforge.*` registration remains a blocker
(lands T4.P6). Marker rule: `[T4.Pn COMPLETE]` only after the phase acceptance test passes AND the full
suite stays green on an independent re-run.

| Phase | State | Evidence |
|---|---|---|
| T4.P1 run intake — submit + status + idempotency-key binding | **[T4.P1 COMPLETE]** | `tests/test_t4p1_intake.py` (6 acceptance cases incl. cross-tenant idempotency isolation) — full suite **196 passed** on independent re-run 2026-07-20; commit b5fb61e + strengthening follow-up. Adversarial review (sentinel lane) REJECTED on 2 misreadings (refuted vs primary evidence) + 1 real test-gap (cross-tenant isolation) which is now closed by a passing test. |
| T4.P2 read surface: status/cancel/findings/evidence/verify/verdict + tenant isolation | **[T4.P2 COMPLETE]** | `tests/test_t4p2_read_surface.py` (6 adversarial cases: cross-tenant 404-no-leak across all 6 endpoints, cancel-then-409, findings list, redacted evidence index, on-disk tamper→valid:false+id, verdict-404-until-signed→independently-verifiable envelope) — full suite **202 passed** independent re-run 2026-07-20; commit 52a3f50. All 9 `echo.certforge.*` caps now have real mapped endpoints. Verifier note: external LLM review lanes both unavailable (sentinel weak; vertex billing-denied), so the gate rests on the adversarial acceptance suite + in-session hole analysis (no uncovered leak/bypass found). |
| T4.P3 signer/control-plane separation + mandatory external anchoring | **[T4.P3 COMPLETE]** | Upgrades 5+6 were already built at P3 (`signing_service.py` isolated signer with `_validate_anchor` gate + control-plane-only signing; `signer_cli.py` out-of-process key holder; `anchor.py` independent receipts) and deeply tested by `tests/test_p3_custody_anchor_signing.py` (forged-anchor→`anchor_verification_failed`, RUNNER/MODEL/DESKTOP/WORKER→`only_control_plane`, key lifecycle). T4 adds the **service-boundary proof** `tests/test_t4p3_signer_anchor.py` (3 cases): (1) recursive scan finds NO Ed25519 private key reachable from the control-plane `ServiceContext`/app graph + `/healthz` truthfully reports `private_signing_key_loaded:false`; (2) a rules-complete run with no signed verdict (anchor→sign chain never ran) is DENIED by the deploy gate (`signed_verdict_missing`) — no non-BLOCK release without the anchor chain; (3) reference-guard that `IsolatedVerdictSigningService.sign` still calls `_validate_anchor`. Full suite **205 passed** independent re-run 2026-07-20. |
| T4.P4 runner↔control-plane narrow protocol + adapter maturity states | PARTIAL / RESEQUENCED | **Upgrade 9 (narrow signed runner protocol) already built** in `runner.py` (1376 lines: RunCredentialClaims/SignedRunCredential, TransportRequest w/ pinned schema_version + request_sha256, EvidenceChunk, RunnerResponse signed, bounded RunnerCommand enum = no arbitrary passthrough, replay/expiry/conflict auth, leases, isolation profiles) — tested by `tests/test_runner.py`. **Upgrade 10 (adapter maturity gating READY on STABLE-only) is DEFERRED**: it depends on the adapter execution layer feeding per-adapter results to the verdict, which does not exist yet (whole-product P5 adapter breadth). Building the maturity gate now would be speculative code with no caller. Resequence: implement adapter maturity WITH the adapter layer in P5, not standalone. |
| T4.P5 billing-failure + data-retention + hostile/supply-chain in run path | **[T4.P5 COMPLETE]** | `executor.py::RunExecutor` drives a QUEUED run to a signed verdict, wiring the pre-execution gates fail-closed: entitlement/billing → INFRASTRUCTURE_FAILURE + BILLING_BLOCKED (no execution, no signed verdict); `hostile.scan_target_source` → blocking findings (upgrade 7); `supply_chain.scan_dockerfile` → blocking findings (upgrade 8). Retention (upgrade 12): `evidence_retention` table + `set_retention`/`purge_expired_evidence` (purges expired CONTENT, keeps append-only metadata + signed verdict + Merkle root intact). `tests/test_t4p5_executor.py` (4 cases: billing no-execution, hostile package.json postinstall→BLOCK, hostile Dockerfile→BLOCK, retention purge preserves verdict). |
| T4.P7 (=Task 6) real end-to-end certification run | **[T4.P7 COMPLETE]** | `tests/test_t4p7_e2e.py` (2 cases, real store + Ed25519 + subprocess journey + deploy gate): benign target → PRODUCTION_READY, independently-verifiable bundle (`verify_evidence` valid + signed verdict verifies + `evidence_merkle_root` matches + bound to target digest), **deploy gate ALLOWS**; hostile variant → NOT_READY + blocking finding, signed refusal verifies, **deploy gate DENIES**. Full chain executor→signed verdict→release authority proven. Full suite **216 passed**; service redeployed (823922c, retention schema live). |
| **T4 service DEPLOYED to FORGE** | **LIVE** | `echo-certforge.service` on FORGE **:8309** (systemd, enabled+active, 45MB), staging-gated deploy (`deploy/deploy_forge.sh`: staging :8311 smoke → promote → prod smoke → rollback-on-red) + `deploy/smoke_live.py` (30 fail-closed checks). Independently verified HAMMER→LAN `192.168.1.220:8309` (health cap-shape 200 + real submit → QUEUED NOT_READY). Commit 1c6df44; build 9323. |
| T4.P6 cap registration (9 caps) | **[T4.P6 CAPS COMPLETE]** | **All 9 `echo.certforge.*` caps REGISTERED + live-verified through the SDK gate** (`POST :8000/sdk/invoke`), `health_status=green`, `lifecycle=active` (2026-07-20). `scripts/register_certforge_caps.sql` (idempotent UPSERT) → FULL `echo-workers` restart. Tenant design: SDK gate = sovereign control plane → `static_headers` `X-Tenant-ID=echo-sovereign` on tenant-scoped caps; path params via `args_mode=path`; `deploy_gate` tier-2 HMAC-gated. E2E gate proof: health 200 · submit 201 QUEUED · status 200 · findings/evidence 200 (redacted) · verdict 404 fail-closed · verify 200 · cancel 200→409 · deploy_gate (HMAC) → `{allowed:false, signed_verdict_missing}`. **Remaining T4.P6 sub-items:** R5 async run_id/poll gate path, independent bootstrap cert. |
| T4.P6-remainder R5 async gate path + independent bootstrap cert | **[T4.P6 COMPLETE]** | **R5 async gate path LIVE+verified** — additive `certforge_r5_async_router.py` (auto-mounted on echo-worker-server; does NOT touch the proven sync router) + 2 caps `echo.certforge.r5.{submit_async,status}` (green). Gate E2E: `submit_async`→200 `run_id` RUNNING (immediate, no proxy timeout); operator launched **detached on ANVIL** (`setsid`, `/tmp/r5_async/*`); state persisted `arcanum_sdk.r5_async_runs`; poll → RUNNING→FAILED with FORGE-re-verified result (`r5_gate=BLOCK` for dummy-identity input = correct fail-closed; GREEN full run needs live ANVIL identity harvest, same as sync). **Independent bootstrap cert DONE** — `bootstrap.py::BootstrapCertifier` signs a self-attestation with a key distinct from the run signer (fail-closed on collision); verifies under the bootstrap key, NOT under the run-signer key; `scripts/emit_bootstrap_cert.py` → `artifacts/bootstrap_cert.json` (CERTIFIED, independent, self-verified); 5 acceptance cases. Full suite 210 passed. Commits a96e967, f41aba0. |

## Current authoritative state

The repository ledger records gate evidence; it does not self-authorize production. The sole
authoritative whole-product verdict is the signed, non-expired, exact-commit result returned by
`GET https://cert-api.echosforge.com/v1/status`. Missing, stale, tampered, untrusted, or wrong-commit
attestations fail closed to `NOT_READY`.

- Source phase gates: **P1–P7 COMPLETE**
- SDK contract: **60/60 COMPLETE**
- Master acceptance implementation: **COMPLETE**
- P3 real FORGE acceptance: passed
- P3 re-certified 2026-07-18 against corrected `scripts/p3_forge_acceptance.py` (signer-identity fix source identity): passed
- P4 deterministic closure verifier: passed after P3 re-cert
- Central `echo.certforge.*`: **REGISTERED + live-verified** (12 caps green, 2026-07-21)
- P5 adapter gate: **GO** — GS343 and R2D2 are both STABLE at 240/240 with zero critical failures.
- P6 executable acceptance: **12/12 PASS**.
- P7 executable acceptance: **all scenarios PASS**.
- Hosted CI: must be successful for the exact deployed source commit and is checked by the final signer.

A completed phase never upgrades the whole-product verdict by itself. Only the final signed gate can do so.
