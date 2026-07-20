# Certification Forge Phase Ledger

| Phase | State | Evidence | Product verdict |
|---|---|---|---|
| P1 deterministic evidence/verdict foundation | COMPLETE | `artifacts/p1_verification_report.json` | NOT_READY |
| P2 runner and authenticated transport foundation | COMPLETE | `artifacts/p2_forge_acceptance.json`, `artifacts/p2_forge_acceptance.summary.json`, `artifacts/p2_verification_report.json` | NOT_READY |
| P3 production evidence custody, anchoring, and signing | COMPLETE | `artifacts/p3_forge_acceptance.json`, `artifacts/p3_forge_acceptance.summary.json`, `artifacts/p3_offline_bundle/`, `artifacts/p3_verification_report.json` | NOT_READY |
| P4 hostile runner, signer image, and supply-chain qualification | COMPLETE | FORGE gate `passed=True, run_outcome=COMPLETE` — `p4-runs/p4-8c6b30d-rerun7c/p4_hostile_result.json` (2026-07-20, commit 8c6b30d) | NOT_READY |
| P5 adapter breadth and service modes | NOT_STARTED | ANVIL routing proof blocked | NOT_READY |
| P6 deployment enforcement and platform integration | NOT_STARTED | exact-digest evaluator exists; real deployment hook absent | NOT_READY |
| P7 subscriber productization and governance | NOT_STARTED | none | NOT_READY |

## Task 4 — Certification Forge service + `echo.certforge.*` caps (sub-track)

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
| T4.P5 billing-failure + data-retention + hostile/supply-chain in run path | NOT_STARTED | — |
| **T4 service DEPLOYED to FORGE** | **LIVE** | `echo-certforge.service` on FORGE **:8309** (systemd, enabled+active, 45MB), staging-gated deploy (`deploy/deploy_forge.sh`: staging :8311 smoke → promote → prod smoke → rollback-on-red) + `deploy/smoke_live.py` (30 fail-closed checks). Independently verified HAMMER→LAN `192.168.1.220:8309` (health cap-shape 200 + real submit → QUEUED NOT_READY). Commit 1c6df44; build 9323. |
| T4.P6 cap registration (9 caps) | **[T4.P6 CAPS COMPLETE]** | **All 9 `echo.certforge.*` caps REGISTERED + live-verified through the SDK gate** (`POST :8000/sdk/invoke`), `health_status=green`, `lifecycle=active` (2026-07-20). `scripts/register_certforge_caps.sql` (idempotent UPSERT) → FULL `echo-workers` restart. Tenant design: SDK gate = sovereign control plane → `static_headers` `X-Tenant-ID=echo-sovereign` on tenant-scoped caps; path params via `args_mode=path`; `deploy_gate` tier-2 HMAC-gated. E2E gate proof: health 200 · submit 201 QUEUED · status 200 · findings/evidence 200 (redacted) · verdict 404 fail-closed · verify 200 · cancel 200→409 · deploy_gate (HMAC) → `{allowed:false, signed_verdict_missing}`. **Remaining T4.P6 sub-items:** R5 async run_id/poll gate path, independent bootstrap cert. |
| T4.P6-remainder R5 async gate path + independent bootstrap cert | NOT_STARTED | Registration path found: gate supports `handler_kind='http'` (3801 caps use it) with full `target_url` + `target_method` + `target_node='forge'` + `args_mode∈{query,body,path}` — so the 9 caps can proxy to `http://127.0.0.1:8309/...` **without router code**. OPEN DESIGN (before registering): (1) path-param substitution for `/v1/certifications/{run_id}` via `args_mode='path'` — confirm the invoke dispatch's `{param}` handling; (2) **SDK-identity → `X-Tenant-ID` mapping** — the certforge service is tenant-scoped via that header; the gate must inject the caller's tenant (may need a thin router like `certification_forge_r5_router.py` rather than raw http-proxy if header-injection from identity isn't supported by the http kind). Then INSERT 9 signed rows (`sig_ed25519` vestigial — raw INSERT is consistent) + **FULL** `systemctl restart echo-workers` (gunicorn preload caches the registry) + verify each cap through `POST :8000/sdk/invoke`. Register only after health-verified per `contracts/certforge-capability-readiness.v1.json`. |
| T4.P7 (=Task 6) real end-to-end certification run | NOT_STARTED | — |

## Current authoritative state

- `completed_phase_gate`: `P4`
- `run_outcome`: `COMPLETE`
- `release_verdict`: `NOT_READY`
- P3 real FORGE acceptance: passed
- P3 deterministic closure verifier: passed
- Central `echo.certforge.*`: not registered
- `echo.builds.log`: not registered
- Hosted CI: `CI STARTUP BLOCKER — ROOT CAUSE UNRESOLVED`
- Echo Desktop P8C: not started

A completed phase does not upgrade the whole-product verdict. P4 hostile-runner + image supply-chain qualification is now COMPLETE (FORGE gate green 2026-07-20, commit 8c6b30d — validates the 307667a signer image-identity fix and the 25420a8 public-verifier-probe fix; run repeatably via `scripts/run_p4_gate.sh`). Remaining fail-closed blockers to product readiness: P5 GS343/R2D2 adapter identity and quality proof, P6 real deployment enforcement, P7 subscriber governance, central `echo.certforge.*` capability registration, and hosted CI resolution.
