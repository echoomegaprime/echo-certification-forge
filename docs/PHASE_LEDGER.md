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
| T4.P4 runner↔control-plane narrow protocol + adapter maturity states | NOT_STARTED | — |
| T4.P5 billing-failure + data-retention + hostile/supply-chain in run path | NOT_STARTED | — |
| T4.P6 cap registration + R5 async gate path + independent bootstrap cert | NOT_STARTED | — |
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
