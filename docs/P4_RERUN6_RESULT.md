# P4 rerun6 — FORGE gate result (closed after P3 re-cert, 2026-07-18)

**Objective:** re-run the full FORGE container-provenance + signature gate at the signer-identity-fix HEAD, then close the one remaining P3 source-identity follow-up. **Result: full P1–P4 + hardening sweep GREEN; phase gate P4 COMPLETE; product `release_verdict` remains `NOT_READY` by contract.**

## What passed (real evidence)

- **12 role images built** (no-cache) + **seal PASSED** — `artifacts/p4_images/manifest.json` (+ manifest-verification.json), manifest_sha256 = bc86b3ce...
- **P4 hostile-acceptance gate GREEN** — `artifacts/p4_forge_acceptance.json` top-level `passed: true`: image_signatures.passed + all 18 scans passed. Signer-identity fix validated (false `signer_image_identity_mismatch` gone; genuine mismatch still fails).
- **P4 hardening verification PASSED** — `artifacts/p4_hardening_verification.json` passed:true.
- **P1 PASSED** — `p1_verification_report.json` passed:true.
- **P2 PASSED** — `p2_verification_report.json` passed:true.
- **P3 re-certified PASSED** — real re-run of `scripts/p3_forge_acceptance.py` under the corrected source identity (`dc733b6af0b8b758…`), then `scripts/verify_p3.py` re-baselined to that golden evidence (not a silent hash edit of the old report). Acceptance: 34/34 checks, `run_outcome: COMPLETE`, report sha256 `e805e6b9913a8a3712fee4710aec5d6b180b149ed2e729723bb178e7327a1ee6`. Offline bundle regenerated from the same workspace.
- **P4 closure verifier PASSED** — `scripts/verify_p4.py` failures:[], completed_phase_gate:P4, run_outcome:COMPLETE.

## Closed follow-up (was the only RED on initial rerun6)

- **Was:** P3 verification INCONCLUSIVE — `closure source identity mismatch: scripts/p3_forge_acceptance.py` because the verifier pinned the pre-fix script while the tree held the reviewed signer-identity fix (307667a, 5ec68c8).
- **Resolution:** re-ran real P3 acceptance on FORGE against the corrected script; packaged public offline material; updated `verify_p3.py` / `verify_p4.py` golden pins to the **new** evidence identities produced by that run; re-ran full sweep green.

## Verdict

`[P4 COMPLETE]` **earned**. Phase gate is complete with full deterministic evidence. Product-level `release_verdict` remains `NOT_READY` (GS343/R2D2, central registration, deployment enforcement, subscriber governance, hosted CI remain blockers). FORGE load was checked; timeouts were not weakened (first acceptance attempt under high load timed out the signer container at the existing 30s bound; re-run succeeded without changing timeouts).
