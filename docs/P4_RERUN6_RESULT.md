# P4 rerun6 — FORGE gate result (grok-4.5 orchestrated, 2026-07-18)

**Objective:** re-run the full FORGE container-provenance + signature gate at the signer-identity-fix HEAD (8ccfa65) to validate the fix. **Result: the P4 gate is GREEN; release_verdict = NOT_READY due to one legitimate follow-up (P3 must be re-certified against the corrected shared script).**

## What passed (real evidence, at HEAD 8ccfa65; workdir p4-8ccfa65)
- **12 role images built** (no-cache) + **seal PASSED** — `artifacts/p4_images/manifest.json` (+ manifest-verification.json), manifest_sha256 = bc86b3ce...
- **P4 hostile-acceptance gate GREEN** — `artifacts/p4_forge_acceptance.json` top-level `passed: true`: image_signatures.passed + all 18 scans (filesystem/malware/vulnerability x anchor/custody/runner/signer/verifier/worker) passed. This validates the signer-identity fix (the false signer_image_identity_mismatch is gone; a genuine mismatch still fails, regression-locked).
- **P4 hardening verification PASSED** — `artifacts/p4_hardening_verification.json` passed:true.
- **P1 PASSED** — `p1_verification_report.json` passed:true; the P1 runtime smoke was aligned to the P3 API contract (it had expected a pre-P3 PENDING status; now reflects completed_phase_gate:P3) — aligned, NOT weakened.
- **P2 PASSED** — `p2_verification_report.json` passed:true.

## The one RED (a real follow-up, not a fix failure)
- **P3 verification INCONCLUSIVE** — `p3_verification_report.json`: RuntimeError "closure source identity mismatch: scripts/p3_forge_acceptance.py". The P3 verifier pins the hash of p3_forge_acceptance.py, and that is exactly the file the signer-identity fix corrected (the digest-vs-image-ID bug lived in run_signer_container). So P3's pinned evidence references the OLD (buggy) script.
- **Resolution (follow-up):** re-run P3 acceptance against the corrected script so P3 evidence is regenerated under the new source identity — then the full gate is green and P4 can be marked complete. This is a legitimate re-certification, not a weakening.

## Verdict
`[P4 COMPLETE]` NOT claimed (release_verdict NOT_READY). The rerun6 achieved its purpose — a real gate run proves the signer fix works — and surfaced the one remaining honest task: re-certify P3 with the corrected shared p3_forge_acceptance.py. FORGE was responsibly respected throughout (seal deferred until load dropped; timeouts never weakened).
