# P4 Hostile Runner and Image Supply-Chain Qualification

## Current state

- Phase: `P4`
- State: `IN_PROGRESS`
- Completed phase gate: `P3`
- Product release verdict: `NOT_READY`
- FORGE uses a rootful Docker Engine. Hardened non-root containers do not prove a rootless daemon.

## Implemented controls

- Six purpose-built roles: runner, custody, anchor, signer, worker, and public verifier.
- Immutable base digest and hash-locked dependencies.
- Non-root UID/GID `65532:65532`; privileged executable bits removed.
- Expiring Ed25519 image attestations and public verification.
- Fail-closed admission for unknown, premature, expired, revoked, compromised, drifted, role-mismatched, base-mismatched, source-mismatched, Dockerfile-mismatched, and lockfile-mismatched identities.
- Production runner allocation requires successful image admission before Docker creation and records the policy and attestation key IDs.
- SPDX SBOM and provenance binding.
- Public-only verifier image.
- Bounded source, build-context, archive, recursive-archive, installer-script, submodule, lockfile, LFS, and legacy-build checks.
- Deterministic runtime observations, target-log sanitization, exact container ownership, and unrelated-container preservation.
- A real FORGE gate for independent builds, image scanning, signatures, service lifecycle, resource boundaries, network denial, tenant separation, evidence integrity, cleanup, and signer regression.

## Source validation

- Tests: `109 passed`, `0 failed`.
- Branch coverage: `85.79%`.
- Required floor: `85%`.
- Compilation: passed.

## Remaining exit work

1. Commit and push this source baseline.
2. Build every role twice on FORGE from its exact Git archive.
3. Verify external scanner and signature tooling.
4. Execute the full real FORGE gate.
5. Correct any real defect without weakening a check.
6. Import exact evidence bytes.
7. Add deterministic `scripts/verify_p4.py`.
8. Run closure gates, update ledgers, commit `[P4 COMPLETE]`, push, and verify remote identity.

P4 is not complete from source existence, local tests, labels, or the earlier foundation result alone.
