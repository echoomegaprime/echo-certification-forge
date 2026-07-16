# P4 Hostile Runner and Image Supply-Chain Qualification

## Current state

- Phase: `P4`
- State: `IN_PROGRESS`
- Completed phase gate remains: `P3`
- Product release verdict remains: `NOT_READY`

## Foundation implemented

- Purpose-built runner and signer Dockerfiles.
- Base image pinned to `python:3.12.10-slim-bookworm@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db`.
- Hash-locked Python runtime dependency graph.
- Non-root image user `65532:65532`.
- Explicit runner and signer role labels.
- Signed image-identity contract using Ed25519 public verification.
- Fail-closed image admission for role, exact digest, base digest, source commit, Dockerfile digest, lockfile digest, trusted key, revocation, compromise, and drift.
- Pinned-Dockerfile policy and hostile Dockerfile rejection.
- Build-context symlink and resource-limit policy.
- SPDX 2.3 SBOM construction and image binding.
- Real FORGE supply-chain acceptance harness with exact-container ownership and cleanup.

## Current verified infrastructure fact

FORGE uses a rootful Docker Engine. The images and execution policy are non-root and hardened. This does not establish a rootless Docker daemon or microVM isolation.

## Remaining P4 exit work

- Rebuild both images from the exact P4 Git commit.
- Produce real FORGE SBOM, provenance, public attestation, admission, containment, and forbidden-file evidence.
- Complete dependency and operating-system vulnerability scanning.
- Complete hostile build and runtime fixture matrix: hostile package-install scripts, traversal/symlink contexts, archive bombs, fork/PID, CPU, memory, disk, file-size, exfiltration, timeout, cancellation, crashes, evidence corruption, cross-tenant attempts, and orphan cleanup.
- Prove purpose-built signer operation with the P3 isolated signing workflow.
- Resolve exact reproducibility or record independently comparable build evidence.
- Add image revocation and compromised-image denial to the actual runner/signer admission path.
- Capture final P4 evidence package, commit, and push before marking P4 complete.
