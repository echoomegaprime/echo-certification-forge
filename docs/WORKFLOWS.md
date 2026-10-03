# Certification Forge workflows

These workflows preserve the same invariant: no revision advances because a status field, branch
name, or operator assertion says it is ready. Advancement requires evidence bound to one immutable
source identity and independently verified at each trust boundary.

## Release qualification

1. Pin the repository and exact 40-character commit SHA; never submit a moving branch reference.
2. Run the full deterministic suite and the offline `scripts/certification_journey.py` against that
   checkout. Preserve the command, exit status, and output digest.
3. Submit the exact revision under the governed subscriber policy. Replays must use the identical
   request and dispatch identity; materially different inputs require a new request.
4. Execute work in the hardened runner plane, append evidence to custody, anchor its Merkle root,
   and evaluate every required policy gate.
5. Verify the signed verdict using public material only. A missing, expired, revoked, untrusted, or
   wrong-revision verdict is `NOT_READY`.
6. Boot the candidate on the staging port and run production-shaped smoke tests. Promote only the
   exact `PRODUCTION_READY` revision, then repeat health and identity checks in production.
7. If post-deploy verification fails, restore the prior release and retain both the failed evidence
   and rollback receipt for audit.

## Incident containment

1. Freeze promotion while leaving public verification available when it can remain trustworthy.
2. Identify the affected tenant, project, run, target digest, key, runner, and evidence scope from
   append-only audit records; do not infer scope from a mutable branch.
3. Revoke the narrowest affected credential or resource, quarantine suspect evidence, and place a
   legal hold before any repair that could change forensic material.
4. Recover through a new isolated candidate. Never edit an issued verdict or reuse an idempotency
   identity for different content.
5. Rerun the exact negative control that detected the incident, the full regression suite, staging
   smoke, and signed-verdict verification.
6. Resume promotion only after the corrected immutable revision independently reaches
   `PRODUCTION_READY`; otherwise keep the incident and release gate open.

## Operator evidence

The canonical deployment and rollback procedure is in [Operations](OPERATIONS.md). Trust boundaries
are in [Architecture](ARCHITECTURE.md), disclosure policy is in [Security](../SECURITY.md), and the
release-critical commands are listed under `Verification` in the root README.
