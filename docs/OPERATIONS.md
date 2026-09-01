# Operations

## Operator principles

- Treat `NOT_READY` as the default and expected failure state.
- Diagnose with exact run, target, environment, policy, and evidence identities.
- Never edit evidence, verdicts, or release assets in place.
- Never restart production onto an unverified tree.
- Preserve the prior release until staging and post-promotion health are green.

## Verification sequence

Before a worker may issue `PRODUCTION_READY`, mount a collector envelope through
`--production-e2e-attestation` (or
`ECHO_CERTFORGE_PRODUCTION_E2E_ATTESTATION`) and a directory containing only the
pinned collector public keys through `--trusted-production-e2e-keys` (or
`ECHO_CERTFORGE_TRUSTED_PRODUCTION_E2E_KEYS`). The private collector key must not
be present on the worker. Absence, signature failure, expiration, or any exact
identity/E2E mismatch is a normal `NOT_READY` result, never a bypass.

1. Confirm hosted CI succeeded for the exact source SHA.
2. Execute the declared production-shaped journey with the pinned runner image.
3. Verify evidence custody, receipt chains, signatures, expiry, and revocation state.
4. Generate exact-source product readiness and verify it with the public trust root.
5. Boot staging from that same SHA and run live smoke and negative paths.
6. Promote atomically, health-check production, and roll back on any mismatch.
7. Publish immutable machine certificates and the repository certificate graphic.

The Echo GitHub Autonomy production collector must use profile
`echo-github-autonomy-remote-mcp-v2` and exactly the three governed accounts.
Profile v1 and evidence containing the retired `Bmcbob76` identity fail closed.

## Incident triage

Capture the run ID, target SHA, environment digest, policy version, service health, dispatcher state,
and sanitized logs. A failed gate is not repaired by changing a verdict field; repair the failing
evidence-producing control, rerun from a new idempotency key, and retain the failed run for audit.

## Recovery

Production uses a current-release pointer and retained prior release. If post-promotion health or
identity differs, atomically restore the prior pointer, restart through the deployment gate, and
record the rollback receipt. Do not delete failed evidence or reuse a run ID for another target.
