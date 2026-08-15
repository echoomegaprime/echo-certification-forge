# Operations

## Operator principles

- Treat `NOT_READY` as the default and expected failure state.
- Diagnose with exact run, target, environment, policy, and evidence identities.
- Never edit evidence, verdicts, or release assets in place.
- Never restart production onto an unverified tree.
- Preserve the prior release until staging and post-promotion health are green.

## Verification sequence

1. Confirm the exact source SHA with local deterministic gates
   (`python -m pytest -q` and `python scripts/p1_acceptance.py`). GitHub Actions
   is disabled account-wide (support ticket #4663295); do not treat hosted CI as
   green and do not try to re-enable account Actions from this repository.
2. Execute the declared production-shaped journey with the pinned runner image.
3. Verify evidence custody, receipt chains, signatures, expiry, and revocation state.
4. Generate exact-source product readiness and verify it with the public trust root.
5. Boot staging from that same SHA and run live smoke and negative paths.
6. Promote atomically, health-check production, and roll back on any mismatch.
7. Publish immutable machine certificates and the repository certificate graphic.

## Secret scan

Run a redacted full-history scan before promoting a SHA:

```powershell
python scripts/full_history_secret_scan.py
```

The report is `artifacts/full_history_secret_scan.json`. It never stores secret
material. Blocking detectors are private-key blocks, GitHub tokens, and AWS
access keys. Hosted CI is not a substitute for this local gate.

## Incident triage

Capture the run ID, target SHA, environment digest, policy version, service health, dispatcher state,
and sanitized logs. A failed gate is not repaired by changing a verdict field; repair the failing
evidence-producing control, rerun from a new idempotency key, and retain the failed run for audit.

## Recovery

Production uses a current-release pointer and retained prior release. If post-promotion health or
identity differs, atomically restore the prior pointer, restart through the deployment gate, and
record the rollback receipt. Do not delete failed evidence or reuse a run ID for another target.
