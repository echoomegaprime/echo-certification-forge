# Operations

## Dispatcher recovery limits

Operator sandbox and runtime measurement failures stop the dispatcher before
it claims another job. The unexecuted claim returns to pending with its retry count
unchanged. Service restarts use the configured supervisor delay. Inspect the
structured `dispatcher_runtime_circuit_open` event, repair the runtime through
supported governance, then restart. Tenant journey or environment mismatches use a
persisted 60-second delay between bounded retries; they cannot open the global
circuit or occupy the head of the queue while delayed. Do not consume the customer
backlog as a diagnostic probe.

Intake recovery isolates validated request-local failures and malformed stored
intake payloads. Unexpected database integrity failures and corrupt materialized
run records deliberately remain fail-loud: stop and investigate the original
database with a preserved snapshot. Broad exception swallowing could conceal
cross-record corruption or an ownership failure. API rejection refunds are fenced
to the exact still-reserved request; recovery-owned or executing work is retained.

The current post-promotion dispatch smoke shares the normal FIFO queue and has a
180-second deadline. A backlog can cause a false red and source rollback. Check
queue drain readiness before promotion; scoped canary dispatch remains a separate
availability improvement. This smoke is not a claim that the service supports
multiple independent dispatchers during long target acquisition.

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

The durable subscriber dispatcher resolves attestations from
`ECHO_CERTFORGE_PRODUCTION_E2E_ATTESTATION_DIR`. Each envelope is named
`<target_identity_digest>.<environment_identity_digest>.json`; both values are
the exact 64-character digests published for the queued run. The matching
collector public key is pinned independently under
`ECHO_CERTFORGE_TRUSTED_PRODUCTION_E2E_KEYS`. Both directories are root-owned
and readable by the dispatcher but are not writable by its `forge` service
identity. Install a collector envelope atomically (temporary file followed by
rename), never place a private key in either directory, and never accept a
target-selected path or target-supplied public key. Missing, untrusted, stale,
or identity-mismatched envelopes remain `NOT_READY`.

Exact Git acquisition uses the bounded dispatcher setting
`ECHO_CERTFORGE_GIT_ACQUISITION_TIMEOUT_SECONDS` (production default: 900;
allowed range: 30–1800 seconds). This bounds network and checkout stalls while
allowing large repositories to materialize under normal disk contention. An
invalid value fails the acquisition before creating the target destination;
never remove the timeout to make a run pass.

The 900-second default is sized for the governed Echo monorepo (approximately
1 GiB and more than 23,000 files). The previous 300-second ceiling produced a
reproducible false infrastructure failure during exact-SHA checkout while the
disk remained healthy and the checkout continued making I/O progress.

Private GitHub targets use the dispatcher-owned GitHub App identity configured by
`ECHO_CERTFORGE_GITHUB_APP_ID` and
`ECHO_CERTFORGE_GITHUB_PRIVATE_KEY_FILE`. The worker mints a short-lived
installation token restricted to the requested repository and `contents:read`.
Git receives that token only through an ephemeral `GIT_ASKPASS` process
environment; the token is never placed in the repository URL, command line,
target record, evidence, or exception text. The askpass helper is removed after
acquisition on both success and failure. A partially configured App identity,
missing installation, invalid key, or token-mint failure blocks acquisition.
Do not replace this path with a PAT-bearing URL or a persistent credential
helper.

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

For `acquisition_failed` with GitHub reporting `Repository not found`, first
confirm that both GitHub App settings are present, their files are readable by
the dispatcher, and that the App is installed on the named repository. Never
print the private key, minted token, process environment, or credential-helper
output while diagnosing the failure.

## Recovery

Production uses a current-release pointer and retained prior release. If post-promotion health or
identity differs, atomically restore the prior pointer, restart through the deployment gate, and
record the rollback receipt. Do not delete failed evidence or reuse a run ID for another target.

After the candidate API has been started, automatic rollback preserves the current
database, including submissions and billing events acknowledged during promotion.
With both API and dispatcher stopped, it creates a separate integrity-checked
post-promotion SQLite snapshot and restores the prior source and service units.
The original pre-promotion snapshot is retained as a separate recovery artifact.
Only failures before the first candidate API start may restore that older snapshot
automatically. A failure to stop either writer or preserve the accepted-write
snapshot stops rollback without replacing the database. If the previous source
cannot read the retained database, its health check fails closed and forward
recovery is required; acknowledged work must not be discarded to obtain green
health. Schema-changing releases must separately prove backward compatibility.

Required-adapter staging boots with the same adapter mode and inherited owner
runtime profile as production. Its authenticated runtime probe validates the
journey commitment and operator image, rejects missing authorization and another
tenant's key, and fails before promotion when the runtime profile is unavailable.
Production dispatch smoke resolves its own exact journey declaration through the
same runtime API instead of reusing the default status environment.
