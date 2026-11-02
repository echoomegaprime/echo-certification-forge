# Reconcile expired ownership on a released terminal reservation

Historical terminal reconciliation could set a reservation to `RELEASED` while
retaining its claim and lease. Those fields do not authorize a released worker;
their retention is a metadata-cleanup defect. The initial maintenance guard used
their presence as a conservative proxy for possible orphan work. A separately
reviewed activity classifier can establish quiescence from canonical terminal,
lease, dispatch and process-ownership evidence while retaining the anomaly and
cleanup obligation. This change does not alter that guard or waive cleanup.
Normal expired-claim recovery selects only `EXECUTING`/`STARTED`, and an ordinary
release is already a no-op for `RELEASED`, so neither repairs this residue.

Normal terminal reconciliation now clears claim and lease fields in the same
existing transaction that releases the reservation. No run state, dispatch,
usage charge, compensation, historical heartbeat or signing field is changed by
that additional cleanup.

For existing residue, the supported owner API is:

```http
POST /v1/subscriber/certifications/{run_id}/reconcile-reservation
X-Tenant-ID: <existing authorized organization>
Authorization: Bearer <existing owner/admin key with governance:manage>
Content-Type: application/json

{"reason":"expired_terminal_claim_owner_repair"}
```

This uses the existing `governance:manage` permission and its existing role and
key-scope policy. It does not create a permission, credential or scope grant.
The source declares `echo.certforge.governance.reconcile_reservation` with the
existing `certforge.governance.manage` SDK scope, tier2 and server-side Vault
credential reference. Its strict command-bearing schema is generated through
the existing contract generator. This declaration is not live registration.
The exact source-declared SDK set increases from 61 to 62 capabilities; manifest,
generated schemas and exact-count validators stay synchronized and strict.
The library entry point is
`SubscriberGovernance.reconcile_released_reservation(principal, run_id=..., reason=...)`.
It repeats live key, membership, role, organization, subscription and scope
authorization under the same immediate write transaction as the repair.

The method accepts exactly one reservation joined to a run in the principal's
tenant. It requires reservation `RELEASED` and run `COMPLETED`, `CANCELLED` or
`INFRASTRUCTURE_FAILURE`. An existing dispatch must be terminal and unclaimed.
For residual ownership, the stored lease must be parseable, timezone-aware and
expired under the canonical clock. A claim without proof of lease expiry is
refused. Active, unexpired, nonterminal, ambiguous or cross-tenant rows cannot
be repaired through this operation.

The transaction clears only `claim_token`, `lease_expires_at` and the reservation
update time, then reads back the cleared fields. SQL selects only the boolean
presence of a claim; neither API output nor audit contains a claim token or
idempotency key. It preserves run/outcome, dispatch, usage/compensation and all
other reservations. The existing audit chain records one
`certification.released_claim_reconcile` event with reason, terminal state,
prior ownership-presence flags and `meter_compensated:false`. Audit failure rolls
back the cleanup. A clean repeat returns `reconciled:false` with unchanged
reservation metadata and creates no second domain reconciliation event. Normal
API request-outcome auditing still applies to each request.

The response schema is
`echo.certforge.released-reservation-reconciliation.v1`. It reports tenant/run,
terminal run state, released reservation state, whether cleanup occurred,
claim/lease absence, durable reservation update time and uncompensated metering.
Unknown or other-tenant run IDs return the same `run_reservation_not_found`.

## Admission and operation boundaries

This source candidate is based on installed commit
`d8ad9fd881365801354b78a758632d2a31ab6828`; it is not an installed repair. The
existing d8ad API does not acquire this endpoint merely because source tests
pass. No SDK registration SQL is applied by this source change.

Normal delivery requires independent source acceptance, the required local and
hosted checks, exact-candidate CertForge and Certification App evidence, and
the normal owner release/readiness and deployment/rollback admission applicable
to the changed service. Any installed source change invalidates old exact-source
commitments: refresh the installed source closure, readiness and owner guard
bindings rather than relabeling d8ad evidence. Until then, do not import this
candidate into the live service, autoload it, mutate the live database directly,
or weaken the quiet guard.

Once the exact implementation and owner route are admitted, the owner must first
read the exact tenant/run/reservation/dispatch, prove no active work, preserve the
pending-work projection and metering/history fingerprints, then use the ordinary
authenticated API. Read back the exact response, canonical row/audit state and
all protected projections; repeat once to prove idempotence. Existing grants
must cover `governance:manage`; absent permission is an admission dependency,
never a reason to mint or broaden a key implicitly.

Rollback of this source candidate is an ordinary scoped revert or retention of
the previously admitted service revision. A later successful terminal-ownership
cleanup must not be undone by restoring an old claim token or rewriting history.
Live service rollback and any database recovery require their separately tested
owner procedures; this source change performs neither.
