# Certification Forge Project Contract

The canonical PDF in `SPEC.md` is strengthened by the following release requirements. Conflict resolution is fail-closed and uses the stricter requirement.

## Product boundary

- EchoForge.com is the tenant-isolated subscriber platform.
- Echo Desktop is the private operator console and may only consume controlled APIs and public verification material.
- The subscriber plane never receives sovereign SDK access, private memory, administrative shells, runner credentials, or private signing keys.

## Identity and determinism

Every verdict binds the exact target digest, environment digest, mandatory-rule manifest digest, evidence Merkle root, signing-key identity, issue time, and expiry time. A changed source commit, archive, container digest, package, dependency state, configuration, runtime image, harness, prompt, model route, policy, or deployment identity invalidates reuse unless a versioned policy explicitly allows it.

`run_outcome` is one of `COMPLETE`, `INCONCLUSIVE`, `CANCELLED`, or `INFRA_FAILED`. `release_verdict` is one of `NOT_READY`, `CONDITIONALLY_READY`, or `PRODUCTION_READY`. Any non-complete outcome is `NOT_READY`.

## Evidence and signing

Evidence is append-only, content-addressed, hash-chained, and Merkle-rooted. Missing, altered, unredacted, cross-tenant, or structurally invalid evidence blocks readiness. Verdicts are Ed25519-signed by a trusted control-plane signer that workers cannot access. Self-signed untrusted public keys are rejected. Verdict lifecycle supports expiry, revocation, invalidation, and supersession.

An independent external anchor for finalized Merkle roots is mandatory before commercial production readiness; the local P1 implementation deliberately reports that capability as pending.

## Execution isolation

Untrusted targets execute only on dedicated ephemeral runners with non-root identity, read-only root filesystem, dropped capabilities, seccomp or stronger isolation, default-deny egress, resource limits, authenticated short-lived runner identity, replay protection, and verified cleanup. The control plane never executes customer code.

## Subscriber execution governance

A subscriber worker may acquire or execute only an existing `QUEUED` run with a matching `BOUND` reservation. The reservation and run must agree on tenant, project, policy, target type/reference, and target identity digest; claiming atomically transitions the reservation to leased `EXECUTING`. Direct, duplicate, stale, or mismatched invocation fails closed before acquisition. API intake first commits a metered reservation containing the complete validated submission, exact target, and journey, then idempotently materializes the deterministic run and transactional outbox. After a process crash anywhere in that gap, the restart-safe dispatcher reconstructs and binds the same run ID before dispatch; it may not invent or substitute identity, and it may claim only work compatible with its registered worker, execution location, signer, and signing authority.

Persisted governance is enforced at claim and revalidated immediately before execution. Private-worker mode requires an active registered worker and matching attestation, local-only mode requires both a local target and local execution location, and customer-managed signing requires the configured customer key and customer signing authority. Entitlement and retention lookup failures block execution, and retention is always capped by the current plan.

Worker claims heartbeat under an expiring lease. The execution boundary atomically revalidates subscription and governance, records both versions, transitions the run to `ACQUIRING_TARGET`, and transitions the reservation to `STARTED` before customer code can run. Expired pre-start claims safely requeue without quota compensation until the bounded retry limit; retry exhaustion or an expired started claim terminates as an infrastructure failure, releases concurrency, fails the dispatch, and receives one idempotent compensation in the original billing period.

All principal-authorized subscriber mutations repeat live API-key, membership, role, organization, subscription, and scope authorization inside the same write transaction. Billing activation, reactivation, renewal, and plan-change events require complete valid billing periods. Plan changes atomically reconcile retention and unsupported controls without leaving past-due, suspended, or cancelled states. A risk transition atomically revokes non-started claims and queued dispatches; only an ordered explicit activation/reactivation event may restore execution. Authenticated validation failures, denials, and unhandled errors are recorded in the immutable final-outcome audit chain.

## Intelligence boundary

GS343 may propose discovery, classification, and bounded harness repairs. Deterministic rules own the final verdict. Repairs may never alter target source, expected outcomes, fixtures that encode product behavior, evidence policy, or mandatory rules. R2D2 is presentation-only and cannot alter state or verdicts.

## Completion rule

Implementation, source validation, contracts, real runtime, failure and recovery, evidence package, scoped Git record, and Commander acceptance are distinct gates. A registered capability is not presumed visible, healthy, schema-complete, authorized, or runnable.
