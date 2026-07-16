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

## Intelligence boundary

GS343 may propose discovery, classification, and bounded harness repairs. Deterministic rules own the final verdict. Repairs may never alter target source, expected outcomes, fixtures that encode product behavior, evidence policy, or mandatory rules. R2D2 is presentation-only and cannot alter state or verdicts.

## Completion rule

Implementation, source validation, contracts, real runtime, failure and recovery, evidence package, scoped Git record, and Commander acceptance are distinct gates. A registered capability is not presumed visible, healthy, schema-complete, authorized, or runnable.
