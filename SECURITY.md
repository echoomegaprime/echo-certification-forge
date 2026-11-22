# Security policy

Echo Certification Forge is release-control infrastructure. Protecting signing boundaries,
evidence custody, tenant isolation, and fail-closed verdict behavior takes priority over feature
velocity.

## Supported version

Security fixes target the current `main` branch and the currently deployed release. Historical
commits are retained for evidence and are not patched in place.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report to
`security@echo-op.com` with:

- affected revision or endpoint;
- reproduction steps and expected impact;
- whether any signing, tenant, evidence, or secret boundary may be involved;
- safe contact details for follow-up.

Do not include live credentials, private keys, customer evidence, personal records, or exploit
payloads in public channels. We will acknowledge a complete report, reproduce it in an isolated
environment, issue a tracked remediation, and publish a disclosure when the fix is deployed.

## Security invariants

- A run begins and fails closed at `NOT_READY`.
- Private signing material never enters the public API or repository.
- Exact target, environment, policy, evidence, and lifecycle identities must agree.
- Replay, stale verdict, revocation, compromised key, and evidence-integrity failures block release.
- Production promotion follows staging smoke and exact-source readiness verification.
