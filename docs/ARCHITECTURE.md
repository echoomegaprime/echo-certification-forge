# Architecture

Echo Certification Forge separates evidence production, evidence custody, verdict derivation,
signing, and deployment admission so that no single self-reported status can promote a release.

## Trust flow

```text
exact target + environment + policy
                |
                v
isolated journey execution --> append-only evidence --> independent anchor
                |                                      |
                +------------------+-------------------+
                                   v
                        deterministic verdict engine
                                   |
                                   v
                         isolated signed envelope
                                   |
                                   v
                      exact-digest deployment gate
```

HTTP mutations that accept a JSON body authorize in a FastAPI dependency, not
inside the handler. FastAPI validates bodies before it calls the endpoint, so an
in-handler check is a schema oracle: anonymous callers can distinguish 422 from
401 and brute-force the request shape. Dependencies run first, so malformed and
well-formed anonymous POSTs to `/v1/certifications` (and the other body-validated
subscriber mutations) return the same status and body. The authorized tenant is
the principal's organization, not a caller-supplied body field.

The intake and subscriber layers authorize a bounded run and reserve it idempotently. The runner
executes the declared journey in a constrained environment and records artifacts. Custody verifies
hashes and receipt order. The verdict engine derives `PRODUCTION_READY` or `NOT_READY` from policy;
it never accepts a caller-provided verdict. The deploy gate independently rechecks the signed
envelope, target and environment identities, evidence integrity, expiry, revocation, and lifecycle.

## Major modules

- `intake.py`, `subscriber.py`: authorization, quota, idempotency, and tenant boundaries.
- `runner.py`, `executor.py`, `sandbox.py`: execution lifecycle and evidence production.
- `evidence.py`, `custody.py`, `anchor.py`: append-only storage, receipt chains, and anchoring.
- `verdict.py`, `signing.py`: deterministic decision and isolated signature envelope.
- `deploy_gate.py`, `product_readiness.py`, `production_launch.py`: exact-source promotion.
- `certificate_graphic.py`: fail-closed presentation bound to both machine certificates.

Private keys remain outside the public service and source tree. Public verification uses published
trust material and never requires access to a signer.
