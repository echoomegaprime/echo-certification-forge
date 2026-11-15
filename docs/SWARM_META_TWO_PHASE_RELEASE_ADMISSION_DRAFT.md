# Swarm ↔ Meta Hatch: governed two-phase release admission (DRAFT)

**Status:** proposal for policy-owner, CertForge maintainer, release owner, and HAMMER collector review. This document **does not approve** a deployment, change a verdict, create an attestation, enroll a key, or authorize a service window.

**Tracking:** [CertForge #51](https://github.com/echoomegaprime/echo-certification-forge/issues/51); [Swarm PR #16](https://github.com/echoomegaprime/echo-swarm/pull/16). Candidate source commit: `f65935510f35b035536e08b6ae292cd821f02327`.

## 1. Verified current constraint

- A reproducible, clean exact-commit FORGE checkout and isolated full-app loopback smoke have accepted the exact Meta callback `https://agent.meta.ai/api/hatch/oauth/callback` with HTTP 201. Independent HAMMER public HTTPS *staging* canary also accepted that URI, rejected lookalikes, and was torn down. These are **staging evidence only**.
- Independently observed canonical live `POST https://swarm-app.echo-op.com/oauth/register` still returns HTTP 400 `invalid_redirect_uri` (2026-11-11 01:51 UTC). No confirmed production fix.
- The exact-target CertForge run `cert_68c302c879ce0c73ac1f859a6396aefbdc08a470` is `NOT_READY` with no valid production E2E signature. The trust-rooted production attestation requires exact target and environment identity, a fresh signed envelope, and 6 baseline checks. `PRODUCTION_READY` is an invariant of the deployed deterministic verdict engine, not a label to set manually.
- The trusted HAMMER Maximalist production collector requires the candidate code **already deployed** to the canonical service, exact production source-tree/readback equivalence, public probes, live 40-seat and six controls. Production still contains the previous SHA, so it cannot truthfully sign this candidate as production.
- **Circular dependency:** operator instruction disallows production promotion/restart until `PRODUCTION_READY`; the existing evidence collector cannot supply production proof until deployment. Staging evidence cannot break this dependency. No automatic release is possible under both constraints as currently written.
- The local deployed CertForge source at `/home/forge/echo-certification-forge-current` includes `src/echo_certification_forge/production_e2e.py` and production enforcement in `verdict.py`. The deployed tree records release commit `d8ad9fd881365801354b78a758632d2a31ab6828`, which is reachable in `echoomegaprime/echo-certification-forge` and contains `production_e2e.py`. GitHub `main` currently **diverges** from this deployed commit (the deployed commit is 16 commits ahead and 1 behind `main`), and default `main` lacks that file. Reconcile and merge the exact deployed line safely before any executable gate changes; never patch the stale default branch expecting it to change the live gate.

## 2. Immutable phase and state separation

### Phase A: isolated exact-head *preproduction* proof

All checks below are necessary. Their success creates only a **candidate dossier** (`CANDIDATE_VERIFIED` in an out-of-band report); it **must never** set CertForge `PRODUCTION_READY`, create `certforge.production-e2e.v1`, or satisfy a production `DeployGate`.

1. Freeze and reacquire the GitHub PR head. Require exact match to the candidate SHA, acquisition artifact SHA-256, target digest and environment digest. Recompute if head changes; never reuse a previous receipt.
2. Launch an independent, rollbackable, network-isolated full **app + fusion bridge + 40-seat live worker** stack at distinct staging ports/hostnames; separate OAuth client state, identity, provider sessions, queues, logs and secrets. Do not reuse, restart or relabel the canonical production service.
3. Explicitly authorize bounded paid live-provider test budget and dedicated test credentials; redact tokens, client secrets, API keys and prompts containing private user data. No mock seats, simulated successes or retroactive logs.
4. Independently probe from HAMMER through real public HTTPS: exact Meta callback 201; host/path/scheme/query/port/trailing-slash lookalikes 400; existing allowlisted ChatGPT/Claude callbacks 201; OAuth discovery 200 with matching issuer; unauthenticated MCP 401; no cross-environment registration replay.
5. Complete an authentic **40 distinct live seats**, separate Trinity synthesis, contradictions/dissent, dynamic retasking, resume/recovery, provider receipts, SDK capability checks, negative authorization checks and at least 3 stability probes. Record per-seat ID, timestamp, provider mode, actual attempt/result, idempotency key, failure and audit chain with no private credentials.
6. HAMMER independently verifies candidate source/tree hashes against its own fetched immutable source; timestamps and signs the *candidate/staging* dossier with an **explicitly separate schema/domain** if such a collector is approved. Private signing keys never leave HAMMER. Record key ID, signature, target/environment scope, collection time, expiry and chain-of-custody. Do not assert production or use the existing production trust directory to smuggle staged evidence into production verification.
7. Tear down temporary public canary hostnames and tunnels by the identities actually created; verify cleanup. Keep production status unchanged.

### Admission between A and B: **explicit policy owner decision required**

The current no-promotion-until-`PRODUCTION_READY` rule remains in force. If it is not **formally amended**, the workflow stops here with `BLOCKED_POLICY_CIRCULARITY` even if every staging check passes.

One possible reviewed amendment is a **time-limited, single-SHA, signed and rollback-capable production canary exception**, granted by a release-policy authority. This is a **new authorization type**, never equivalent to `PRODUCTION_READY`. It must specify exact SHA and digests, operator/change-window owner, canonical host and isolated route, maximum duration, health and rollback deadlines, independent observer, revocation conditions, and rollback artifacts. Any proposal must obtain formal approval before it is implemented or exercised; the present instruction explicitly forbids production promotion/restart without `PRODUCTION_READY`.

Alternative policy designs can be submitted for review, but cannot silently redefine `PRODUCTION_READY`, point a production collector at staging, bypass the pinned HAMMER key registry, or mark staging checks as production checks.

### Phase B: authorized canonical production verification (NOT AUTHORIZED NOW)

**Only after** the policy authority explicitly resolves the circularity and grants a valid reversible service window (or another equally strict approved admission mechanism):

1. Freeze candidate identity and code provenance again; ensure rollback snapshot, operator authority, bounded window and bridge/worker capacity.
2. Execute only the specifically authorized reversible change. Immediately read back exact SHA and source-tree/worker identity from the **canonical** public service, inspect service restart count and health, and confirm that no unrelated workload changed.
3. Run **new** full 40-seat live-provider canonical production E2E and all negative/security controls while independently observed by HAMMER. No replay of the Phase A result.
4. HAMMER verifies raw evidence, actual canonical deployment SHA/tree, exact target/environment digests, three public TLS stability probes and custody; signs a fresh `certforge.production-e2e.v1` only when all requirements succeed. Use the existing pinned public trust-key verification, not any collector-provided trust key.
5. Submit a fresh exact-target `certforge.release-strict.v2` certification referencing the genuine envelope; accept only verified `COMPLETE` / `PRODUCTION_READY` with valid unexpired signed receipt and exact evidence Merkle root. Do not recycle certs for `b069ab08`.
6. Fail closed and restore the snapshot on any health/readback/seat/signature/certification failure; log rollback and independent post-rollback health. Do not mask failure by simply marking the old service healthy.
7. Once all gates actually pass, confirm canonical exact callback `POST /oauth/register` returns 201 and independently complete the **real Meta Hatch OAuth flow** using a connected authorized account. A 201 registration alone is not restored OAuth.

## 3. Deterministic rejection matrix

All of the following must yield **not production-ready** with an auditable reason:

| Input | Mandatory rejection |
| --- | --- |
| Missing candidate or production evidence | Fail closed; no implicit attestation |
| Staging proof provided where production proof is required | Wrong domain/schema; never `PRODUCTION_READY` |
| Expired, future-dated or overlong attestation | Reject freshness |
| Mismatched SHA, target/environment digest, artifact/tree hash or issuer | Reject identity |
| Self-signed/untrusted collector, wrong HAMMER key, forged or missing signature | Reject custody |
| 39/40 seats, mock/fallback provider, incomplete Trinity/dissent/recovery | Reject critical journey |
| Failed unauthorized-MCP, malicious callback or permission control | Reject negatives |
| Less than 3 public stability probes or stale runner | Reject observability |
| Missing, unsigned or expired window; unauthorized traffic switch | Refuse mutation |
| Canonical readback drift or worker tree mismatch | Stop, restore verified rollback |
| Deployment failed midway or rollback unsuccessful | Escalate incident; no ready claim |
| Previous-SHA receipts or stale queue artifacts | Never bind to new exact target |

## 4. Implementation review and acceptance path

- First align the *deployed* CertForge commit/package and source with the GitHub development repository. Do not treat a default-branch design PR as already deployed.
- Agree on separate candidate evidence schema, attestation collector ownership, policy authority, and signed exception protocol. Implement all changes as reviewed source-controlled PRs with unit, integration and hostile tests. Do not modify the live `production_e2e.py`, `verdict.py`, trust store or HAMMER production signer in place.
- Preserve existing six trusted HAMMER keys, CertForge immutable event history, lock/queue safety, existing Swarm PR #16 exact head and the unrelated ECHO Core Recovery Tick.
- Only a fully authorized and independently witnessed test of the amended policy can unblock a real production release. Until then the correct verdict is `NOT_READY`.

## 5. Test context (2026-11-11 01:52 UTC)

On FORGE, `/home/forge/.nvm/versions/node/v24.20.0/bin/node --test scripts/oauth-meta-callback.test.mjs` on the exact Swarm stage tree passed **1/1**. In the deployed CertForge source, `python3 -m pytest -q tests/test_production_e2e.py tests/test_evidence_and_verdict.py` passed **26/26**. Initial attempts using system Node 20 (no TypeScript type stripping) and the CertForge runtime venv (no pytest) failed as *test runner environment errors*; the corrected commands passed. These tests are neither a live 40-seat journey nor a signed production attestation.
