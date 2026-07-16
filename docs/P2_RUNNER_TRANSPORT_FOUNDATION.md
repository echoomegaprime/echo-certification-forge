# P2 Runner and Transport Foundation

## Phase result

- `completed_phase_gate`: `P2`
- `run_outcome`: `COMPLETE`
- `release_verdict`: `NOT_READY`
- execution node: `FORGE`
- execution mode: equivalent hardened non-root containers on a rootful Docker Engine

## Implemented contracts

- strict immutable isolation profile and resource limits;
- short-lived run-scoped Ed25519 credentials separate from verdict-signing identities;
- typed authenticated requests and signed runner responses;
- nonce replay rejection and semantic idempotent retries with fresh nonces;
- durable leases, monotonic heartbeats, cancellation, state transitions, and orphan reaping;
- append-only evidence chunks with interruption/completion verification;
- tenant-scoped lease and evidence reads;
- safe ZIP/TAR extraction with traversal, link, special-file, and expanded-size rejection;
- immutable image digest, non-root user, read-only root, network `none`, all capabilities dropped, no-new-privileges, built-in seccomp, Docker AppArmor, and cgroup v2 limits;
- exact ownership labels and cleanup limited to recorded container IDs.

## Real FORGE acceptance

All cases passed:

- isolation identity and inspect drift;
- CPU exhaustion;
- PID/fork exhaustion;
- disk-fill quota;
- file-size quota;
- hostile install-script root mutation and network exfiltration;
- timeout;
- cancellation;
- runner crash;
- authentication failure;
- expired identity;
- replayed request;
- duplicate idempotent transition/request behavior;
- lost heartbeat and orphan reaping;
- cross-tenant retrieval denial;
- archive traversal and symlink rejection;
- interrupted and completed evidence upload.

The acceptance preserved all 21 unrelated pre-existing containers and removed all nine exact run-owned containers with zero cleanup errors.

## Evidence

- `artifacts/p2_forge_acceptance.json`
  - bytes: `20807`
  - SHA-256: `d563aefcb121f91f5b6beda0f82ce80d776dd7bc6f2caaf6253226370883ef68`
- `artifacts/p2_forge_acceptance.summary.json`
  - bytes: `12256`
  - SHA-256: `3d17fee069b44b30794ee1f5ef871934406a785307e2b64724f8a59956b81093`
- runner image: `sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99`
- isolation profile: `d43e10e46744391c5a420905f8096eeb3a6150ebb2576413765fd3c1778d8930`
- `runner.py` source identity: `19ebf1354779b00a8601da8aea8f456eb4741087b77b995591281fb8226f8e8b`
- acceptance source identity: `4c83a1871fbf9ef4931251bdcbfebc3ac5ed52fd53621cd79b5a49bb7c5febe4`

## Degraded infrastructure

- The available Docker Engine is rootful. P2 proves an equivalent hardened non-root container foundation, not a rootless daemon.
- `echo.functions.search` and `echo.functions.locate` were registered but live calls returned Cloudflare 502 while the locator health endpoint remained green.
- `echo.nodes.copy` and Action Broker execution require a tier-2 HMAC envelope not available to this task; no bypass was attempted.
- GitHub Actions remains `CI STARTUP BLOCKER — ROOT CAUSE UNRESOLVED`.

## SDK capability visibility

- Required `echo.skills.*` capabilities were catalog-visible, registered, authorized, and successfully invoked before substantial P2 work.
- Central catalog search for `echo.certforge.*` returned zero matches.
- Exact lookup of `echo.certforge.health` returned `capability not found`.
- Central catalog search for `echo.builds.log` returned zero matches.
- Exact lookup of `echo.builds.log` returned `capability not found`.
- These are registration/catalog blockers. They are not classified as authorization failures because no registered capability exists to authorize or invoke.
- `echo.node.exec` was registered, authorized with the explicit SDK confirmation token, and successfully executed real FORGE inspection and acceptance commands.
- `echo.nodes.copy` and Action Broker execution were registered but unavailable to this task because they require a tier-2 HMAC envelope; no bypass was attempted.

## Remaining whole-product blockers

- production signing service or HSM/KMS separation;
- independent external Merkle-root anchoring;
- production hostile-runner qualification and worker-image supply-chain controls;
- GS343/R2D2 adapter identity and fallback proof plus quality qualification;
- central `echo.certforge.*` capability registration and health proof;
- real deployment-path exact-digest enforcement;
- remaining productization, retention, deletion, export, billing, and support-access controls.
