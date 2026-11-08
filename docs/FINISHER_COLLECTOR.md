# Finisher observation collector candidate

This collector validates fresh, authenticated, independently recalled Finisher
journeys through a separately admitted owner probe. Its only successful output is
`UNSIGNED_CANDIDATE`, with `release_verdict: NOT_READY` and
`signature_verified: false`. It does not sign, enroll a collector, install an
attestation, create a worker grant, change the staging gate or deploy a target.

The implementation uses the installed `generic-production-v1` contract from
CertForge source `d8ad9fd881365801354b78a758632d2a31ab6828`. It reuses the canonical
JSON hash and existing restricted-content checks. Existing trust verification
rejects its unsigned payload. A passing test fixture is not live evidence.

## Current missing prerequisites

There is no owner-probe executable included in this candidate and no newly
admitted collector or signer. The CLI fails with `owner_probe_unconfigured` when
that dependency is absent. An implementation that returns configured booleans or
replays a saved observation is not a valid owner probe.

The independently admitted owner must supply and review the real adapter to the
existing authentication, control, observation and receipt services. Its entire
executable dependency closure must be immutable and hash pinned, and its runtime
identity must have actual admission for this exact policy, target and operation.
Hash pins provide integrity, not authorization. The implementer of this candidate
cannot make themselves an independent collector, signer or reviewer by changing
their role label. Existing Maximalist signatures and the Forge integrity
bootstrap do not attest to Finisher.

There are also concrete selected-runtime constraints. In transport source
`1b79e2ee932927b3e408ff2ed43eb8d248875aaf`:

* `SYSTEMS/finisher_cloud_integration/cloud_front.py` treats `start` as
  reconciliation of an already running singleton. A stopped singleton requires
  an independently admitted owner bootstrap operation; frontend `start` does not
  provide one.
* `SYSTEMS/finisher_cloud_integration/ui_runtime.py` returns a read-only
  `echo.finisher.ui.snapshot.v1` for status. Accepted/applied are journal control
  fields, not a status mutation receipt.
* Native controller halt is `halted`, not `stopped`. The Cloudflare observer in
  `SYSTEMS/cf_terminal/cloud/container_control.py` currently requires a live
  process for `readback_verified`. It cannot prove terminal halt after that
  process exits. The UI projection also omits the controller's `halted` field.
  The owner probe must not invent terminal proof; that source/runtime dependency
  must be repaired, independently reviewed and actually observed first.
* Worker-image rollback alone does not restore a compatible checkpoint. The
  runtime rejects a checkpoint whose source identity differs. A separately
  authorized compatible checkpoint/config restoration and exact readback are
  prerequisites. This collector does not provide a reset or data-restore route.

These constraints remain holds. They are not requests to weaken the gate or to
reuse another product's trust identity.

## Invocation and private configuration

Run on an admitted Linux observer host using its normal opaque scoped broker
environment. Do not copy another client's auth state or put credentials in the
policy, command arguments, receipt or output.

```sh
python scripts/collect_finisher_e2e.py \
  --policy /ABSOLUTE/PRIVATE/owner-policy.json \
  --policy-sha256 ACTUAL_POLICY_FILE_SHA256 \
  --output /ABSOLUTE/PRIVATE/new-unsigned-observations.json
```

The policy file must be regular, at most 64 KiB, owned by root or the observer
identity, and not writable by group/other. Its exact bytes must match the pin.
The output parent must be a canonical private directory owned by the observer;
output is created exclusively with mode 0600. No existing output is overwritten.
Exit 0 means collection succeeded **unsigned**; exit 2 is a verified hold; exit 3
is invalid input or I/O failure. Fixed reason codes do not include raw provider
responses or credentials. Structured logs contain only operation names, receipt
identifiers and hashes.

Policy fields:

| Field | Required value |
| --- | --- |
| `schema` | `echo.finisher.collector-policy.v1` |
| `tenant_id`, `collector_id`, `authority_id`, `execution_id`, `admission_id` | Actual distinct scoped identities; bounded identifiers |
| `bindings.target_identity_digest`, `environment_identity_digest` | Exact canonical CertForge identity hashes |
| `bindings.source_commit` | Exact native or transport source being certified |
| `bindings.native_source_commit`, `transport_source_commit` | Full 40-character immutable source commits |
| `bindings.artifact_sha256`, `native_artifact_sha256` | Actual artifact byte hashes, not a tag or source SHA |
| `bindings.image_digest` | Actual `sha256:` OCI index/image digest, distinct from archive byte hash |
| `bindings.account_id`, `application_id`, `durable_object_id` | Complete actual Cloudflare tuple; 32 hex account and 64 hex DO IDs |
| `bindings.installation_id`, `owner_id`, `cloudflare_origin` | Exact installation, admitted owner and HTTPS origin without userinfo/query |
| `rollback_artifact_sha256`, `rollback_source_commit` | Actual distinct compatible prior artifact/source |
| `rollback_checkpoint_sha256`, `rollback_configuration_sha256` | Owner-approved immutable prior checkpoint/configuration digest pins |
| `recovered_checkpoint_sha256`, `recovered_configuration_sha256` | Owner-approved recovered candidate checkpoint/configuration digest pins |
| `providers` | Exactly claude/codex/gemini/grok, each with exact `model` and nonpersonal `account_sha256` |
| `probe.command` | Exactly `[ABSOLUTE_INTERPRETER, ABSOLUTE_REVIEWED_PROBE_SCRIPT]` |
| `probe.sha256` | Exact SHA256 pins for those two files in the same order |
| `probe.dependencies` | Absolute dependency paths mapped to immutable SHA256 pins |
| `probe.timeout` | Whole process deadline from 1 to 120 seconds, default 120 |

The four checkpoint/configuration pins must come from the owner's reviewed,
immutable prior-baseline and recovered-candidate manifests **before** collection,
not from a candidate's self-reported readback. Mutable runtime checkpoints must
be deliberately frozen or version-addressed for meaningful exact comparison.
The owner admission verifies these immutable policy values as part of the
canonical policy hash; arbitrary well-formed digests are not rollback evidence.

The transport runs the interpreter in isolated mode, accepts no shell text or
provider flags, bounds stdin to 8192 bytes and stdout to 128 KiB, discards stderr,
and checks executable pins before and after each operation. Nonblocking stdin
and stdout share the same deadline, including a child that never reads input.
The process owns its group and reaps it on every exit. Environment inheritance is
limited to normal PATH/HOME/locale/TLS paths and opaque SOL broker/run/role/state
variables, including `SOL_STATE_DB`. No API billing or custom provider route
fallback is added. Owner admission must make pinned files/closure immutable to
untrusted concurrent writers; rehashing is not a sandbox or an administrative
grant.

## Public owner-probe protocol

Each invocation receives one JSON object on stdin and returns one JSON object on
stdout. The owner adapter performs real authenticated requests; it must not load
responses from fixtures, accept a caller-supplied `verified: true`, mint a grant,
or turn a blocked command into an indirect interpreter/SSH/container execution.

Request schema `echo.finisher.owner-query.v1` contains:

* `operation`: `admission`, `observe`, or `recall` only.
* A new unpredictable `nonce`, plus canonical `policy_sha256`.
* Exact `admission_id`, `execution_id`, `tenant_id`, `collector_id`, and complete
  `bindings` as above.
* For `observe`: collection `challenge`, finite `kind` and `name` below.
* For `recall`: exact `receipt_id` returned by the previous actual observation.

Response schema `echo.finisher.owner-response.v1` contains the identical nonce,
`request_sha256` over canonical full request, actual `authority_id`, independently
established `authenticated: true` and `authorized: true`, a fresh timezone-aware
`observed_at`, and `result`. These fields are trusted only because the owner has
independently admitted and pinned the real adapter and its authenticated service
routes. This candidate is a verifier/transport, not that authority service.

For `admission`, result must contain `allowed: true`, `independent: true`, exact
policy hash, all request identities/bindings, an expiry in the next hour,
`operations: ["observe", "recall"]`, and `restoration_allowed: true`. The actual
admission must cover the complete finite journey including its controls,
negative checks, prior snapshot/config rollback, owner restoration, and all
24 separately recalled `stability-front/<index>:<front>` route observations.
The collector rechecks admission before every observe and recall, and at
completion. An aggregate health result is not authority for a named route.

For `observe`, result contains a new actual `receipt_id`. The collector then
requests `recall`; recall result contains the identical ID, exact `content`, and
canonical `content_sha256`. Content schema `echo.finisher.observation.v1` contains
the receipt ID, `mode: live`, exact collection challenge/kind/name, identities and
bindings, a fresh `observed_at`, and the journey result. No receipt or provider
invocation may be reused. The complete collection is bounded to 30 minutes.

The receipt service must preserve actual authenticated provenance and permit
exact readback. Merely echoing the just-submitted request or returning an
unverifiable success flag does not satisfy this contract. The separately
admitted signer must independently verify the receipt manifest before signing.

## Finite journey and result contract

The ordered fronts are `auto`, `cauto`, `gauto`, `grauto`, `CFauto`, `CFcauto`,
`CFgauto`, `CFgrauto`, mapped to claude/codex/gemini/grok respectively.

1. `front/<front>` performs the authorized real front journey. Its result binds
   actual provider/model/account, run/worker/session and native invocation IDs;
   observed model/subscription identity; exact resumed session; real scoped MCP,
   hook capture and exact capture readback hashes; live heartbeat; uncertain
   replay suppression; and process cleanup. It requires zero inference caused
   by readonly status. `start` has the actual `singleton_observed` shape with
   `already_running`, verified readback and exact target. `status_snapshot` is
   the real UI snapshot, with no top-level accepted/applied/request ID. It must
   be fresh, online, installation/resource/heartbeat/service verified, and bound
   to the actual full Cloudflare target and transport source. `controls` contains
   exactly pause/resume/halt, each with distinct actual `request_id` and
   `native_request_id`, matching `action`, exact full `target` including run,
   `submitted_at`, accepted/applied proof and paused/running/halted `state`.
   Each `readback` must independently match that target and transport source,
   have fresh `observed_at >= submitted_at`, verified installation/readback,
   and `controller.last_control_id` equal to the exact native request ID.
   The actual paused/halted flags must agree with the action. Pause/resume
   require active service and fresh heartbeat. Halt requires a fresh independently
   established `terminal_halt_verified: true`, `lifecycle: halted` and
   `online: false` observation after process exit without pretending that the
   exited controller still has a live heartbeat. A live controller setting its
   halted flag before cleanup is insufficient. A stale
   observation, replayed native ID, other run/installation, accepted write,
   pending journal or unavailable terminal readback must fail.
2. Immediately after **each** halt, `restoration/<front>` requires
   `method: admitted_owner_operation`, the same admission ID, previous run ID,
   a new actual owner operation ID, and a fresh healthy exact-target snapshot.
   This is a normal independently authorized owner bootstrap, never a synthetic
   frontend start receipt. Without an actual admitted restoration route the
   collection stops; it does not continue to the next front in a stopped state.
3. `negative/<name>` checks unauthenticated, wrong_owner, wrong_installation,
   wrong_source, invalid_token, expired_token, stale_control, replayed_control,
   out_of_scope, redirect and forbidden_native_route. Each result must prove
   denial, no side effects, and identical bounded before/after state hashes.
   Credentials and personal identity never enter the receipt. A redirect check
   must refuse rather than follow an unadmitted destination.
4. `rollback/restore-and-recover` requires actual prior and recovered artifact
   and source readbacks, both checkpoint source matches, and verified restored
   and recovered state. All four actual checkpoint/configuration SHA256 readbacks
   must **equal their separately owner-approved immutable policy pins**. A digest
   of the right length, a truthful-looking boolean, or only a Worker image
   replacement is insufficient. It runs **before** final stability.
5. `stability/0`, `/1`, `/2` establish aggregate health, resource admission,
   fresh heartbeat and zero unexpected restarts only. Legacy aggregate
   `snapshots` are rejected; they cannot count as eight-front evidence.
   Each aggregate probe is followed by **eight separate** owner-issued,
   independently recalled `stability-front/<index>:<front>` receipts, each
   bound to its exact challenge/kind/name, front and expected provider. Each
   route result requires `route_readback_verified: true`, a fresh healthy
   `snapshot`, and `snapshot_sha256` equal to the canonical digest of that
   snapshot. Reusing another route's receipt/result fails named-route binding.
   All routes may legitimately share the single Cloudflare singleton `run_id`;
   route receipt provenance, not distinct run IDs, proves eight-front coverage.
   The first-to-third aggregate observation interval must be at least 30 seconds.
6. `external/acceptance` requires a distinct independent reviewer, actual Access
   session, immutable UI assets, exact HTTPS origin and accepted live behavior.

Tests use explicitly synthetic authority fixtures to exercise forged, replayed,
stale, mismatched, revoked and incomplete receipts. They also exercise real local
child processes on FORGE for small-pipe/nonreading deadlines, output bounds and
opaque broker state inheritance. None of these tests call a real provider or
produce admission, signing, deployment or production-acceptance evidence.

## Unchanged signing and deployment boundaries

Only after real observations and independent review may an already admitted
independent signer add its actual key identity and produce the existing signed
production-E2E envelope. The normal trusted-key verifier must accept that exact
envelope and its source/target/environment/manifest bindings before re-running
certification. Private signing keys never belong in this collector or its worker.

The existing deployment admission hook remains unchanged:

```sh
python /home/forge/echo-certification-forge-current/scripts/deployment_admission_hook.py \
  admit --forge-url ADMITTED_FORGE_ORIGIN --tenant ACTUAL_TENANT \
  --artifact-digest ACTUAL_ARTIFACT_BYTE_SHA256 --environment staging \
  --environment-identity-digest ACTUAL_ENVIRONMENT_IDENTITY_DIGEST \
  --rule-manifest-digest ACTUAL_RULE_MANIFEST_DIGEST \
  --deployment-id ACTUAL_DEPLOYMENT_ID --requested-by ACTUAL_ADMITTED_OWNER
```

Any credential required by that existing hook stays opaque in its normal owner
environment; do not paste values into this command or handoff. Staging and
production gates remain enforced. Actual outcome registration and exact readback
remain owner responsibilities after an admitted deployment. This collector's
source, tests, draft PR or unsigned output cannot clear those gates.
