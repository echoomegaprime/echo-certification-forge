# Measured worker runtime identity

The `certforge.runtime.v1` contract replaces fixed `certforge-worker-env:*` labels.
An environment commits to the selected manifest digest, exact journey argv and
mandatory rules, executable CertForge package bytes, dependency declarations,
actual Python executable and installed public dependency versions, host platform,
pinned sandbox image, and effective sandbox resource/isolation settings. Verified
adapter bundle and adapter-set commitments bind their prompt/configuration and
model-routing inputs. Missing adapter evidence is explicitly represented as absent;
it does not become a measured or qualified adapter.

The published `runner_image_digest` is the exact SHA-256 pin passed to Docker.
Both repository references ending in `@sha256:<64 hex>` and local immutable Docker
content IDs `sha256:<64 hex>` are supported. The sandbox commitment records
`repository_digest` or `docker_content_id` explicitly; an image ID is never
represented as a registry manifest receipt or fabricated `RepoDigest`.
Measuring it proves selection, not image execution. Journey and independently
signed production E2E evidence still prove execution and acceptance. A host fixture
run is identified as having no container isolation; its runner field commits to
the measured host runtime and is never presented by the production service as a
container-image attestation.

## Shared operator configuration

Set `ECHO_CERTFORGE_RUNTIME_PROFILE` to an operator-owned public JSON file for both
the API and dispatcher. `--runtime-profile` selects the same file for a CLI launch.
It accepts only `schema_version` (`certforge.runtime.v1`), `journey` (an argv array
or null), and `sandbox`. The sandbox accepts `image`, `memory`, `cpus`, `pids_limit`,
`tmpfs_size`, `timeout_s`, and `user`. Other fields fail closed. The image must use
an exact repository digest or content ID, user must be non-root, and limits must be positive. Omitted
limits use `DockerSandbox` defaults. Image selection may also come from
`ECHO_CERTFORGE_SANDBOX_IMAGE` or `--sandbox-image`; a conflicting profile pin is
rejected. The Docker command must agree between API and worker configuration.

The profile must contain no secrets, credentials, or private data. Arbitrary
environment variables and signing files are never scanned or hashed. Sandbox
`extra_env` is unsupported by this version and fails closed rather than excluding
an execution-affecting input from the commitment. Only package `*.py` files,
`pyproject.toml`, and `images/requirements.lock` are read for the harness commitment;
target files, `var/`, trust stores, and private keys are outside that traversal.

The API publishes `certification_environment_identity_digest`,
`runner_image_digest`, `runtime_profile_schema`, and `runtime_journey_json`.
The production dispatcher loads the same profile and passes its actual sandbox to
the worker. Before acquisition, the worker rejects a different sandbox or journey.
It measures the effective inputs again and uses existing transactional environment
reconciliation to fence changes before target execution. Source and installed
dependencies must be immutable within a release; restart API and dispatcher on a
release or public-profile change. A missing/unreadable measured input fails closed.

Without a profile, the advertised journey is null and the selected pinned default
sandbox is used. This is not a useful production acceptance plan: the mandatory
critical-journey gate remains failing until an operator selects a real journey.
The existing minimal Python image does not imply that target dependencies are
installed. A dependency-complete image must be built, independently pinned and
selected by the release owner before running a program that needs those packages.

## Migration and rollback

All old fixed-label environment commitments differ from the measured contract.
Existing verdicts are not re-signed, upgraded, or silently reused. Queued requests
declaring an old or mismatched environment fail closed through existing worker
reconciliation. After admission of the changed release, callers must obtain the
fresh service environment and submit a new exact-identity request with a new
idempotency key. Nothing in this change automatically updates production profiles,
queues, trust roots, collector attestations, or service units.

This repair is based on measured deployed revision
`d8ad9fd881365801354b78a758632d2a31ab6828`. Canonical main was separately measured at
`4f7d99e2dd4422f3d81cf5b709581be963f5818a`; their merge base is
`153ee6b6d40d6c789436b7081fafa9714bfb3a2c`. Main lacks deployed acquisition and
production-E2E protections. The repair must be reviewed against the deployed
baseline and reconciled with canonical history before promotion; replacing the
deployed release with older main is not a valid rollback or integration strategy.

Focused verification is `python -m pytest -q tests/test_runtime_identity.py`.
The tests cover changed image, journey, policy, harness and sandbox limits;
secret-field rejection; service/dispatcher/worker identity agreement; and rejection
before acquisition. Subscriber regression tests additionally verify that changed
journey commitments cannot execute or receive a signed verdict. Full repository
and acceptance checks remain required before a release claim.
