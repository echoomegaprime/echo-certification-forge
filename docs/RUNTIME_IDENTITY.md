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
Wheels include those two public declarations under `runtime_data/`; measurement
uses the actual installed package files and the same canonical names as the
source checkout. The installed interpreter directory is never treated as a
repository, and missing packaged declarations fail closed.

The API publishes `certification_environment_identity_digest`,
`runner_image_digest`, `runtime_profile_schema`, `runtime_journey_json`, and
`runtime_journey_mode`.
The production dispatcher loads the same profile and passes its actual sandbox to
the worker. A non-null operator journey remains an exact pin. A null journey
selects `per_job` mode: each persisted job supplies its own bounded argv while
the operator's image, Docker command and isolation limits remain exact pins.
Before acquisition, the worker rejects a different sandbox, an incompatible
operator journey, or an environment declaration that does not match the measured
job inputs.
It measures the effective inputs again and uses existing transactional environment
reconciliation to fence changes before target execution. Source and installed
dependencies must be immutable within a release; restart API and dispatcher on a
release or public-profile change. A missing/unreadable measured input fails closed.

For a shared service, resolve the exact job argv through authenticated read-only
`POST /v1/subscriber/runtime/environment` (`echo.certforge.runtime_environment`).
It accepts only `journey` (null or 1–32 nonempty strings of at most 2048 characters,
without NUL). It returns canonical `environment` components and
`submit_environment` for the existing submission contract. Use that exact argv
and declaration together. This operation does not execute code, create a run,
reserve quota, select an image, or certify readiness. It uses the existing
subscriber read permission and rate/authentication controls.

The null-journey environment advertised by `/v1/status` describes the shared
profile's default plan; it is not a declaration for a job with a different argv.
Without an explicit image profile, the selected pinned default sandbox is used.
Omitting a real job journey still fails the mandatory critical-journey gate.
The existing minimal Python image does not imply that target dependencies are
installed. A dependency-complete image must be built, independently pinned and
selected by the release owner before running a program that needs those packages.

## Migration and rollback

All old fixed-label environment commitments differ from the measured contract.
Existing verdicts are not re-signed, upgraded, or silently reused. Queued requests
declaring an old or mismatched environment fail closed through existing worker
reconciliation. After the bounded dispatch attempts are exhausted before execution,
the run becomes `INFRASTRUCTURE_FAILURE`, its reservation is released, and its
original billing-period charge is compensated exactly once. No target acquisition
is allowed for a mismatched profile. After admission of the changed release, callers must obtain the
fresh per-job environment and submit a new exact-identity request with a new
idempotency key. Nothing in this change automatically updates production profiles,
queues, trust roots, collector attestations, or service units.

This repair retains measured deployed revision
`d8ad9fd881365801354b78a758632d2a31ab6828`. The ECF release reconciliation merges
canonical main `4f7d99e2dd4422f3d81cf5b709581be963f5818a`, measured-runtime repair
`690ea5b58cee637e76bb1011e7d08da0895422fa` (PR28), and image-admission/local-intake
repair `77cba79e0fd971ad7301203242108c76998d26e5` (PR29). It preserves the deployed
acquisition and production-E2E protections alongside main's longer bounded
readiness polling and retained staging diagnostics. The P7 intake probe uses one
measured environment for its exact journey and the same manifest-scoped request
digest and idempotency key as production intake. Its v1 host-worker scenarios are
subscriber regression evidence, not v2 Docker runtime admission. Release acceptance
must separately exercise the authenticated runtime endpoint and actual pinned
Docker worker under the production policy. Original owner branches are retained.
This source reconciliation is not runtime admission, a certificate, or a
production promotion. The exact combined source still requires those gates;
replacing the deployed release with older main is not a valid rollback strategy.

Focused verification is `python -m pytest -q tests/test_runtime_identity.py tests/test_runtime_job_binding.py`.
The tests cover changed image, journey, policy, harness and sandbox limits;
secret-field rejection; service/dispatcher/worker identity agreement; and rejection
before acquisition, authenticated per-job resolution, caller-image rejection,
and equivalent source/real-built-wheel harness commitments. Subscriber regression
tests additionally verify that changed
journey commitments cannot execute or receive a signed verdict. Full repository
and acceptance checks remain required before a release claim.

Host Python and kernel measurements are intentional identity inputs. A host update
can invalidate queued job declarations even if application source is unchanged.
Coordinate host updates with API and dispatcher restarts, resolve a fresh per-job
environment, and submit a new identity-bound request. Do not keep old identity
labels or weaken these measurements to preserve availability.
