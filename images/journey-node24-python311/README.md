# Node 24 and Python 3.11 journey candidate

This recipe builds an **unadmitted development candidate** for journeys that need
Node 24.19.0 and Python 3.11 together. It selects official Linux/amd64 Debian
Trixie manifests by immutable digest and copies Node with its matching C++/GCC
runtime libraries into the pinned Python image. No package installation or target
code is involved. Installer packages and bundled ensurepip wheels are removed:
the declared journey needs Node built-ins and Python's standard library only.
This avoids carrying unused installer vulnerabilities into the runtime. Build
with networking disabled for all RUN steps.

```text
docker build --network=none --platform linux/amd64 --pull=false \
  --tag echo-certforge/discord-memory-candidate:<owned-build-id> \
  images/journey-node24-python311
```

The image sets `ECHO_TEST_PYTHON=/usr/local/bin/python3`, UTF-8 pipe encoding and
non-root UID/GID 65534. Execution still requires the existing DockerSandbox
network, read-only root/source, capability, privilege, CPU, memory, swap, PID,
tmpfs, timeout and cleanup controls. The recipe does not select a live image,
change any project, alter a policy, create credentials or sign an attestation.

Before admission, require exact source/recipe/base provenance, a complete OS and
language SBOM (including the copied Node libraries), current vulnerability and
secret scans, independent build comparison, and an attestation from the existing
trusted image authority. The existing `scan_dockerfile`, `scan_build_context`,
`evaluate_image_admission` and P4 evidence schema remain authoritative. The
twelve-role `seal_p4_images.py` wrapper does not itself accept this different
layout; do not fabricate its record or relabel a local image as admitted.

The API and worker now bind a selected sandbox's actual pinned image and complete
execution profile to the environment identity, reusing the prior sandbox-profile
repair. This intentionally invalidates legacy fixed-label environment reuse.
Before a reviewed owner rollout, drain or reconcile queued reservations through
supported governance; do not edit their identity or rewrite completed evidence.
The source commit, configured image and fresh environment digest must match in
the API, dispatcher, signed evidence and eventual production E2E attestation.

For a reviewed exact-run operation, the existing dispatcher accepts `--once`,
`--run-id` and `--sandbox-image`. The shared dispatcher can race that claimant;
there is no per-project selector in the current submission schema. A source-only
candidate or test does not authorize stopping the shared dispatcher or changing
its configuration. An independently reviewed owner procedure must establish
admitted image identity, current queue/lease state, credential custody, rollback
and exact-source service acceptance before any such action.

Old failed runs remain immutable. A fresh final target SHA requires a new
idempotency key and actual signed evidence. Successful local/source journeys
cannot satisfy the independent production E2E rule or establish a 95+ bot grade.
