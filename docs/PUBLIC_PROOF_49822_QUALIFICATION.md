# Public proof qualification, task 49822

This candidate extends producer commit `2c95413650b4f333d84e50ba1c3b2672d15e6564`
on `agent/cert-proof-49822-20261112`. The original producer worktree and draft
PR 17 are preserved. This is source qualification, not production certification.

## Failure found and repaired

The complete producer baseline returned **739 passed, 4 failed, 1 skipped** in
the existing QUENCH owned Windows Job (1 GiB memory, 32 processes). All four
failures were `MemoryError` at the OCI member read: the expanded-rootfs byte
allowance was also passed as a roughly 1 GiB read-buffer request, including for
tiny archive entries. A separate first attempt could not collect tests because
the shared runtime lacked project dependencies; qualification uses a task-local
virtual environment without changing that runtime.

OCI members now copy through at most 1 MiB reads into an owned sibling temporary
file. Declared sizes are checked against the remaining cumulative rootfs
allowance before reading. Actual byte counts must match the declaration.
Input/output handles close before replacement, including self-hardlinks on
Windows. Failed reads and failed regular-file replacement preserve the previous
file, remove the partial temporary file, and leave the budget unchanged. A
directory replacement still removes the existing owned directory after copying;
that directory-removal step is not claimed to be atomic. Structured debug events
contain byte counts or exception type, not archive content or credentials.

The 1 GiB total expanded-byte limit and existing path, device, whiteout, inert
symlink and digest checks are retained. This repairs member materialization;
it does not make the entire OCI pipeline constant-memory. Registry blob buffering
and tree hashing are unchanged. It does not address the separate native Codex
worker memory failure or authorize restarting the disabled builder tick.

## Exact consumer boundary

The optional interop tests load the actual `certificate_chat.py` Git blob from
consumer commit `bf8471df40b7bf5eb3460e2364dddf38dd0e7ae0`, with required SHA-256
`c23e46579662e755638519e0d5854b8146ddc91758b7d549f1f2e7d378d9ba6d`.
Set `ECHO_CERTFORGE_CONSUMER_SOURCE` to that exported file. A different digest
fails; an absent snapshot explicitly skips consumer qualification. The loader
omits only the unused relative `github_ops` import and retains the verifier and
helper definitions. This is not a full consumer application or Commander
certificate ceremony acceptance test.

The producer's real publication/public-read routes provide the JSON consumed
by that verifier. Tests cover the round trip, missing identities, identity and
signed-payload tampering, absent trust pins, wrong repository/SHA, and public-read
revocation/expiry. Ephemeral test keys, synthetic attestations and process-local
trust fixtures are used. They are never production release evidence or installed
trust configuration.

## Reproducible checks and receipts

Evidence directory:
`D:\ECHO_OMEGA_PRIME\08_ARTIFACTS\commander-sol-e323a2e03b`.
The exact consumer export and its provenance receipt are under
`cert49822-consumer`; installed dependency versions are in
`cert49822-dependencies.txt`. Python is 3.13.15. Tests ran headlessly inside the
owned Job with unchanged physical/commit/disk admission floors and verified Job
closure. Use the task-local interpreter, or install this project's `.[dev]`
dependencies in an isolated environment and supply the pinned consumer export.

| Check | Result | Receipt |
| --- | --- | --- |
| New bounded-read regression before repair | 3 failed, 5 deselected | `cert49822-oci-red.log` |
| OCI regressions and existing OCI scenarios | 16 passed, 22 deselected | `cert49822-oci-final.log` |
| Exact consumer interop | 15 passed | `cert49822-consumer-interop.log` |
| `python -m pytest -q` | 768 passed, 1 skipped | `cert49822-pytest-final.log` |
| `python scripts/p1_acceptance.py` | passed, exit 0; all 3 scenarios passed | `cert49822-p1-acceptance.log`, `cert49822-p1-acceptance-report.json` |

P1 explicitly preserves `NOT_READY` for default and source-only evidence and
rejects tampering; its passing result is not a production-ready verdict. The
fresh generated `artifacts/p1_acceptance_report.json` was copied to the evidence
directory, then that generated worktree file was restored. Historical
`p1_verification_report.json` is not cited as current evidence. The full suite's
one Starlette/httpx deprecation warning is recorded, not suppressed.

## Live observations and remaining release work

Scoped SDK reads observed both services active/running. The consumer service's
configured working directory contains the exact `bf8471d...` release identity;
loaded file bytes were not verified. The producer reports `/healthz` status `ok`
and version `1.0.0` without a source commit. Its current release directory is not
a Git repository, and the SDK rejected `readlink` as outside its allowlist.
Producer loaded-source identity is therefore unverified. These are bounded
observations, not production acceptance.

Governed remote comparison confirmed draft PR 17's branch identical to producer
`2c9541...` before this derivative candidate. Independent review, governed source
integration, installed-source readback, real production E2E attestation and
release admission remain outstanding. No merge, deployment, hotpatch, live
trust-key addition, scope expansion or new signing authority was performed.
Parent task 49782 remains open. Existing holds 49360/49481 remain in force.
