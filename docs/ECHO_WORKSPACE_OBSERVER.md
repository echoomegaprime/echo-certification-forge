# Echo workspace observations

`echo_certification_forge.echo_workspace_probe` is a concrete observer for the
shipped Echo CLI owner API and Echo ADK workspace. It addresses issue #42.

It operates on an explicitly identified, empty, task-owned Linux canary. It
does not launch a candidate, stop its services, load production data, invoke a
model or provider account, create a signing identity, sign an attestation, or
issue a release verdict. The service owner retains the lane's lifetime and
shutdown controls.

## Actual execution

The observer independently hashes the pinned Git archives, verifies their PAX
commit identities and every manifest source file, checks installed ADK source
and built CLI artifact bytes, and compares the running processes and loopback
listeners with the declared lane. It repeats the identity measurement after
the journeys. The archive and manifest hashes must come from the owner's
reviewed staging receipt; a hash alone does not establish authority.

It then obtains the native Prime cookie from the actual landing page and calls
the same owner routes used by the UI. The finite journey covers:

- Missing-session, cross-origin, missing-request-header and worker Host denials.
- Agent and paused bot creation with no capability scopes and a zero dollar cap.
- A paused idempotent event, duplicate receipt readback and cancellation before
  dispatch; an empty bot's resume/pause controls.
- Bot-scoped memory write/read, stale revision refusal, isolation and restore.
- One-time, monthly, yearly and five-field cron schedule persistence while paused.
- Credential-free department export, digest verification, stale-plan refusal,
  reviewed import and verification that all imported bots remain paused.
- Real sandboxed per-bot Chromium snapshots and a screenshot, screenshot digest
  verification, cross-bot artifact refusal and a denied external navigation.
- Three spaced health/budget observations and actual marketplace availability.
- Cleanup of only acknowledged task-owned bot and agent identities.

No mutation is automatically retried. An unknown creation result leaves the
run unsuccessful and requires reconciliation; the observer does not invent an
ID or delete a resource based only on its display name. Cleanup has a separate
90-second allowance and never claims an uncertain delete succeeded. Terminal
run/audit records may remain in the disposable lane until its owner removes it.

## Invocation

The lane must contain the reviewed `running.json`, `runtime-files.json` and
reference-only Prime configuration, with the exact fields produced by its
owner's staging harness. It must declare `isolated_engineering_canary`, no
production data or credentials, and no configured models, SDK or OAuth
providers. The observer checks those identities and independently reads the
actual files/processes; it does not trust prior `startup_passed` fields.

```sh
python -m echo_certification_forge.echo_workspace_probe \
  --lane /absolute/task-owned/canary \
  --running-sha256 <reviewed-running-document-sha256> \
  --manifest-sha256 <reviewed-runtime-manifest-sha256> \
  --output /absolute/new-observation.json
```

HTTP is restricted to literal `127.0.0.1` origins, without a proxy or redirect.
Responses and requests have a 1 MiB limit, an absolute body-read deadline and a
bounded call count. Cookies remain inside the process. Reports contain fixed
failure codes, operation paths, status/size/timing metadata, acknowledged IDs,
and hashes; they omit cookies, raw provider responses, notes and screenshots.

Exit zero means all listed **engineering** checks passed. The report always
retains `release_verdict: NOT_READY`, `production_e2e: false` and
`signature_verified: false`. It explicitly lists the remaining real SDK
journey, OAuth consent/read, bounded autonomous turn, external owner acceptance
and trusted collector admission. It cannot be installed as a signed production
E2E envelope and does not satisfy those checks merely by serving HTTP 200.

## Owner integration and limits

The deployed generic production E2E verifier independently requires an approved
collector signature, exact target/environment/source/deployment bindings, six
real checks, at least three stability probes and a fresh bounded lifetime. This
observer supplies measured evidence for review; it does not replace that
admission or signing boundary. A production collector must execute the missing
real journeys through their normal authenticated hosts and bind this evidence
to its approved target policy before any production attestation is issued.

The existing Windows package runner's key and command are scoped to enrolled,
per-run Windows package observations. Their availability does not authorize
this observer to reuse that transport identity for generic production E2E.
No key, trust registry, verifier or production service is changed by this module.

Local native-session checks do not verify the public Workspace login or edge
callback logging. Browser profiles/processes are not per-bot virtual machines.
An unavailable marketplace does not establish a live provider connection.

## Verification and reuse

`tests/test_echo_workspace_probe.py` uses real controlled HTTP servers to check
redirect refusal, size/time limits, slow-body deadlines, in-process cookies and
no replay after an uncertain mutation. It also tests malformed evidence,
source drift/symlinks and refusal to infer production readiness from local
checks. Real lane observations are separate from these test fixtures.

The implementation imports the repository's existing `canonical` helpers. The
library-first source search and the reviewed target-specific collector
architecture were consulted before adding the Echo-specific journeys. No
target-specific Finisher or Windows package attestation is relabeled as Echo
production evidence.

## Recorded engineering observation

On 2026-11-08, the concrete observer exercised Echo CLI
`768b364b2a702f9e3ee6ff0b25e1b60e3029d9fb` with Echo ADK
`3e798d56f34a8657c4db626464a604ed9aa9c85c` in an isolated, owner-created
loopback lane. All nine engineering checks passed, including the actual
Chromium snapshots, memory revision conflict, import-plan conflict and owned
resource cleanup. The services were subsequently stopped by the lane owner.
The observation document SHA-256 is
`6897ee86ea668afc96075386f1aeef99ea21a81daacb6ea543f1dd8b0e03e8de`;
the observer source SHA-256 is
`30d0e7bed7c7994980b3883c70cce079a93a3ff24d9885b86aa825ed01e84e0b`.

This is unsigned engineering evidence. SDK and provider credentials were not
configured, external Workspace authentication and autonomous reasoning were
not exercised, and no runtime model-call counter was instrumented. The report
retains all five remaining requirements above and `NOT_READY`. Earlier failed
observer attempts were retained separately; they are not counted as passes.
