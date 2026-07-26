# Windows Package Execution Plane

This plane certifies a digest-bound Windows installer without ever executing it in Echo
Desktop or in the control plane. It is rerunnable for every new source/artifact pair:
the submitted reservation—not source constants in the worker—defines the accepted
`reference`, `artifact_sha256`, `source_commit`, and environment identity.

## Trust boundary

- Desktop may submit a `package` target, but receives no runner credential or signing key.
- The Windows runner only hashes the installer, verifies the source worktree HEAD, checks
  for symlink/reparse escape, and calls Windows Authenticode inspection. It has no command
  or installer-launch surface.
- A control-plane-issued Ed25519 credential lasts at most 15 minutes and is bound to one
  tenant, run, enrolled private-worker identity, runner public key, and `transition` scope.
- `POST /v1/internal/windows-package-results` accepts a signed observation only when every
  identity equals the still-BOUND reservation and QUEUED run. Wrong digest, commit,
  reference, environment, runner key/image, replay, expiry, or extra fields fail closed.
- The runner's `ready_candidate` is only an observation. The isolated platform signer
  independently issues the deterministic signed verdict; model output and runner claims
  cannot override failed mandatory rules or blocking findings.

## Per-build flow

1. Submit `target_type=package` with the exact installer path, SHA-256, source commit, and
   `declared_target_identity_digest(...)`. Submit the environment digest returned by
   `windows_package_environment(<enrolled-worker-image-sha256>)`.
2. Initialize the runner identity once with
   `python -m echo_certification_forge.windows_package_worker init ...`; enroll its public
   identity and worker-image digest through the existing private-worker and runner APIs.
3. Initialize a separate control-plane transport authority once with
   `python -m echo_certification_forge.windows_package_credential init ...`; add only its
   public key to `ECHO_CERTFORGE_TRANSPORT_KEYS`.
4. Issue a short-lived per-run credential with `windows_package_credential issue`.
5. Run `windows_package_worker run` with the submitted artifact SHA, source commit, and
   reference. The process posts only the signed observation.
6. On the key-isolated host run `windows_package_finalize --run-id ... --tenant ...`.
   It reconciles the declared identity, stores the authenticated evidence and blockers,
   and asks the deterministic engine plus isolated signer for the terminal verdict.
7. Verify `/v1/certifications/{run_id}/verdict/verify` and the exact release gate. A missing
   or invalid Authenticode signature produces signed `NOT_READY`; it never self-closes the
   release evidence item.

The historical `6a7a8da4` / `1bdef4...face55` pair appears only in tests as the first live
acceptance fixture. Advancing Desktop sources require a new exact submit and credential,
not a CertForge code change.
