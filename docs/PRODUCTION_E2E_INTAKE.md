# Production E2E owner intake

`python -m echo_certification_forge.production_e2e_intake` implements the atomic
owner installation already specified by the deployed CertForge operations
contract. It supplies the existing `DirectoryProductionE2EProvider`; it does
not create a second release authority or a new mandatory release rule.

The operator selects the canonical target and environment from the exact
certification run, the existing independently managed public-key directory,
and the existing attestation directory. The collector supplies only an
envelope. Its embedded public key never establishes trust.

## Qualification before promotion

The deployed sequence permits a production-shaped journey against an isolated
exact candidate before promotion. A candidate therefore does not need to be
already running in production to be observed. The observation must accurately
state its scope. For a private candidate lane, preserve fields such as
`execution_scope: private_exact_artifact_acceptance` and
`public_deployment_verified: false`; installation does not change those fields.

An ordinary App staging result may establish the exact candidate and identify
the remaining production-E2E rule. That result is not itself a production
attestation. The actual collector still has to execute the required journeys,
negative controls, exact identity readbacks, at least three stability probes
and external acceptance, using its independently established authority.

The existing six-check production contract, lifetime limit, signatures and
exact target/environment/source/deployment bindings remain unchanged. Nothing
in this tool converts an unsigned engineering report or successful process
exit into trusted production evidence.

## Operator invocation

The owner identity document contains exactly `target` and `environment`, using
the canonical `TargetIdentity` and `EnvironmentIdentity` fields recorded by the
control plane. Obtain its digest and the envelope's digest from the reviewed
owner handoff. A collector-controlled identity document is not an independent
binding.

The production roots already documented for FORGE are:

- Attestations: `/var/lib/echo-certforge/production-e2e/attestations`
- Public trust: `/var/lib/echo-certforge/production-e2e/trusted-keys`

First verify the exact proposed bytes without writing an intake file or lock:

```sh
python -m echo_certification_forge.production_e2e_intake \
  --envelope /absolute/reviewed/envelope.json \
  --envelope-sha256 EXACT_REVIEWED_ENVELOPE_FILE_SHA256 \
  --identities /absolute/owner/canonical-run-identities.json \
  --identities-sha256 EXACT_OWNER_IDENTITY_FILE_SHA256 \
  --attestation-directory /var/lib/echo-certforge/production-e2e/attestations \
  --trusted-key-directory /var/lib/echo-certforge/production-e2e/trusted-keys
```

Execute the same owner command with `--install` to publish the verified bytes.
The default owner UID is zero. The operational entrypoint requires protected
POSIX directories and normal operating-system write authority. It does not
elevate privileges or accept an owner UID override from the command line.

For a renewal, additionally supply `--replace-content-sha256` with the exact
current installed file digest. A different existing document blocks the write
unless that digest matches. Repeating the identical verified document returns
`already_present`, without a second publication.

After installation, use the ordinary certification/App workflow to reevaluate
the exact source and independently verify its new signed verdict. The intake
receipt says `release_verdict: NOT_ISSUED`; successful intake cannot issue a
release, deploy a target or change SDK scopes.

## File and failure behavior

The intake verifies reviewed input bytes, the existing signature, the full
production contract and current freshness before taking a lock. It reloads
public trust and checks freshness under the lock and again before publishing.
It rejects symlinked paths, nonregular files, oversized or ambiguous JSON,
unexpected envelope fields, writable trust material, unprotected directories
and wrong owners. It never reads a private key.

Publication uses a private exclusive temporary file, file `fsync`, atomic
rename, directory `fsync` and exact readback. A nonblocking owner lock prevents
concurrent updates from bypassing the replacement comparison. Pre-publication
failure leaves the existing attestation unchanged. An I/O failure after a
publication attempt returns `state: unknown`; reconcile the installed bytes
before issuing a different write. The same input can then report
`already_present` after current signature, identity and freshness verification,
file and directory `fsync`, and exact readback. Continuing durability failure
keeps the result unknown. Post-publication temporary-file cleanup errors also
preserve that unknown outcome.

## Contract provenance

This branch restores `src/echo_certification_forge/production_e2e.py` unchanged
from the actual deployed CertForge revision
`d8ad9fd881365801354b78a758632d2a31ab6828`. Its SHA-256 is
`467a24dba4047e6f8450b79bd03dc752956d4cd4569662f39542d2e4d5ff0de6`.
The existing corresponding tests are restored from that revision as well.
The PR43 base did not include the deployed provider module. Reusing its exact
implementation avoids introducing an alternative signature or eligibility
validator in this owner tool. No mandatory-rule manifest, dispatcher or signer
is altered by this source addition.

The new tests use ephemeral test-only Ed25519 keys and private temporary
directories. They verify actual signatures, actual provider consumption,
wrong identity, missing checks, expired evidence, untrusted embedded keys,
replacement conflicts, real locking, symlinks, nonregular inputs and an
uncertain post-publication I/O outcome. Test keys are never operational trust.

## Current integration boundary

This change implements the missing verified atomic installation operation. It
does not provide a generic collector private key, enroll a collector, or claim
that a production signer command exists. Existing runner enrollment and
transport-key rotation are scoped to transport and cannot supply that
authority. A newly written producer still needs the owner's real signing
custody workflow before its output can pass this intake.
