# Offline sandbox runtime input

The public two-line recipe uses the official Python 3.12.16 / Alpine 3.24 amd64
manifest and upgrades only krb5-libs to 1.22.3-r0. It copies no application code,
customer data, credentials or signing material. The six P4 roles use the same
upstream/package pair; their role images require separate fresh qualification.

The delivered runtime is the full local Docker image ID:
sha256:061deb070723eabc0cb5cb8ffd1eeab591206d27fdf71991e915cce72e4e7558.
On the measured Docker29.4.1 OCI image store this is an OCI image INDEX digest.
It is not the platform manifest, configuration digest or a registry RepoDigest.
runtime-input.json records those identities separately and binds the ordered
layer descriptors, decompressed diff IDs, recipe and archive hashes.

## Actual private qualification

The archive qualified-base-fullid.docker.tar is 18,906,112 bytes, SHA256
e05c6c4f3a6f116842d52e98d31940b912e730cfbafbfb5d7de3644bb20fc898.
All eleven blob hashes and five decompressed filesystem-layer digests were checked.
After removing only this task-owned image without force, inspection proved it
absent; loading the verified archive restored the same index/configuration/rootfs.
A post-load non-root, read-only, no-network container ran by the FULL local ID;
both its requested Config.Image and actual container.Image matched. Twelve
containment/import probes passed. A missing local image failed locally under
--pull=never without creating resources or trying a registry fallback.

Fresh Trivy0.74.0 scanned that actual restored full ID: exit0, zero HIGH/CRITICAL
findings and zero secrets; seven lower findings remain. The database was updated
2026-11-14T01:05:40Z. These are private qualification observations, not a trusted
readiness signature or production admission.

The verified archive and public proof files are checkpointed on QUENCH at:
D:/ECHO_OMEGA_PRIME/08_ARTIFACTS/fielddesk-issuer-recovery-20261113/runtime-base-qualified
Their hashes are recorded in runtime-input.json. Generated test keys are not included.

## Provisioning and release acceptance

1. Review the candidate source and provenance; obtain the exact archived bytes.
   Recompute the archive, blob, descriptor, config and ordered filesystem hashes.
   Do not substitute a new build merely because its package versions match:
   build timestamps can produce another immutable ID.
2. Import with the supported Docker archive loader on the admitted execution node.
   Read back the exact delivered full ID and platform/config/rootfs relationship.
   A different engine or store that changes identity needs fresh qualification and
   source admission; do not invent an alias or RepoDigest.
3. Run the actual default under the unchanged sandbox hardening, then fresh
   candidate-default MASTER and relevant acceptance. Local IDs use --pull=never;
   immutable repository@sha256 OCI target acquisition retains its existing behavior.
4. Verify all twelve new P4 role images and all required evidence for the final
   source commit. Preserve the seven lower findings for independent review.
5. Independent release review and trusted exact-source readiness signing remain
   required before promotion. This metadata explicitly grants NO production admission.

CI builds a behavior-test fixture from the same hash-verified public recipe and
records its own full local ID. That tests the real DockerSandbox behavior; it does
not claim to execute or qualify the delivered DEFAULT artifact. The delivered
artifact is independently tested on FORGE. Missing or malformed CI fixture input
fails rather than selecting another image.
