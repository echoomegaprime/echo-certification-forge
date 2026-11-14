# FieldDesk issuer runtime repair — November 14, 2026

## Objective and custody
Canonical echoomegaprime/echo-certification-forge; branch
agent/builder-fielddesk-issuer-runtime-20261114 begins at
2147fc35fc2a244015f6f708824eb340a871cfe8 (PR68, including PR64/65/deployed ancestry).
This follow-up repairs the actual runtime and scan qualification needed before
FieldDesk PR12 can proceed. Existing branches, live services, evidence, data,
private keys and protected policy are unchanged. Source-only Builder intent;
Complete Builds and God Mode workflows; MEGA not needed. No role grant or signature
is inferred from the existing subscriber OWNER role.

## Demonstrated failures and repairs
Fresh Trivy0.74.0, database updated2026-11-14T01:05:40Z, found19fixed HIGH blockers
in the old pinned base (krb5-libs, musl/musl-utils, zlib). The current official
Alpine3.24 base still needed the exact krb5-libs=1.22.3-r0 fix. Both P4 scanner
helpers and their manifest caller accepted partial successful-looking JSON after
a failed scanner;18 regression cases reproduced this before the guard repair.
They now require a successful tool exit, complete schema, a fresh output path,
and unchanged vulnerability/secret rules. Manifest verification requires actual
integer0, rejecting booleans, strings and missing tool status.

All six role Dockerfiles use the immutable official Python3.12.16/Alpine3.24
amd64 base a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20
and only the exact krb5-libs fix; Python package hash locks remain unchanged.
New image labels, sealer source URI and gate repository default identify the
current canonical echoomegaprime repository, not the obsolete owner namespace.

The old generic DEFAULT_IMAGE is production-reachable: the installed dispatcher
has --sandbox and no image override, and git journeys preserve that sandbox.
P4 role qualification alone does not qualify that separate default.

## Delivered offline runtime
The public two-line recipe and structural provenance are in images/sandbox.
Actual full Docker ID:
sha256:061deb070723eabc0cb5cb8ffd1eeab591206d27fdf71991e915cce72e4e7558.
On Docker29.4.1 this identifies the OCI INDEX, not its config or a registry digest.
Metadata separates the index, platform manifest, config, eleven blob hashes,
five uncompressed layer hashes, ordered chain ID and archive envelope.

Archive18906112bytes, SHA256
e05c6c4f3a6f116842d52e98d31940b912e730cfbafbfb5d7de3644bb20fc898.
QUENCH checkpoint:
D:/ECHO_OMEGA_PRIME/08_ARTIFACTS/fielddesk-issuer-recovery-20261113/runtime-base-qualified

Actual non-force removal proved the task-owned image absent. Loading the hashed
archive restored the same ID/config/rootfs; post-cold container.Image and
Config.Image matched and12containment/import probes passed. Missing local ID
failed locally without resource creation. Fresh Docker-only full-ID Trivy
returned exit0, zero HIGH/CRITICAL/secrets, seven lower findings retained.
Raw scan SHA2569b7d80431aafba8b459d475ddc801c13caf6d42f31050800d637830d06f4c816.

Local full IDs use --pull=never. Repository@sha256 OCI targets retain their
existing acquisition behavior; acquisition downloads blobs but does not itself
load the Docker store. Master acceptance accepts only full local or repository
digest identities, never short/mutable/malformed identities.

## Validation and scope
Scanner regression suite33passed after18baseline failures.
Final affected Windows suite120passed,3skipped: two actual-Docker cases lacked a
local Docker CLI, and one unchanged symlink privilege case is platform-specific.
Actual delivered-runtime Docker/cold-load tests ran on FORGE separately.
The CI helper's post-build environment-append failure reproduced a false passing
report; its error handler now clears passed and the regression passes.
Structural lineage checks protect the default/recipe/archive identity mapping;
they are not a substitute for actual archive verification or signed admission.

CI provisions a behavior fixture from the same exact public recipe, validates
its own full ID and records it separately. Only the real-Docker test fixture
selector uses that CI variable. Production has no new environment override.
CI does not claim to qualify the delivered DEFAULT artifact.

## Queue and completion gates
- Publish this source without force, open a narrow PR targeting PR68, read remote
  exact SHA and require fresh full Linux CI/P1/P6/P7/CodeQL/Sentinel.
- Re-export that exact source; rerun real P2/P3 protocol tests, actual-default
  Docker MASTER, SDK validation, versioned P5 bundle revalidation, all12fresh P4
  role builds/seals/scans and the real hostile gate. Do not transfer2147 results.
- Independently verify input hashes; a disposable test signer grants no
  production authority. The existing d8ad readiness report must fail for new SHA.
- Obtain independent source review and trusted exact-source readiness signing,
  then follow governed issuer release admission. Never synthesize Commander
  acceptance or read/export production private keys.
- Recover FieldDesk's original rerun key, preserve failed evidence, and continue
  frozen data reconciliation, immutable staging, authenticated hostname routing,
  genuine production collector/dual issuer evidence, provider and Pixel acceptance.

FieldDesk remains290658c with verified private browser and FORGE acceptance and a
sealed non-live deployment preview. No customer migration, production service,
ingress, provider, phone or physical-device action was performed.
