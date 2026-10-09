# Admit a separate journey image through existing P4 authority

The Node24/Python3.11 journey image has a different layout from the twelve P4
role images. It must not be relabeled as a P4 role variant or replace their
manifest. `prepare_journey_image_admission.py` prepares a separate unsigned
`ImageAdmissionPolicy` using the existing public policy and attestation. It
preserves trusted keys, compromised-key exclusions and revoked image digests,
and binds only the candidate image, source, final base, recipe and dependency
commitment. The two-stage base provenance remains in the hashed input lock and
provenance. A source-integrated recipe does not relabel a previously built image;
retain that image's actual build source in `ImageIdentity`.

Preparation verifies bounded exact material bytes, recipe policy, source and
SPDX image/runtime-package binding, independent-build comparison commitments,
scanner/Node-core negative counts, runtime isolation assertions, and current
existing authority. Qualifications are strict typed, at most24 hours old, and
must bind the canonical identity digest. Public assertions and report hashes
are review inputs, not authenticated scanner attestations. Independently inspect
their referenced raw reports, tool provenance and two actual builds before
approving the request. Do not infer image qualification from operator-supplied
zero counts alone.

```text
python scripts/prepare_journey_image_admission.py \
  --packet <public-evidence-directory> --qualification <qualification.json> \
  --dockerfile images/journey-node24-python311/Dockerfile \
  --prior-policy <existing-public-policy.json> \
  --prior-attestation <existing-public-attestation.json> \
  --expected-source <actual-image-source-sha> \
  --expected-image sha256:<actual-image-digest> \
  --expected-policy-sha256 <reviewed-public-policy-file-hash> \
  --output <new-owned-output-directory>
```

The packet contains `runner.identity.UNSIGNED.json`, `runner.spdx.json`,
`runner.provenance.json`, and `journey-image-inputs.lock.json`. All paths must be
regular files below non-reparse ancestors. Inputs are bounded to4MiB each.
Outputs use exclusive creation and a completion receipt written last. Existing
output paths are refused; an incomplete directory is not an admission. The
owner must serialize input custody while reading; path checks do not lock a
directory against another authorized writer.

After independent review, the admitted control-plane owner may use the bounded
sealer with the **existing** P4 key in its original custody:

```text
python scripts/seal_journey_image.py \
  --request <request.UNSIGNED.json> \
  --approved-request-sha256 <canonical-request-digest-from-reviewed-receipt> \
  --attestation-private-key <existing-owner-only-P4-key-path> \
  --valid-days 7 --output-dir <new-owned-sealed-directory>
```

This wrapper reuses `seal_p4_images.load_private_key`; it has no key generation,
trust bootstrap or policy installation mode. It requires POSIX same-owner0600
regular-file custody, current exact prior public admission and the same public
key/key ID. It never serializes the private key, passes it to a child or exposes
it to a worker. Signing is bounded by both30days and the existing authority's
remaining lifetime. All outputs are public; errors report a fixed category.
The review digest proves input integrity, **not permission or a Commander
signature**. Execute only through the admitted owner workflow with the actual
authorization and reviewed implementation. Synthetic test keys are not usable
as a production trust root.

The result is `SEALED_NOT_INSTALLED`. Its canonical signature/admission must be
independently read back before owner selection. It does not install a policy,
modify any existing P4 role, update API/dispatcher configuration, mutate a queue,
restart a service, certify the CertForge source, or certify a target application.
Source release still requires its exact-SHA gates and rollback. Runtime selection
must use the shared measured profile in `RUNTIME_IDENTITY.md`; preserve the
original profile and old source/image, drain/reconcile leases through supported
governance, then independently verify API/worker identity agreement. No opaque
environment label or fixed-image default may bypass that measurement.

This integration retains PR28's measured runtime identity and the local intake
fix that preserves optional artifact/source commitments. Artifact or acquired
source drift still fails before journey execution or signing. Image admission,
source certification, target certification and ordinary deployed bot acceptance
remain separate. A successful source-only journey cannot satisfy production E2E
or establish a95+bot grade.
