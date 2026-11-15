# Canonical identity export

`GET /v1/certifications/{run_id}/identities` exports the two canonical identity
objects already stored for one certification run. This is a metadata projection;
it does not reconstruct a target, read evidence artifacts, issue an attestation,
change a verdict, or admit a deployment.

## Authorization and integrity

The route requires configured subscriber governance and an authenticated Bearer
principal with `runs:read`. The existing tenant consistency check and tenant-scoped
store lookup apply. A tenant header by itself is insufficient, including when
subscriber governance is disabled. Unknown and foreign runs both return 404.

The exporter requires every field of the stored `TargetIdentity` and
`EnvironmentIdentity`, validates their models, and recomputes both identity
digests. Declared identities and records whose objects do not match their stored
digests return 409. Duplicate fields, oversized records, unknown fields, invalid
source revisions, and references containing credentials, query material,
fragments, or control characters are refused. Encoded reference material is
checked conservatively. The exporter never silently redacts an identity and
substitutes a different digest.

Before returning data, the route rechecks the live principal through the existing
resource audit operation. Revoked keys, changed permissions, and audit failures
prevent the export. The audit records only the run identifier and four digests;
canonical references and object contents are not audit details. Responses use
`Cache-Control: no-store`. Run rows, evidence, signatures, and policy stay unchanged.

## Response and collector handoff

The strict response schema is `certforge.canonical-identities.v1`. It contains:

- `run_id`, `tenant_id`, `rule_manifest_id`, and `rule_manifest_digest`;
- the stored `target_identity_digest` and `environment_identity_digest`;
- `identities`, with exactly `target` and `environment`;
- `identities_sha256`, the SHA256 of canonical JSON for `identities`;
- `export_sha256`, the SHA256 of canonical JSON for the response excluding
  `export_sha256` itself.

Canonical JSON uses sorted keys, separators `(',', ':')`, UTF-8,
`ensure_ascii=False`, and no trailing newline. An admitted consumer verifies the
run/tenant and both digests against its independently selected certification run,
verifies `export_sha256`, and writes exactly the canonical `identities` bytes.
`identities_sha256` is then the exact file hash for the separately reviewed
production-E2E intake's `--identities-sha256` argument. The identity document has
only `target` and `environment`, as required by that intake.

These hashes establish content consistency. They are not collector signatures,
release authority, or evidence that production journeys occurred. The existing
collector trust, freshness, real journey, external acceptance, and verdict checks
remain mandatory. No identity values are supplied as hand-written examples.

## SDK contract and admission

The proposed capability is `echo.certforge.identities`, a GET path operation with
`command` and `run_id` as required inputs, `certforge.read` as its gateway scope,
and danger tier 0. Its complete output schema is generated from the FastAPI route.
The registration proposal retains the same server-held tenant header and vaulted
subscriber credential reference as `echo.certforge.status`. No credential value
is placed in the request, response, source change, or documentation.

Source declarations do not activate this capability. Native admission must verify
the exact issuer revision, trusted runtime, deployed route, registered descriptor,
and current HTTP handler's forwarding of the server-held Bearer/tenant binding.
Require an authenticated positive read of the intended run, wrong-tenant and
revoked-key negatives, matching digests, and a committed audit event. Do not infer
wrapper readiness solely from a registration row or schema. Existing evidence
artifact scopes, collector keys, service protections, and deployment policy must
remain unchanged.

The service and generated contract repairs are isolated source work until that
admitted rollout and readback succeed. The separate production-E2E intake must
also be independently reviewed and admitted; this change neither installs it nor
selects or provisions a collector signer.
