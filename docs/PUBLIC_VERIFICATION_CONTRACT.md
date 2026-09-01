# Public verification contract

`GET /v1/public/verifications/{verification_id}` is the secret-free,
machine-readable surface for independently checking a published Certification
Forge verdict. Publication is allowed only for a current signed
`PRODUCTION_READY` run. Every later read re-evaluates the deploy gate, so an
expired, revoked, superseded, compromised, or otherwise invalid verdict returns
`valid: false` with fail-closed reasons.

## Response material

The response contains:

- `verification_id`, `valid`, and deterministic `reasons`;
- the exact signed verdict `payload`;
- a secret-safe public `target_identity` projection, the canonical
  `environment_identity`, and a secret-safe signed `production_e2e` projection;
- the Ed25519 `signature_b64`, `key_id`, and public verification key.

These identities are public verification material, not authority by themselves.
The private target record remains bound to `target_identity_digest` but is never
returned. The public target projection deliberately omits local paths and raw
Git remote URLs; for a credential-free HTTPS GitHub source it exposes only the
normalized `owner/repository`. Its hash is committed separately as
`public_target_identity_sha256`. The environment and production-E2E projections
are bound by `environment_identity_digest` and
`production_e2e_identity_sha256`. A serialization or digest mismatch forces
`valid: false` with a specific fail-closed reason.

The public production-E2E projection contains signed aggregate results only:
tool/account/client counts and boolean reconciliation, visibility, authority,
OAuth, persistence, ledger, sharing, import, and continuity outcomes. Raw
account names, per-account repository counts, credential routes, private sample
repository IDs/node IDs/branches/HEAD SHAs, and per-client fingerprints remain
inside the private evidence record and are never copied to the public response.
Every generic production-E2E proof must include a bounded, credential-free
HTTPS canonical target without user information, query data, fragments, or
port zero. Hosts are normalized before policy evaluation and must be either an
unscoped global IP literal or a strict ASCII LDH name with an alphabetic TLD.
Special-use names, punycode A-labels, noncanonical numeric hosts, and
non-global, multicast, site-local, or scoped address literals fail closed. The
same canonicalizer governs signed-proof validation and public projection so a
consumer never receives a target the producer would reject.

## Independent verifier procedure

An independent consumer must:

1. Canonicalize the verdict payload and verify `signature_b64` with the returned
   Ed25519 public key, while enforcing the expected trusted key identity and
   lifecycle policy.
2. Canonicalize `target_identity`, `environment_identity`, and
   `production_e2e`; hash each with SHA-256; and compare them with
   `public_target_identity_sha256`, `environment_identity_digest`, and
   `production_e2e_identity_sha256` in the signed payload.
3. Confirm the target identity names the intended repository/artifact and exact
   source revision.
4. Confirm the signed production-E2E identity, environment, rule-manifest
   digest, evidence root, and release verdict satisfy the consumer's named
   profile. Independently pin the accepted CertForge key IDs and rule-manifest
   digests; response-provided values cannot expand either trust set.
5. Treat network errors, missing fields, key-policy failures, digest mismatches,
   and `valid: false` as rejection. Cached green state is not authority.

The public response never contains a private signing key, GitHub credential,
Vault secret, subscriber token, OAuth secret, customer-private evidence body,
or Commander signing key. Certificate presentation and Commander approval are
owned by Echo GitHub Autonomy; Certification Forge independently owns the
signed source/environment/E2E verdict that the App must verify.

Git acquisition also rejects HTTP(S) user information, URL query/fragment
credentials, and nonstandard credential-like SCP usernames before invoking Git,
so those values cannot enter source identity, subprocess errors, or public
verification data.
