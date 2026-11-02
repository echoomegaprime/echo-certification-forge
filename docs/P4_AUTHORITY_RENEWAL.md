# Renew P4 evidence with the existing owner trust key

An expired image attestation requires fresh qualification and owner sealing. It
does not require a new trust root. The six current role recipes and sandbox/P4
defaults pin Python3.12.16 base
`sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0`.
Each role also installs exact Alpine libcrypto3/libssl3 3.5.9-r0 and libuuid
2.42.3-r1 fixes. Actual image scans decide qualification; these declarations
alone do not establish safety.

Use the existing full P4 builder and sealer through the admitted owner workflow.
The convenience `run_p4_gate.sh` still creates a fresh test trust key by default;
that default is unsuitable when renewing an existing production authority.

1. Pin the exact reviewed source, existing public metadata, key identity and
   public policy hashes. Verify the existing key's original protected custody
   without copying its contents. Retain compromised-key exclusions and image
   revocations; conflicting trust state prevents renewal.
2. Run `scripts/build_p4_images.py` with that exact source, a new unique tag
   prefix and the **existing** `--public-metadata` file. It builds all six roles
   twice. Verify every resulting role, revision, key-ID label, non-root user and
   content identity; never overwrite another run's tag prefix.
3. Scan all twelve immutable images with the qualified scanner before invoking
   the owner sealer. Require zero critical, zero fixable high/critical and zero
   secret findings. Retain raw reports, scanner/database identities and runtime
   checks. A failed or incomplete scan prevents signing.
4. Invoke `scripts/seal_p4_images.py` with the exact twelve-image map, source,
   base digest, qualified scanner, original owner key path and a new output
   directory. Only this owner process loads the existing private key; workers
   receive public records. No key generation or alternate trust selection is
   part of this renewal.
5. Independently verify the completed manifest, exact public key, signatures,
   freshness, source/image/material bindings, all twelve runtime/security
   reports and A/B normalized comparisons. Run the full hostile acceptance gate
   with its genuine scanner, malware scanner and signing-tool prerequisites.
   Partial sealer output is not admission or a completed phase.
6. Use the renewed runner public records to prepare the separate journey-image
   request in `JOURNEY_IMAGE_ADMISSION.md`, preserving existing trust and
   revocations. The ECF journey image remains a separate image and policy.

All outputs remain separate from selected live configuration until their owner
release and rollback requirements pass. Renewing P4 image evidence does not
refresh product readiness, certify source, deploy the service or certify a
target application. Product readiness still requires measured phase evidence,
the actual master acceptance journey, exact-source hosted CI and its existing
signing authority. Do not extend old timestamps or relabel old receipts.
