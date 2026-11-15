# P4 official definition profile

Fresh P4 acceptance requires a frozen public ClamAV definition profile. There is
no bundled-database fallback. Provision it through normal official FreshClam
outside source and build contexts, then freeze only the three selected vendor
archives and their actual versioned sidecars. Never bypass vendor download limits.

The root contains manifest.json, exactly one CVD or CLD for each of main, daily
and bytecode, and the real name-VERSION.cvd.sign files required by selected CVDs.
Patched Daily CLD authenticates internal signed INFO; no invented outer sidecar is
required. Unknown files, custom definitions, duplicates, symlinks, hardlinks,
malformed headers, missing signatures and changed bytes fail closed.

The manifest has schema_version 1.0.0 and kind clamav-definition-profile.
It binds official_updater_reference, files (path, size_bytes, sha256) and database
header identities (path, version, signatures, required_functionality_level,
build_epoch, header_sha256). Its SHA256 is a separate required CLI input.
Supplied metadata cannot relax fixed Daily age of 48 hours or future-clock skew
of five minutes. Main and Bytecode can legitimately be older after authentication.

The harness validates and copies the snapshot into its private fresh workspace.
CVD detached signatures and FIPS-limited sigtool information checks authenticate
the databases offline. These authentication flags do not alter target-scanning
signature semantics. Target scans use normal clamscan with official-db-only=yes
and an explicit database path. All checks mount the selected data read-only over
/var/lib/clamav, covering the vendor image's declared volume. No scan-time
updater, networking, caller CA override or additional capabilities are enabled.
Actual mounted paths, complete bytes, engine, daily build time and qualification
time are bound in the report; data is rechecked before and after use.

Daily freshness is checked again during unsigned P4 input admission before owner
key access. Already-signed readiness TTL and lifecycle rules are unchanged.
Previous bundled-database P4 JSON cannot satisfy the new producer/consumer contract.

Use a fresh workspace and output on every attempt; existing evidence is preserved.
The shell driver requires CLAMAV_DB_DIR and CLAMAV_DB_MANIFEST_SHA256. Direct use:

    python scripts/p4_hostile_acceptance_hardened.py \
      --images /qualified/sealed/images.json \
      --sealed-manifest /qualified/sealed/manifest.json \
      --base-digest SHA256_BASE \
      --source-commit EXACT_SOURCE_SHA \
      --trivy /qualified/tools/trivy \
      --cosign /qualified/tools/cosign \
      --clamav-image clamav/clamav@sha256:45fe5149fbee5a46509c9848ef20d0c354b7b2323c9369f285939a37cf33422a \
      --clamav-db-dir /qualified/public-definitions \
      --clamav-db-manifest-sha256 SHA256_OF_MANIFEST_JSON \
      --workspace /qualified/new-owned-workspace \
      --output /qualified/new-p4-report.json

Private qualification is separate from independent release signing and production
admission. Report engine version separately from any bundled database suffix:
the selected profile's authenticated Daily identity is the scan input.
