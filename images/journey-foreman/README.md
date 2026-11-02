# Foreman dependency journey candidate

This is an unsigned, dependency-only development recipe. It does not select a
live runtime, admit an image, modify an owner policy, or establish production E2E.
The Foreman target is `cd088e2e07c756b8bc195ce3d1fa6253d845983f`; target code is
mounted read-only during qualification and is not copied into this image.

The recipe reuses the Node-binary/library composition in the existing
`images/journey-node24-python311` layout with the supported exact pair Node
24.22.1 and CPython 3.12.16. Both public Linux/amd64 bases are immutable Trixie
manifests. This preserves the existing 34 hash-locked wheels, including the
manylinux native wheels. The ECF Alpine recipe cannot reuse this wheel lock.
Only the Node binary and its matching C++/GCC library files are copied; npm and
ECF application packages are not included. Node is not started as a background
service. Python installs only the exact binary wheels with public PyPI hashes;
there is no target-source or credential build context.

`RECIPE_COMMIT` must be the actual committed CertForge recipe source, supplied
after the recipe is committed. Its label points to this canonical repository.
The Foreman target label is separate. `recipe-inputs.json` commits base,
dependency and probe inputs; it is deliberately not an admission input lock.
After committing, generate the separate qualification/admission lock with the
actual recipe source commit and bind the exact material hashes. Do not hardcode
a circular future commit or relabel the Foreman target as the recipe source.

The build context contains exactly `Dockerfile`, `requirements.lock`, and
`runtime_probe.py`. Build only after reviewing their hashes, binding the current
Docker daemon identity, and confirming at least 20 GiB free. The intended task
build limits are 768 MiB RAM with no additional swap, two CPUs and a 300-second
deadline; the install step verifies the actual kernel limits. Use unique owned
tags and labels. No build or image reuse is authorized by these instructions
alone. A prior retained portable archive remains separate from the current
daemon's image inventory.

The non-root probe checks actual Node, Python, libc and embedded OpenSSL/Undici
versions, rejects npm, and hashes both ELF executables plus the dynamic-library
closure reported by `ldd`. Missing, relative, static, oversized or unknown
dependency output fails closed. The kernel VDSO is not invented as an image file.
The copied libraries must additionally be traced to the exact Node base and
included in the complete SPDX inventory. Their presence or package versions
must not be inferred from the Python base's package database. The probe is an
inventory, not an authenticated scanner, advisory review, or admission verdict.

Run the focused, offline parser/version controls with:

```text
python -m unittest discover -s images/journey-foreman -p test_runtime_probe.py -v
```

Fresh qualification still requires two actual bounded builds and normalized
comparison, a full image/secret scan, current independent Node-core review,
complete SPDX/provenance, and the actual three-scenario Foreman program under
the reviewed non-root, read-only, network-disabled execution profile. SPDX must
contain exactly one actual `nodejs` 24.22.1 and one `CPython` 3.12.16 runtime row.
Do not transfer a previous image's scan or core zero-count assertion to a new
digest. The supported-pair enum does not override an applicable vulnerability.

The read-only preparation review used the official Node security working-group
core index at `f643f84d4977d0ba379dc7c5805c9b65206369b5` and the official
[October 21 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
and [24.22.2 release](https://nodejs.org/en/blog/release/v24.22.2). Refresh the
review at qualification time. The existing journey admission preparation and
existing-authority signing workflow remain unchanged. Owner scope, trust,
signature, revocation, freshness and exact-source release gates still apply.
