# FieldDesk dependency-only journey image

This is an unsigned build recipe, not a runtime admission or deployment. It uses
the existing supported Node24.22.1/Python3.12.16 qualification pair and the six
dependency inputs of FieldDesk290658c4be634af6dd308021d1946f737032c3cf. No FieldDesk
application checkout, signing identity, operator environment or customer data is
included. dependency_source_commit records the dependency snapshot origin, not the
active target binding. A later target with byte-identical six inputs still needs
its own exact-source profile and actual journey proof. Live host runtime selection
is a separate security/admission decision.

Construct a fresh public-only build context with these committed files, the
hash-matched frontend-dependencies.tar.gz and all27 hash-verified CP312/universal
wheels under wheelhouse/. Preserve raw public download/SRI/CAS provenance outside
the image. Do not copy a whole repository, user home or deployment directory.

The builder verifies the public archive, exact dependency seal and Python lock.
Archive member types, paths, links, duplicate names and expanded bytes are bounded.
Installation is offline, binary-only, hash-required and does not run package hooks.
The final image copies dependency files only; download archives and wheelhouse
remain outside its final filesystem. npm/pnpm and pip/setuptools/wheel are absent.

Supply RECIPE_COMMIT as the actual committed recipe source at each independent
build. Keep that source distinct from the FieldDesk target and final issuer head.
Run both builds with explicit task resource limits and no networking. Record both
real receipts, OCI/archive/config/rootfs identities and normalized file inventories.

Before proposing admission, use the actual runtime_probe.py under read-only root,
networknone, nonroot65534, dropped capabilities and no-new-privileges. Capture Docker
inspection, Python/Node/package versions, current complete Node-core review, fresh
vulnerability/secret/SPDX/material/provenance evidence and all four real FieldDesk
journey steps under the exact proposed2GiB/120second profile. Verify owned cleanup.

Only an independently admitted owner can sign/install an exact reviewed image
policy and activate the matching API, worker, SDK, App and operator profile.
Disposable test trust, a measured profile or a passing private journey grants
neither signing authority nor production readiness.
