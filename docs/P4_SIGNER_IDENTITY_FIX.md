# P4 Signer Image-Identity Fix — root cause of the rerun5 INFRA_FAILED

Status as of 2026-07-17: **fixed at the root cause, regression-tested, local
suite green. NOT yet validated by the real FORGE gate — that is what rerun6
is for.** Nothing below claims gate validation.

## The bug (rerun5, 2026-07-17T09:27–10:02Z)

`scripts/p3_forge_acceptance.py::run_signer_container` validated the signer
container's image identity like this (pre-fix, as of commit `c978f45`):

```python
if created.get("Image") != image.split("@", 1)[-1]:
    issues += ("signer_image_identity_mismatch",)
```

Two incompatible representations were being compared:

- Docker container-inspect `Image` is **always the image ID**
  (`sha256:<64-hex>` of the image config), never the tag or repo digest the
  container was created from.
- `image.split("@", 1)[-1]` yields the **repo digest** for a
  `name@sha256:...` reference — and for a plain tag reference (which is what
  the P4 gate actually passes: `echo-certforge-signer:p4-b9f93c9-a`) the
  split is a no-op and yields the **raw tag string**.

Image-ID vs tag-string (or vs repo-digest, which hashes the manifest, not
the config) can never be equal, so the check false-positived on every run.
Verified on FORGE, not inferred: `docker image inspect
echo-certforge-signer:p4-b9f93c9-a` → ID `sha256:5ebade8331a05c37…`, exactly
the ID the rerun5 container ran. The signer container itself SUCCEEDED
(exit 0, `ok:true`, signed payload, anchor receipt issued); the only failure
was the identity check. Result: `inspect_issues:
['signer_image_identity_mismatch']` → "purpose-built signer failed P3
workflow" → `run_outcome: INFRA_FAILED`, `rerun5.exit = 1`. Full forensics:
`docs/P4_RERUN5_READINESS.md`.

## The fix (commit `307667a` + distinctness hardening in this commit)

Resolve the reference to the exact local image ID FIRST, bind container
creation to that ID, and compare ID-to-ID:

```python
def resolve_image_id(api: DockerAPI, reference: str) -> str:
    inspected = api.request("GET", f"/images/{urllib.parse.quote(reference, safe=':@')}/json")
    image_id = (inspected or {}).get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise RuntimeError(f"unresolvable image reference: {reference}")   # fail-closed
    return image_id

# in run_signer_container:
resolved_image_id = resolve_image_id(api, image)
payload = signer_payload(image=resolved_image_id, ...)   # creation bound to the ID
...
if created.get("Image") != resolved_image_id:            # ID-to-ID
    issues += ("signer_image_identity_mismatch",)
```

Properties, deliberately in the STRONGER direction:

- **Fail-closed:** an unresolvable reference raises before any container is
  created; the gate aborts rather than skipping the check.
- **Race removed:** creation is bound to the immutable ID, so a tag being
  re-pointed between resolution and creation cannot swap the image.
- **Genuine mismatch still fails:** the check itself was not removed or
  loosened — only the representations were made comparable. A container
  running any image other than the resolved one is still flagged.

### Same-class bug fixed in the distinctness check (this commit)

`signer_image_distinct_from_runner_image` had the same
string-form-vs-identity defect in the opposite (unsafe) direction:

```python
# before — tag string vs image ID: trivially "distinct" for ANY tag reference,
# even one pointing at the runner image itself
"signer_image_distinct_from_runner_image": args.signer_image.split("@", 1)[-1] != P2_RUNNER_IMAGE,

# after — resolved ID vs pinned runner ID
"signer_image_distinct_from_runner_image": signer_image_is_distinct_from_runner(api, args.signer_image),
```

`signer_image_is_distinct_from_runner` resolves the signer reference via
`resolve_image_id` and compares against the pinned `P2_RUNNER_IMAGE` ID. A
signer tag that actually points at the runner image now correctly FAILS the
distinctness check instead of passing on string inequality. This is a
strictly stronger supply-chain check; no check was weakened.

## Regression tests (`tests/test_p3_signer_image_identity.py`, 6 tests)

The suite proves both required directions — the fix is NOT an always-pass:

| Test | Proves |
|---|---|
| `test_resolve_image_id_returns_exact_id` | tag → exact local `sha256:` ID resolution |
| `test_resolve_image_id_fails_closed_on_unresolvable` | unresolvable reference raises (fail-closed) |
| `test_tag_reference_binds_creation_to_exact_id_without_false_mismatch` | **(a)** matching image, passed by tag, creates the container bound to the ID and raises NO `signer_image_identity_mismatch` — the rerun5 false positive is gone |
| `test_container_running_different_image_is_flagged` | **(b)** a container running a genuinely different image IS still flagged `signer_image_identity_mismatch` |
| `test_signer_distinct_from_runner_compares_resolved_ids` | a signer resolving to a non-runner ID reports distinct |
| `test_signer_tag_pointing_at_runner_image_is_not_distinct` | a signer tag resolving to the runner image ID FAILS distinctness (previously a trivial pass) |

Evidence (2026-07-17, HAMMER, repo `.venv` Python 3.13):

```
tests/test_p3_signer_image_identity.py::test_resolve_image_id_returns_exact_id PASSED
tests/test_p3_signer_image_identity.py::test_resolve_image_id_fails_closed_on_unresolvable PASSED
tests/test_p3_signer_image_identity.py::test_tag_reference_binds_creation_to_exact_id_without_false_mismatch PASSED
tests/test_p3_signer_image_identity.py::test_container_running_different_image_is_flagged PASSED
tests/test_p3_signer_image_identity.py::test_signer_distinct_from_runner_compares_resolved_ids PASSED
tests/test_p3_signer_image_identity.py::test_signer_tag_pointing_at_runner_image_is_not_distinct PASSED
6 passed
```

Full local suite on the same tree:

- `python -m compileall src scripts` → exit 0
- `pytest --cov=echo_certification_forge` (branch coverage, floor 85% in
  pyproject) → **141 passed, 0 failed; total 85.33% ≥ 85%**

## Rerun6 readiness — true state

- The rerun5 root cause is fixed and regression-locked; the distinctness
  sibling check is hardened the same way.
- Per the project contract, only the real FORGE gate validates the fix.
  Before rerun6: push the new HEAD, rebuild role images from that exact
  commit, re-seal identities (`scripts/seal_p4_images.py`) — the `b9f93c9`
  seal does not cover the new harness hashes — and mind FORGE resource
  pressure (see `docs/P4_RERUN5_READINESS.md` §3).
- `completed_phase_gate` remains `P3`; release verdict remains `NOT_READY`
  until the gate passes.
