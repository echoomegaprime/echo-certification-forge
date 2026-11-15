#!/usr/bin/env python3
"""Certification Forge journey for echo-certification-forge itself (ops-20260924).

CertForge runs this against the exact acquired commit, offline and stdlib-only, from a
read-only checkout. The product's full suite needs pydantic and cryptography, so it runs in
hosted CI and in P1-P7 acceptance. This journey proves the release contract that has to hold
for any certifiable CertForge build:

- The production rule manifest's canonical digest equals the pinned
  run_worker._PRODUCTION_MANIFEST_SHA256 and the deploy default.
- Every role image and the journey sandbox use one patched base-image digest, and
  cryptography is hash-locked at a patched release.
- The dispatcher unit only Wants= the API service (issue #22).
- Every source module compiles.
- The stdlib-runnable release suites pass through scripts/certforge_testkit.py.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import certforge_testkit  # noqa: E402

SUITES = ("tests/test_release_pins.py", "tests/test_deploy_gate.py")


def fail(message: str) -> int:
    print(f"CERTFORGE_SELF_JOURNEY_FAILED: {message}", file=sys.stderr)
    return 1


def canonical_digest(path: Path) -> str:
    value = json.loads(path.read_text(encoding="utf-8"))
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def main() -> int:
    cert = json.loads((ROOT / ".echo/certification.json").read_text(encoding="utf-8"))
    apps = json.loads((ROOT / ".echo/apps.json").read_text(encoding="utf-8"))
    if cert.get("version") != 1 or apps.get("apps", {}).get("certification-forge", {}).get("enabled") is not True:
        return fail("opt-in contract invalid")

    manifest_digest = canonical_digest(ROOT / "policies/mandatory-rules.v2.json")
    run_worker = (ROOT / "src/echo_certification_forge/run_worker.py").read_text(encoding="utf-8")
    pinned = re.search(r'_PRODUCTION_MANIFEST_SHA256 = \(\s*"([0-9a-f]{64})"', run_worker)
    deploy = (ROOT / "deploy/deploy_forge.sh").read_text(encoding="utf-8")
    deploy_default = re.search(r'TRUSTED_MANIFEST_SHA256="\$\{ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256:-([0-9a-f]{64})\}"',
                               deploy)
    if not pinned or pinned.group(1) != manifest_digest:
        return fail(f"run_worker manifest pin != canonical policy digest {manifest_digest}")
    if not deploy_default or deploy_default.group(1) != manifest_digest:
        return fail("deploy default trusted manifest digest != canonical policy digest")

    compiled = 0
    for path in sorted((ROOT / "src").rglob("*.py")):
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except SyntaxError as exc:
            return fail(f"syntax error: {path.relative_to(ROOT)}: {exc}")
        compiled += 1
    print(json.dumps({"manifest_sha256": manifest_digest, "modules_compiled": compiled}))
    # The two release suites are self-contained text/contract checks; tests/conftest.py needs
    # pydantic/cryptography, which the stdlib-only sandbox does not have.
    return certforge_testkit.run(ROOT, SUITES, sys_paths=("tests", "."), budget_s=60.0,
                                 min_passed=15, conftest=False)


if __name__ == "__main__":
    raise SystemExit(main())
