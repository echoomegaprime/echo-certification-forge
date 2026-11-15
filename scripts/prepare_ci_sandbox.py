#!/usr/bin/env python3
"""Provision an immutable CI behavior fixture from the public runtime recipe.

This reproduces the qualified profile, not the delivered DEFAULT_IMAGE artifact.
The exact delivered artifact is verified separately on the execution node.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL_LOCAL_ID = re.compile(r"sha256:[0-9a-f]{64}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    output = ROOT / "artifacts/ci-sandbox-fixture.json"
    output.parent.mkdir(exist_ok=True)
    report = {"scope": "CI_PROFILE_REPRODUCTION_NOT_DELIVERED_DEFAULT",
              "source_commit": os.environ.get("ECHO_SOURCE_SHA"),
              "passed": False}
    try:
        qualified = json.loads((ROOT / "images/sandbox/runtime-input.json").read_text(encoding="utf-8"))
        recipe_path = ROOT / qualified["recipe"]["path"]
        recipe = recipe_path.read_bytes()
        recipe_sha = hashlib.sha256(recipe).hexdigest()
        if recipe_sha != qualified["recipe"]["sha256"]:
            raise ValueError("CI runtime recipe hash differs from the qualified input")
        expected_recipe = (
            f'FROM {qualified["recipe"]["upstream_reference"]}\n'
            f'RUN apk add --no-cache --upgrade {qualified["recipe"]["os_package_upgrade"]}\n'
        ).encode("utf-8")
        if recipe != expected_recipe:
            raise ValueError("CI runtime context must contain only the exact public base/package recipe")
        report.update(recipe_sha256=recipe_sha, qualified_default_image=qualified["reference"])
        with tempfile.TemporaryDirectory(prefix="certforge-ci-runtime-") as temporary:
            context = Path(temporary)
            (context / "Dockerfile").write_bytes(recipe)
            iid_path = context / "image-id.txt"
            command = ["docker", "build", "--pull=false", "--no-cache",
                       "--iidfile", str(iid_path), str(context)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
            report["build_returncode"] = completed.returncode
            if completed.returncode != 0:
                report["build_diagnostic"] = (completed.stdout + completed.stderr)[-4000:]
                raise RuntimeError("CI runtime fixture build failed")
            image_id = iid_path.read_text(encoding="ascii").strip()
            if FULL_LOCAL_ID.fullmatch(image_id) is None:
                raise ValueError("Docker build did not return a full immutable local image ID")
            inspected = subprocess.run(["docker", "image", "inspect", image_id],
                                       capture_output=True, text=True, check=True, timeout=20)
            image = json.loads(inspected.stdout)
            if len(image) != 1 or image[0].get("Id") != image_id:
                raise ValueError("CI image inspection does not match the built full local ID")
            report.update(ci_fixture_image_id=image_id,
                          rootfs_diff_ids=(image[0].get("RootFS") or {}).get("Layers", []),
                          identity_kind="docker_local_image_id",
                          passed=True)
            if args.github_env is not None:
                with args.github_env.open("a", encoding="utf-8") as environment_file:
                    environment_file.write(f"ECHO_CERTFORGE_TEST_SANDBOX_IMAGE={image_id}\n")
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"CI behavior fixture: {report['ci_fixture_image_id']}")
        print(f"Runtime recipe SHA256: {recipe_sha}")
        print("Scope: reproduced profile; delivered DEFAULT artifact acceptance is separate")
        return 0
    except Exception as exc:
        report["passed"] = False
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"CI runtime fixture failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
