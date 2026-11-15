"""A post-build CI provisioning failure cannot leave a passing evidence report."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_env_append_failure_clears_provisional_ci_success(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("prepare_ci_sandbox", ROOT / "scripts/prepare_ci_sandbox.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    image = "sha256:" + "a" * 64
    upstream = "python:3.12-alpine@sha256:" + "b" * 64
    recipe = f"FROM {upstream}\nRUN apk add --no-cache --upgrade krb5-libs=1.22.3-r0\n".encode()
    inputs = tmp_path / "images/sandbox"
    inputs.mkdir(parents=True)
    (inputs / "Dockerfile").write_bytes(recipe)
    (inputs / "runtime-input.json").write_text(json.dumps({
        "reference": "sha256:" + "c" * 64,
        "recipe": {"path": "images/sandbox/Dockerfile",
                   "upstream_reference": upstream, "os_package_upgrade": "krb5-libs=1.22.3-r0",
                   "sha256": hashlib.sha256(recipe).hexdigest()},
    }))
    def fake_run(argv, **kwargs):
        if argv[:2] == ["docker", "build"]:
            Path(argv[argv.index("--iidfile") + 1]).write_text(image)
            return subprocess.CompletedProcess(argv, 0, "", "")
        assert argv == ["docker", "image", "inspect", image]
        return subprocess.CompletedProcess(argv, 0, json.dumps([{"Id": image, "RootFS": {"Layers": []}}]), "")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    # Opening a directory as GITHUB_ENV fails only after successful fixture inspection.
    monkeypatch.setattr(sys, "argv", ["prepare_ci_sandbox.py", "--github-env", str(tmp_path)])
    assert module.main() == 1
    report = json.loads((tmp_path / "artifacts/ci-sandbox-fixture.json").read_text())
    assert report["passed"] is False
    assert report["error"]["type"] in {"IsADirectoryError", "PermissionError"}
