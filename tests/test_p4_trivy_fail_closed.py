from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name + "_trivy_regression", ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=["seal_p4_images", "p4_hostile_acceptance"])
def scanner(request, tmp_path: Path):
    module = _load(request.param)
    raw = tmp_path / "scan.json" if request.param == "seal_p4_images" else tmp_path / "runner.trivy.json"

    def invoke():
        if request.param == "seal_p4_images":
            return module.trivy_scan(tmp_path / "trivy", "candidate:exact", raw, tmp_path / "summary.json")
        return module.trivy_scan(tmp_path / "trivy", "candidate:exact", module.ImageRole.RUNNER, tmp_path)

    return module, raw, invoke


def _scanner_output(monkeypatch, module, *, returncode=0, payload=None, write=True):
    def fake_run(command, **kwargs):
        assert kwargs["check"] is False
        if write:
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps(payload), encoding="utf-8")
        return subprocess.CompletedProcess(command, returncode, stdout="", stderr="scanner diagnostic")
    monkeypatch.setattr(module, "run", fake_run)


@pytest.mark.parametrize("returncode", [2, 137, -9])
def test_failed_scanner_cannot_pass_with_parseable_partial_report(scanner, monkeypatch, returncode):
    module, _, invoke = scanner
    _scanner_output(monkeypatch, module, returncode=returncode, payload={"SchemaVersion": 2, "Results": []})
    report = invoke()
    assert report["tool_returncode"] == returncode
    assert report["passed"] is False


def test_successful_clean_scan_retains_zero_exit_and_hash(scanner, monkeypatch):
    module, raw, invoke = scanner
    _scanner_output(monkeypatch, module, payload={"SchemaVersion": 2, "Results": []})
    report = invoke()
    assert report["tool_returncode"] == 0
    assert report["passed"] is True
    assert module.sha256_file(raw) in report.values()


@pytest.mark.parametrize("finding", ["critical", "fixed_high", "secret"])
def test_successful_scan_still_blocks_findings(scanner, monkeypatch, finding):
    module, _, invoke = scanner
    section = {}
    if finding == "secret":
        section["Secrets"] = [{"RuleID": "private-key"}]
    else:
        section["Vulnerabilities"] = [{"Severity": "CRITICAL" if finding == "critical" else "HIGH",
                                      "FixedVersion": "2.0" if finding == "fixed_high" else ""}]
    _scanner_output(monkeypatch, module, payload={"SchemaVersion": 2, "Results": [section]})
    assert invoke()["passed"] is False


def test_preexisting_report_is_preserved_and_cannot_supply_scan_evidence(scanner, monkeypatch):
    module, raw, invoke = scanner
    original = '{"SchemaVersion":2,"Results":[]}\n'
    raw.write_text(original, encoding="utf-8")
    calls = []
    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    monkeypatch.setattr(module, "run", fake_run)
    with pytest.raises(RuntimeError, match="already exists"):
        invoke()
    assert calls == []
    assert raw.read_text(encoding="utf-8") == original


def test_missing_report_fails_closed(scanner, monkeypatch):
    module, _, invoke = scanner
    _scanner_output(monkeypatch, module, write=False)
    with pytest.raises(RuntimeError, match="output"):
        invoke()


@pytest.mark.parametrize("payload", [{}, {"Results": None}, {"Results": {}}])
def test_structurally_incomplete_json_cannot_appear_clean(scanner, monkeypatch, payload):
    module, _, invoke = scanner
    _scanner_output(monkeypatch, module, payload=payload)
    with pytest.raises(RuntimeError, match="incomplete"):
        invoke()


def test_invalid_json_fails_closed(scanner, monkeypatch):
    module, _, invoke = scanner
    def fake_run(command, **kwargs):
        Path(command[command.index("--output") + 1]).write_text("{partial", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    monkeypatch.setattr(module, "run", fake_run)
    with pytest.raises(json.JSONDecodeError):
        invoke()
