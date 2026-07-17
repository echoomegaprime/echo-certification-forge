from __future__ import annotations

import hashlib
import importlib.util
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "p4_hostile_acceptance_hardened.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location(
        "p4_hostile_acceptance_hardened_test",
        SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def service_health_probe() -> float:
    deadline = time.monotonic() + 12
    return deadline


def drifted_service_health_probe() -> float:
    deadline = time.monotonic() + 15
    return deadline


def test_apply_service_health_deadline_replaces_only_expected_expression() -> None:
    wrapper = load_wrapper()
    harness = SimpleNamespace(
        service_health_probe=service_health_probe,
        __file__=str(SCRIPT),
    )

    hardened = wrapper.apply_service_health_deadline(harness)

    before = time.monotonic()
    deadline = hardened.service_health_probe()
    after = time.monotonic()
    assert before + 29.9 <= deadline <= after + 30.1
    assert hardened.P4_SERVICE_HEALTH_DEADLINE_SECONDS == 30


def test_apply_service_health_deadline_fails_closed_on_contract_drift() -> None:
    wrapper = load_wrapper()
    harness = SimpleNamespace(
        service_health_probe=drifted_service_health_probe,
        __file__=str(SCRIPT),
    )

    with pytest.raises(RuntimeError, match="deadline contract drift"):
        wrapper.apply_service_health_deadline(harness)


def test_apply_report_hardening_records_deadline_and_entrypoints(tmp_path: Path) -> None:
    wrapper = load_wrapper()
    output_path = tmp_path / "report.json"

    def sha256_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def enrich_report(**kwargs):
        report = {
            "passed": True,
            "run_outcome": "COMPLETE",
            "release_verdict": "NOT_READY",
            "harness": {
                "path": "exact.py",
                "sha256": "before",
                "core_path": "core.py",
                "core_sha256": "core-hash",
            },
            "checks": {"existing": True},
        }
        kwargs["output_path"].write_text(json.dumps(report), encoding="utf-8")
        return report

    exact = SimpleNamespace(
        enrich_report=enrich_report,
        sha256_file=sha256_file,
    )
    wrapper.apply_report_hardening(exact)

    report = exact.enrich_report(
        output_path=output_path,
        harness=SimpleNamespace(),
        capture={},
        return_code=0,
    )

    identity = report["harness"]
    assert identity["path"] == str(SCRIPT.resolve())
    assert identity["sha256"] == sha256_file(SCRIPT.resolve())
    assert identity["exact_path"] == str(wrapper.EXACT_ENTRYPOINT)
    assert identity["exact_sha256"] == sha256_file(wrapper.EXACT_ENTRYPOINT)
    assert identity["core_path"] == "core.py"
    assert identity["core_sha256"] == "core-hash"
    assert identity["service_health_deadline_seconds"] == 30
    assert report["checks"]["bounded_service_health_deadline_recorded"] is True
    assert json.loads(output_path.read_text(encoding="utf-8")) == report


def test_main_layers_over_exact_entrypoint(monkeypatch) -> None:
    wrapper = load_wrapper()
    core = SimpleNamespace(
        service_health_probe=service_health_probe,
        __file__=str(SCRIPT),
    )
    observed = {}

    class Exact:
        def __init__(self) -> None:
            self.load_harness = lambda: core
            self.enrich_report = lambda **kwargs: {}
            self.sha256_file = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

        def main(self, arguments):
            hardened = self.load_harness()
            observed["deadline"] = hardened.P4_SERVICE_HEALTH_DEADLINE_SECONDS
            observed["arguments"] = arguments
            observed["enrich_wrapped"] = self.enrich_report.__name__
            return 0

    exact = Exact()
    monkeypatch.setattr(wrapper, "load_exact_entrypoint", lambda: exact)

    assert wrapper.main(["--probe"]) == 0
    assert observed == {
        "deadline": 30,
        "arguments": ["--probe"],
        "enrich_wrapped": "enrich_report_hardened",
    }
