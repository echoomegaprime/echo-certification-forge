"""Keep the hosted P7 generator executable against measured worker identity."""
import importlib.util
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_p7_acceptance_preserves_positive_and_negative_execution_boundaries(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("p7_acceptance_identity_test", ROOT / "scripts/p7_acceptance.py")
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)
    for name in ("policies", "contracts"):
        shutil.copytree(ROOT / name, tmp_path / name)
    (tmp_path / "artifacts").mkdir()
    monkeypatch.setattr(acceptance, "REPO", tmp_path)

    result = acceptance.main()
    report = json.loads((tmp_path / "artifacts/p7_acceptance_report.json").read_text(encoding="utf-8"))
    failed = [name for name, value in report["scenarios"].items() if not value["passed"]]
    assert failed == [], failed
    assert result == 0 and report["passed"] is True
    assert report["release_verdict"] == "NOT_READY"
    assert report["scenarios"]["canonical_identity_reconciliation"]["worker_result"]["signed"] is True
    assert report["scenarios"]["suspension_wins_execution_boundary"]["customer_code_executed"] is False
    assert report["scenarios"]["expired_lease_cannot_commit_signed_completion"]["worker_result"]["error"] == "subscriber_execution_fenced"
    assert not (tmp_path / "var/p7-acceptance-runtime").exists()
