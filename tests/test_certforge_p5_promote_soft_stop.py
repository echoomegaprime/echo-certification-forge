"""Exit-code contract for certforge-p5-promote.sh soft stops.

Soft stop (pending-hosted-ci) must exit 75 (EX_TEMPFAIL), never 0.
Hard failures exit 1. Only a completed promotion exits 0.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROMOTE = ROOT / "scripts" / "certforge-p5-promote.sh"
SMOKE = ROOT / "scripts" / "smoke_certforge_p5_promote_exit_codes.sh"


def test_promote_script_exists_and_is_executable() -> None:
    assert PROMOTE.is_file()
    text = PROMOTE.read_text(encoding="utf-8")
    assert "EXIT_PENDING=75" in text
    assert "soft_stop" in text
    assert "pending-hosted-ci" in text
    # The historical defect: exit 0 on pending-hosted-ci.
    for line in text.splitlines():
        if "pending-hosted-ci" in line and "exit" in line:
            assert "exit 0" not in line
            assert "exit 75" in line or "soft_stop" in line or "EXIT_PENDING" in line


def test_no_soft_stop_exit_zero_patterns() -> None:
    text = PROMOTE.read_text(encoding="utf-8")
    # Classic defect shape: print pending then exit 0.
    assert not re.search(
        r"pending-hosted-ci[^\n]*\n\s*exit 0\b",
        text,
    )
    assert not re.search(
        r"printf 'promotion=pending-hosted-ci\\n'\s*\n\s*exit 0\b",
        text,
    )


def test_pending_qualification_also_soft_stops() -> None:
    text = PROMOTE.read_text(encoding="utf-8")
    assert "soft_stop \"promotion=pending-qualification\"" in text
    assert "soft_stop \"promotion=launched:" in text or 'soft_stop "promotion=launched:' in text


def test_smoke_exit_code_acceptance() -> None:
    """Run the three-state acceptance harness (green/pending/hard)."""
    assert SMOKE.is_file()
    proc = subprocess.run(
        ["bash", str(SMOKE)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env={**os.environ, "CERTFORGE_PROMOTE_SCRIPT": str(PROMOTE)},
        check=False,
    )
    print(proc.stdout)
    print(proc.stderr)
    assert proc.returncode == 0, (
        f"smoke failed rc={proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "pass=" in proc.stdout
    assert "fail=0" in proc.stdout


def test_and_chain_does_not_advance_on_pending(tmp_path: Path) -> None:
    """Direct integration: pending mock + && must not run the next command."""
    root = tmp_path / "root"
    eval_root = tmp_path / "eval"
    qual = eval_root / "qualification"
    promo = eval_root / "promo"
    logs = tmp_path / "logs"
    for p in (root, qual, promo, logs):
        p.mkdir(parents=True)

    (root / "SOURCE_COMMIT").write_text("abc123\n", encoding="utf-8")
    # Valid qualification so we reach the hosted-CI gate.
    import json

    adapter = {
        "candidate": {"hard_gates_passed": True},
        "promotion_threshold": {"passed": True},
        "promotion_decision": "PROMOTE",
    }
    report = {
        "schema": "echo.certification-forge.p5-qualification/v2",
        "scoring_contract": {
            "schema": "echo.certification-forge.p5-semantic-scoring/v2"
        },
        "run_outcome": "COMPLETE",
        "promotion_decision": "PROMOTE",
        "release_verdict": "NOT_READY",
        "training_split_used": False,
        "response_receipts": {"successful_rows": 960},
        "qualification": {"gs343": adapter, "r2d2": adapter},
    }
    (qual / "qualification-report.json").write_text(
        json.dumps(report), encoding="utf-8"
    )

    marker = tmp_path / "advanced"
    env = {
        **os.environ,
        "CERTFORGE_PROMOTE_ROOT": str(root),
        "CERTFORGE_PROMOTE_EXPECTED_COMMIT": "abc123",
        "CERTFORGE_PROMOTE_SOURCE_COMMIT_FILE": str(root / "SOURCE_COMMIT"),
        "CERTFORGE_PROMOTE_PYTHON": "python3",
        "CERTFORGE_PROMOTE_EVAL_ROOT": str(eval_root),
        "CERTFORGE_PROMOTE_QUALIFICATION": str(qual / "qualification-report.json"),
        "CERTFORGE_PROMOTE_RUN_ID": "pytest-pending",
        "CERTFORGE_PROMOTE_PROMOTION_DIR": str(promo),
        "CERTFORGE_PROMOTE_LOG": str(logs / "p.log"),
        "CERTFORGE_PROMOTE_PIDFILE": str(logs / "p.pid"),
        "CERTFORGE_PROMOTE_LOCK": str(logs / "p.lock"),
        "CERTFORGE_PROMOTE_EVALUATOR_PIDFILE": str(logs / "e.pid"),
        "CERTFORGE_HOSTED_CI_MOCK": "pending",
    }
    shell = (
        f'bash "{PROMOTE}" run && touch "{marker}"; '
        f'echo EXIT:$?'
    )
    proc = subprocess.run(
        ["bash", "-c", shell],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert "promotion=pending-hosted-ci" in proc.stdout
    assert "promotion=pending-hosted-ci" in proc.stderr
    assert not marker.exists(), "&& chain advanced on soft stop"
    # Outer shell reports the promote exit code after failed &&.
    assert "EXIT:75" in proc.stdout or proc.returncode == 75 or "EXIT:75" in (
        proc.stdout + proc.stderr
    )
