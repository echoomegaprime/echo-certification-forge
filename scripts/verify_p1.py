"""One-command P1 verification and evidence-log generator."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ARTIFACTS = REPO / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)


def run(name: str, command: list[str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1"},
        check=False,
    )
    log_path = ARTIFACTS / f"p1_{name}.txt"
    log_path.write_text(completed.stdout, encoding="utf-8", newline="\n")
    return {
        "name": name,
        "command": command,
        "exit_code": completed.returncode,
        "log": str(log_path.relative_to(REPO)),
        "log_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
    }


def source_manifest() -> dict[str, str]:
    result: dict[str, str] = {}
    for base in (REPO / "src", REPO / "tests", REPO / "policies", REPO / "scripts"):
        for path in sorted(item for item in base.rglob("*") if item.is_file() and "__pycache__" not in item.parts):
            result[str(path.relative_to(REPO)).replace("\\", "/")] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def main() -> int:
    python = sys.executable
    checks = [
        run("compileall", [python, "-m", "compileall", "-q", "src", "tests", "scripts"]),
        run("pytest", [python, "-m", "pytest", "-q", "--cov", "--cov-report=term-missing"]),
        run("acceptance", [python, "scripts/p1_acceptance.py"]),
        run("runtime_smoke", [python, "scripts/p1_runtime_smoke.py"]),
        run("pip_check", [python, "-m", "pip", "check"]),
        run("diff_check", ["git", "diff", "--check"]),
    ]
    forbidden: list[dict[str, str]] = []
    for path in sorted((REPO / "src").rglob("*.py")):
        lowered = path.read_text(encoding="utf-8").lower()
        for token in ("todo", "fixme", "notimplementederror"):
            if token in lowered:
                forbidden.append({"path": str(path.relative_to(REPO)), "token": token})
    report = {
        "schema_version": "1.0.0",
        "phase": "P1",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "python": sys.version,
        "checks": checks,
        "forbidden_source_tokens": forbidden,
        "source_manifest": source_manifest(),
    }
    report["passed"] = all(item["exit_code"] == 0 for item in checks) and not forbidden
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (ARTIFACTS / "p1_verification_report.json").write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
