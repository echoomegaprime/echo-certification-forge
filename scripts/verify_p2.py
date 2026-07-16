#!/usr/bin/env python3
"""One-command deterministic P2 verification and evidence package."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from echo_certification_forge.supply_chain import contains_private_key_material

ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

EXPECTED_EVIDENCE = {
    "artifacts/p2_forge_acceptance.json": (
        20807,
        "d563aefcb121f91f5b6beda0f82ce80d776dd7bc6f2caaf6253226370883ef68",
    ),
    "artifacts/p2_forge_acceptance.summary.json": (
        12256,
        "3d17fee069b44b30794ee1f5ef871934406a785307e2b64724f8a59956b81093",
    ),
}
P2_SOURCE_COMMIT = "87c8afcfa5e439219b8737f7fdcb202967810316"
EXPECTED_SOURCE_IDENTITIES = {
    "src/echo_certification_forge/runner.py": "19ebf13539dc878611bb21a8aeb1f8621ca2d43e4cf82b290a5bb3f5761b03d4",
    "scripts/p2_forge_acceptance.py": "4c83a187509a8e62477bed861dc16523a0400476260e8bf44f2ddae8b0dfd823",
}
FORBIDDEN_PATTERNS = {
    "github_token": re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret_assignment": re.compile(
        r"(?i)\b(?:" + "|".join((r"api[_-]?key", "secret", "password", "token"))
        + r")\s*[=:]\s*['\"][^'\"]{12,}['\"]"
    ),
}
SCAN_SUFFIXES = {".py", ".md", ".json", ".yml", ".yaml", ".toml", ".txt"}
SCAN_EXCLUDES = {".git", ".venv", "__pycache__", ".pytest_cache", ".coverage"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_check(name: str, command: list[str], log_name: str) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_path = ARTIFACTS / log_name
    log_path.write_text(result.stdout, encoding="utf-8")
    return {
        "name": name,
        "command": command,
        "exit_code": result.returncode,
        "log": str(log_path.relative_to(ROOT)),
        "log_sha256": sha256(log_path),
    }


def verify_evidence() -> dict[str, Any]:
    verified: dict[str, Any] = {}
    for relative, (expected_size, expected_hash) in EXPECTED_EVIDENCE.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"missing P2 evidence: {relative}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != expected_size:
            raise RuntimeError(f"P2 evidence size mismatch: {relative}")
        if digest != expected_hash:
            raise RuntimeError(f"P2 evidence hash mismatch: {relative}")
        report = json.loads(data)
        if report.get("passed") is not True:
            raise RuntimeError(f"P2 evidence does not pass: {relative}")
        if report.get("run_outcome") != "COMPLETE":
            raise RuntimeError(f"P2 run outcome mismatch: {relative}")
        if report.get("release_verdict") != "NOT_READY":
            raise RuntimeError(f"P2 product verdict must remain NOT_READY: {relative}")
        verified[relative] = {
            "bytes": len(data),
            "sha256": digest,
            "passed": True,
            "run_outcome": "COMPLETE",
            "release_verdict": "NOT_READY",
        }

    full = json.loads((ROOT / "artifacts/p2_forge_acceptance.json").read_text(encoding="utf-8"))
    case_status = {key: value.get("passed") for key, value in full.get("cases", {}).items()}
    required_cases = {
        "isolation",
        "cpu_exhaustion",
        "pid_exhaustion",
        "disk_fill",
        "file_size_limit",
        "hostile_install_script",
        "timeout",
        "cancellation",
        "runner_crash",
    }
    if set(case_status) != required_cases or not all(case_status.values()):
        raise RuntimeError(f"P2 case set or result mismatch: {case_status}")
    transport = full.get("transport", {})
    if transport.get("passed") is not True or not all(transport.get("checks", {}).values()):
        raise RuntimeError("P2 transport checks are incomplete or failed")
    cleanup = full.get("cleanup", {})
    if cleanup.get("errors") != [] or cleanup.get("unrelated_container_ids_preserved") is not True:
        raise RuntimeError("P2 cleanup proof is invalid")
    if len(cleanup.get("owned_container_ids", [])) != 9:
        raise RuntimeError("P2 owned-container cleanup count mismatch")
    return {"files": verified, "case_status": case_status, "transport_checks": transport["checks"], "cleanup": cleanup}


def verify_source_identities() -> dict[str, str]:
    """Verify the immutable P2 closure blobs, not later-phase working-tree source."""
    commit_check = subprocess.run(
        ["git", "cat-file", "-e", f"{P2_SOURCE_COMMIT}^{{commit}}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if commit_check.returncode != 0:
        raise RuntimeError(f"P2 source commit missing: {P2_SOURCE_COMMIT}")
    result: dict[str, str] = {}
    for relative, expected in EXPECTED_SOURCE_IDENTITIES.items():
        blob = subprocess.run(
            ["git", "show", f"{P2_SOURCE_COMMIT}:{relative}"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if blob.returncode != 0:
            raise RuntimeError(f"P2 source blob missing: {P2_SOURCE_COMMIT}:{relative}")
        digest = hashlib.sha256(blob.stdout).hexdigest()
        if digest != expected:
            raise RuntimeError(f"P2 source identity mismatch: {relative}: {digest} != {expected}")
        result[relative] = digest
    result["p2_source_commit"] = P2_SOURCE_COMMIT
    return result


def secret_scan() -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned = 0
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if any(part in SCAN_EXCLUDES for part in path.parts):
            continue
        scanned += 1
        payload = path.read_bytes()
        if contains_private_key_material(payload):
            findings.append({"file": str(path.relative_to(ROOT)), "pattern": "private_key_material", "line": 1})
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in FORBIDDEN_PATTERNS.items():
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "file": str(path.relative_to(ROOT)),
                        "pattern": name,
                        "line": text.count("\n", 0, match.start()) + 1,
                    }
                )
    if findings:
        raise RuntimeError(f"secret scan findings: {findings}")
    report = {"scanned_files": scanned, "findings": findings, "passed": True}
    path = ARTIFACTS / "p2_secret_scan.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["log"] = str(path.relative_to(ROOT))
    report["log_sha256"] = sha256(path)
    return report


def source_manifest() -> dict[str, str]:
    roots = [ROOT / "src", ROOT / "tests", ROOT / "scripts", ROOT / "docs", ROOT / "policies"]
    files: list[Path] = []
    for base in roots:
        if base.exists():
            files.extend(path for path in base.rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    files.extend([ROOT / "README.md", ROOT / "pyproject.toml"])
    return {str(path.relative_to(ROOT)).replace("\\", "/"): sha256(path) for path in sorted(set(files))}


def main() -> int:
    python = sys.executable
    checks = [
        run_check("compileall", [python, "-m", "compileall", "-q", "src", "tests", "scripts"], "p2_compileall.txt"),
        run_check("pytest", [python, "-m", "pytest", "-q", "--cov", "--cov-report=term-missing"], "p2_pytest.txt"),
        run_check("pip_check", [python, "-m", "pip", "check"], "p2_pip_check.txt"),
        run_check("diff_check", ["git", "diff", "--check"], "p2_diff_check.txt"),
    ]
    evidence = verify_evidence()
    source_identity = verify_source_identities()
    secrets = secret_scan()
    passed = all(check["exit_code"] == 0 for check in checks)
    report = {
        "schema_version": "1.0.0",
        "phase": "P2",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "python": sys.version,
        "platform": sys.platform,
        "checks": checks,
        "evidence": evidence,
        "source_identity": source_identity,
        "secret_scan": secrets,
        "source_manifest": source_manifest(),
        "run_outcome": "COMPLETE" if passed else "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
        "passed": passed,
    }
    report_path = ARTIFACTS / "p2_verification_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "report": str(report_path),
        "report_sha256": sha256(report_path),
        "passed": passed,
        "run_outcome": report["run_outcome"],
        "release_verdict": report["release_verdict"],
        "check_exit_codes": {check["name"]: check["exit_code"] for check in checks},
    }, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
