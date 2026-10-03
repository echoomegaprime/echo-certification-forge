#!/usr/bin/env python3
"""Full-history secret scan across every reachable git commit.

Uses gitleaks when present and a local equivalent over unique blobs.
Findings are redacted before they are written. The report never stores
secret material. GitHub Actions is disabled account-wide (#4663295);
this script is the local evidence gate.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "artifacts" / "full_history_secret_scan.json"

PATTERNS = {
    "private_key_block": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----"
    ),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret_assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|token|pepper)\s*[=:]\s*['\"][^'\"]{12,}['\"]"
    ),
}
BLOCKING = {"private_key_block", "github_token", "aws_access_key"}
INFORMATIONAL_PREFIXES = ("tests/", "artifacts/", "docs/", "scripts/")
BINARY_HINTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".woff", ".woff2", ".zip"}


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True)


def _redact(line: str) -> str:
    redacted = line.rstrip("\n")
    for pattern in PATTERNS.values():
        redacted = pattern.sub("[REDACTED]", redacted)
    if len(redacted) > 160:
        redacted = redacted[:157] + "..."
    return redacted


def _severity(detector: str, path: str) -> str:
    relative = path.replace("\\", "/")
    if relative.startswith(INFORMATIONAL_PREFIXES):
        return "informational"
    if detector in BLOCKING:
        return "blocking"
    return "review"


def _gitleaks_executable() -> str | None:
    for candidate in ("/tmp/gitleaks", shutil.which("gitleaks")):
        if candidate and Path(candidate).exists():
            return str(candidate)
    return None


def _gitleaks_findings() -> dict[str, object]:
    executable = _gitleaks_executable()
    if executable is None:
        return {"tool": "gitleaks", "available": False, "findings": []}
    raw_path = ROOT / "artifacts" / ".gitleaks-raw.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            executable,
            "detect",
            "--source",
            str(ROOT),
            "--log-opts",
            "--all",
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            str(raw_path),
            "--no-banner",
            "--exit-code",
            "0",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    version = subprocess.run(
        [executable, "version"], capture_output=True, text=True, check=False
    ).stdout.strip()
    payload: list[dict[str, object]] = []
    if raw_path.exists():
        try:
            loaded = json.loads(raw_path.read_text(encoding="utf-8") or "[]")
            if isinstance(loaded, list):
                payload = loaded
        except json.JSONDecodeError:
            payload = []
        raw_path.unlink(missing_ok=True)
    findings = []
    for item in payload:
        path = str(item.get("File") or "")
        detector = str(item.get("RuleID") or item.get("Description") or "gitleaks")
        findings.append(
            {
                "source": "gitleaks",
                "detector": detector,
                "commit": item.get("Commit"),
                "path": path,
                "line": item.get("StartLine"),
                "preview": "[REDACTED]",
                "severity": _severity(detector, path),
            }
        )
    return {
        "tool": "gitleaks",
        "available": True,
        "version": version,
        "stderr_tail": (completed.stderr or "")[-400:],
        "findings": findings,
    }


def _scan_blob(commit: str, path: str, blob: str) -> list[dict[str, object]]:
    if Path(path).suffix.lower() in BINARY_HINTS:
        return []
    try:
        raw = subprocess.run(
            ["git", "cat-file", "-p", blob],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError:
        return []
    if len(raw) > 1_000_000 or b"\x00" in raw[:2048]:
        return []
    payload = raw.decode("utf-8", errors="replace")
    findings: list[dict[str, object]] = []
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(payload):
            line_no = payload.count("\n", 0, match.start()) + 1
            line = payload.splitlines()[line_no - 1] if payload.splitlines() else ""
            findings.append(
                {
                    "source": "local_equivalent",
                    "detector": name,
                    "commit": commit,
                    "path": path,
                    "line": line_no,
                    "preview": _redact(line),
                    "severity": _severity(name, path),
                }
            )
    return findings


def _local_findings() -> dict[str, object]:
    refs = [
        line.strip()
        for line in _run(
            ["git", "for-each-ref", "--format=%(refname)", "refs/remotes"]
        ).stdout.splitlines()
        if line.strip()
    ]
    commits = [
        line.strip()
        for line in _run(["git", "rev-list", "--all"]).stdout.splitlines()
        if line.strip()
    ]
    scanned_blobs = 0
    findings: list[dict[str, object]] = []
    seen: set[tuple[str, str, int, str]] = set()
    scanned_ids: set[str] = set()
    for commit in commits:
        listing = _run(["git", "ls-tree", "-r", commit]).stdout.splitlines()
        for row in listing:
            parts = row.split(maxsplit=3)
            if len(parts) != 4 or parts[1] != "blob":
                continue
            _mode, _kind, blob, path = parts
            if blob in scanned_ids:
                continue
            scanned_ids.add(blob)
            scanned_blobs += 1
            for finding in _scan_blob(commit, path, blob):
                key = (
                    str(finding["detector"]),
                    str(finding["path"]),
                    int(finding["line"]),
                    str(finding["preview"]),
                )
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
    return {
        "tool": "local_equivalent",
        "available": True,
        "refs_scanned": refs,
        "commits_scanned": len(commits),
        "unique_blobs_scanned": scanned_blobs,
        "findings": findings,
    }


def main() -> int:
    gitleaks = _gitleaks_findings()
    local = _local_findings()
    findings = list(gitleaks.get("findings", [])) + list(local.get("findings", []))
    blocking = [item for item in findings if item.get("severity") == "blocking"]
    report = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "scope": "all git commits reachable from remote-tracking refs",
        "hosted_ci": "disabled_account_wide_ticket_4663295",
        "redacted": True,
        "gitleaks": {
            "available": gitleaks.get("available"),
            "version": gitleaks.get("version"),
            "finding_count": len(list(gitleaks.get("findings", []))),
        },
        "local_equivalent": {
            "refs_scanned": local.get("refs_scanned"),
            "commits_scanned": local.get("commits_scanned"),
            "unique_blobs_scanned": local.get("unique_blobs_scanned"),
            "finding_count": len(list(local.get("findings", []))),
        },
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "findings": findings,
        "passed": len(blocking) == 0,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "report": str(OUTPUT.relative_to(ROOT)).replace("\\", "/"),
                "sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
                "gitleaks_available": bool(gitleaks.get("available")),
                "finding_count": len(findings),
                "blocking_count": len(blocking),
                "passed": report["passed"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
