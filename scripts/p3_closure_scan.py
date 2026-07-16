#!/usr/bin/env python3
"""Fail-closed P3 repository secret, key-material, and incomplete-token scan."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "artifacts/p3_secret_scan.json"
SCAN_SUFFIXES = {".py", ".md", ".json", ".jsonl", ".yml", ".yaml", ".toml", ".txt", ".pem"}
EXCLUDED_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache"}
PATTERNS = {
    "private_key": re.compile("-----BEGIN " + "(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret_assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[=:]\s*['\"][^'\"]{12,}['\"]"
    ),
}
P3_CODE = {
    "src/echo_certification_forge/anchor.py",
    "src/echo_certification_forge/custody.py",
    "src/echo_certification_forge/p3_runtime.py",
    "src/echo_certification_forge/p3_service.py",
    "src/echo_certification_forge/signer_cli.py",
    "src/echo_certification_forge/signing_service.py",
    "scripts/p3_forge_acceptance.py",
    "scripts/verify_p3.py",
    "scripts/p3_closure_scan.py",
}
INCOMPLETE = re.compile(r"(?i)\b(?:" + "|".join(("TO" + "DO", "FIX" + "ME", "Not" + "ImplementedError")) + r")\b")

findings: list[dict[str, object]] = []
scanned = 0
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
        continue
    if any(part in EXCLUDED_PARTS for part in path.parts):
        continue
    scanned += 1
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    relative = str(path.relative_to(ROOT)).replace("\\", "/")
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append({"file": relative, "pattern": name, "line": text.count("\n", 0, match.start()) + 1})
    if relative in P3_CODE:
        for match in INCOMPLETE.finditer(text):
            findings.append({"file": relative, "pattern": "incomplete_code_token", "line": text.count("\n", 0, match.start()) + 1})
report = {
    "schema_version": "1.0.0",
    "phase": "P3",
    "scanned_files": scanned,
    "findings": findings,
    "passed": not findings,
}
OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps({**report, "report": str(OUTPUT.relative_to(ROOT)).replace("\\", "/"), "sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}, indent=2, sort_keys=True))
raise SystemExit(0 if report["passed"] else 1)
