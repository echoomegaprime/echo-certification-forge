"""Security-only extraction regression from CertForge PR #23.

Provenance: echoomegaprime/echo-certification-forge PR #23 head
d8ad9fd881365801354b78a758632d2a31ab6828, reconciled against main
4f7d99e2dd4422f3d81cf5b709581be963f5818a.
This is source-level regression evidence, not P4 seal or production certification.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHED_BASE = "sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111"
OLD_BASE = "sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
ROLES = ("anchor", "custody", "runner", "signer", "verifier", "worker")


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_every_role_matches_pinned_base_and_oci_label() -> None:
    for role in ROLES:
        doc = source(f"images/{role}/Dockerfile")
        assert doc.startswith(f"FROM python:3.12-alpine@{PATCHED_BASE}\n"), role
        assert f'org.opencontainers.image.base.digest="{PATCHED_BASE}"' in doc, role
        assert OLD_BASE not in doc, role


def test_runner_and_p4_base_digest_are_identical() -> None:
    assert f'DEFAULT_IMAGE = "python:3.12-alpine@{PATCHED_BASE}"' in source(
        "src/echo_certification_forge/sandbox.py"
    )
    assert f'BASE_DIGEST="${{BASE_DIGEST:-{PATCHED_BASE}}}"' in source(
        "scripts/run_p4_gate.sh"
    )


def test_cryptography_50_has_hash_locked_artifacts() -> None:
    req = source("images/requirements.in").replace("\r\n", "\n")
    lock = source("images/requirements.lock").replace("\r\n", "\n")
    assert re.search(r"^cryptography==50\.0\.0$", req, re.M)
    assert "cryptography==49.0.0" not in lock
    found = re.search(
        r"^cryptography==50\.0\.0 \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)",
        lock,
        re.M,
    )
    assert found is not None, "Missing cryptography 50 hash-locked wheel set"
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", found.group(1))) >= 20
