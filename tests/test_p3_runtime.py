from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from echo_certification_forge.runner import ControlPlaneTransportAuthority

_RUNTIME_MODULE = "echo_certification_forge.p3_runtime"


def _import_custody_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tmp_path.mkdir(parents=True, exist_ok=True)
    authority = ControlPlaneTransportAuthority.generate()
    transport_public_key = tmp_path / "transport-public.pem"
    transport_public_key.write_text(authority.public_key_pem, encoding="ascii")
    monkeypatch.setenv("ECHO_CERTFORGE_P3_MODE", "custody")
    monkeypatch.setenv("ECHO_CERTFORGE_TRANSPORT_PUBLIC_KEY", str(transport_public_key))
    monkeypatch.setenv("ECHO_CERTFORGE_RUNNER_DB", str(tmp_path / "runner.sqlite3"))
    monkeypatch.setenv("ECHO_CERTFORGE_CUSTODY_DB", str(tmp_path / "custody.sqlite3"))
    monkeypatch.setenv("ECHO_CERTFORGE_CUSTODY_ROOT", str(tmp_path / "evidence"))
    sys.modules.pop(_RUNTIME_MODULE, None)
    return importlib.import_module(_RUNTIME_MODULE)


def test_custody_runtime_factory_and_fail_closed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    runtime = _import_custody_runtime(tmp_path, monkeypatch)
    health = TestClient(runtime.app).get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["private_verdict_signing_key_loaded"] is False

    monkeypatch.delenv("ECHO_CERTFORGE_P3_MODE")
    with pytest.raises(RuntimeError, match="required environment variable is missing"):
        runtime._required("ECHO_CERTFORGE_P3_MODE")

    monkeypatch.setenv("ECHO_CERTFORGE_P3_MODE", "unsupported")
    with pytest.raises(RuntimeError, match="unsupported P3 runtime mode"):
        runtime.build_app()


def test_anchor_runtime_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    runtime = _import_custody_runtime(tmp_path / "custody", monkeypatch)
    anchor_key = Ed25519PrivateKey.generate()
    anchor_key_path = tmp_path / "anchor-key.pem"
    anchor_key_path.write_bytes(
        anchor_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("ECHO_CERTFORGE_P3_MODE", "anchor")
    monkeypatch.setenv("ECHO_CERTFORGE_ANCHOR_ROOT", str(tmp_path / "anchor-root"))
    monkeypatch.setenv("ECHO_CERTFORGE_ANCHOR_PROVIDER_ID", "anchor.runtime.test")
    monkeypatch.setenv("ECHO_CERTFORGE_ANCHOR_PRIVATE_KEY", str(anchor_key_path))

    app = runtime.build_app()
    health = TestClient(app).get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["provider_id"] == "anchor.runtime.test"
    assert health.json()["storage_separate_from_custody_database"] is True
