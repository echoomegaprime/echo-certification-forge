"""The P4 worker health probe keeps every state path on the writable workspace.

The hardened probe runs the worker image with a read-only root. Since P6 the worker app opens its
deployment ledger at import time, and its default path lives on the image root, so the probe died with
"Read-only file system: '/opt/var'" before /healthz answered (P4 INFRA_FAILED, ops-20260924).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "p4_hostile_acceptance.py"
STATE_PATHS = (
    "ECHO_CERTFORGE_DB",
    "ECHO_CERTFORGE_EVIDENCE_ROOT",
    "ECHO_CERTFORGE_TRUSTED_KEYS",
    "ECHO_CERTFORGE_DEPLOYMENT_LEDGER",
)


class _Captured(Exception):
    pass


def _load_harness():
    spec = importlib.util.spec_from_file_location("p4_hostile_acceptance_worker_env_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_worker_health_probe_keeps_state_on_the_writable_workspace(monkeypatch, tmp_path: Path) -> None:
    harness = _load_harness()
    captured: dict = {}

    def fake_create_container(**kwargs):
        captured.update(kwargs)
        raise _Captured()

    monkeypatch.setattr(harness, "create_container", fake_create_container)
    with pytest.raises(_Captured):
        harness.service_health_probe("image@sha256:" + "0" * 64, harness.ImageRole.WORKER, "token-12345678", tmp_path)
    environment = captured["environment"]
    assert environment["ECHO_CERTFORGE_DEPLOYMENT_LEDGER"] == "/workspace/state/deployments.sqlite3"
    for name in STATE_PATHS:
        assert environment[name].startswith("/workspace/state/"), name
