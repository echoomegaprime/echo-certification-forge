from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "certforge_deploy_smoke_dispatch", ROOT / "deploy" / "smoke_dispatch.py"
)
assert SPEC is not None and SPEC.loader is not None
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


def test_production_dispatch_smoke_requires_fail_closed_unattested_verdict() -> None:
    SMOKE._require_attestation_gate_closed(  # noqa: SLF001
        {
            "release_verdict": "NOT_READY",
            "production_e2e": {"verified": False},
        }
    )


@pytest.mark.parametrize(
    "terminal",
    [
        {
            "release_verdict": "PRODUCTION_READY",
            "production_e2e": {"verified": False},
        },
        {
            "release_verdict": "NOT_READY",
            "production_e2e": {"verified": True},
        },
        {"release_verdict": "NOT_READY"},
    ],
)
def test_production_dispatch_smoke_rejects_open_or_ambiguous_gate(terminal: dict) -> None:
    with pytest.raises(RuntimeError):
        SMOKE._require_attestation_gate_closed(terminal)  # noqa: SLF001
