from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "smoke_desktop_admin_caps.py"
SPEC = importlib.util.spec_from_file_location("smoke_desktop_admin_caps_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_sdk_params_adds_command_without_mutating_input() -> None:
    original = {"limit": 3}

    result = MODULE.sdk_params("echo.certforge.admin.audit", original)

    assert result == {"command": "audit", "limit": 3}
    assert original == {"limit": 3}


def test_sdk_params_preserves_explicit_command_override() -> None:
    result = MODULE.sdk_params(
        "echo.certforge.admin.legal_hold_create",
        {"command": "legal_hold_create", "hold_id": "hold-smoke"},
    )

    assert result["command"] == "legal_hold_create"


def test_new_hold_actions_uses_event_identity_when_audit_window_is_full() -> None:
    before = [{"event_id": event_id} for event_id in range(1, 101)]
    after = [
        {
            "event_id": 102,
            "action": "legal_hold.release",
            "resource_type": "legal_hold",
            "resource_id": "hold-smoke",
        },
        {
            "event_id": 101,
            "action": "legal_hold.create",
            "resource_type": "legal_hold",
            "resource_id": "hold-smoke",
        },
        *[{"event_id": event_id} for event_id in range(3, 101)],
    ]

    assert len(before) == len(after) == 100
    assert MODULE.new_hold_actions(before, after, "hold-smoke") == {
        "legal_hold.create",
        "legal_hold.release",
    }
