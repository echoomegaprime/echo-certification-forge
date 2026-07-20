"""Regression tests for the live echo-worker audit contract used by the R5 router."""
from __future__ import annotations

import ast
from pathlib import Path


def test_r5_router_uses_current_five_argument_audit_contract() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "certification_forge_r5_router.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "audit"
    ]
    assert len(calls) == 3
    assert all(len(call.args) == 5 for call in calls)
    assert all(not call.keywords for call in calls)
