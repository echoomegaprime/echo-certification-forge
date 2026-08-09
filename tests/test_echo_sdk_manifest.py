from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_echo_sdk_manifest_matches_the_authoritative_contract() -> None:
    manifest = json.loads((ROOT / ".echo" / "sdk.json").read_text(encoding="utf-8"))
    contract_path = ROOT / manifest["contract"]
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    assert manifest["version"] == 1
    assert len(manifest["capabilities"]) == contract["capability_count"] == 60
    assert set(manifest["capabilities"]) == set(contract["capabilities"])
    assert len(manifest["capabilities"]) == len(set(manifest["capabilities"]))
    assert all(capability.startswith("echo.") for capability in manifest["capabilities"])
