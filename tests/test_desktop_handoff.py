from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_desktop_handoff_is_complete_and_fail_closed() -> None:
    handoff = json.loads((ROOT / "contracts" / "echo-desktop-handoff.v1.json").read_text())
    aliases = handoff["stable_aliases"]
    operations = handoff["operations"]

    assert handoff["schema_version"] == "1.0.0"
    assert len(aliases) == 10
    assert set(aliases.values()) <= set(operations)
    assert handoff["consumer"] == {
        "application": "Echo Desktop",
        "minimum_phase": "P8C",
        "boundary": "operator_and_public_verifier_only",
        "executes_target_code": False,
        "receives_runner_credentials": False,
        "receives_private_signing_keys": False,
        "may_issue_ready_verdict": False,
    }
    assert all(value == "BLOCK" for key, value in handoff["error_contract"].items() if key in {
        "unknown_identity", "invalid_signature", "invalid_evidence",
        "expired_revoked_or_superseded", "digest_mismatch",
    })
    assert operations["echo.certforge.submit"]["mutation"] is True
    assert operations["echo.certforge.cancel"]["mutation"] is True
    assert operations["echo.certforge.deploy_gate"]["tier"] == 2


def test_desktop_handoff_binds_independent_bootstrap_artifact() -> None:
    handoff = json.loads((ROOT / "contracts" / "echo-desktop-handoff.v1.json").read_text())
    bootstrap_path = ROOT / handoff["independent_bootstrap"]["artifact"]
    raw = bootstrap_path.read_bytes()
    bootstrap = json.loads(raw)

    assert hashlib.sha256(raw).hexdigest() == handoff["independent_bootstrap"]["sha256"]
    assert bootstrap["payload"]["bootstrap_verdict"] == "CERTIFIED"
    assert bootstrap["payload"]["signing_key_id"] != bootstrap["payload"]["run_signer_key_id"]
    assert handoff["independent_bootstrap"]["bootstrap_key_is_distinct_from_run_signer"] is True


def test_registration_sql_contains_every_handoff_operation() -> None:
    handoff = json.loads((ROOT / "contracts" / "echo-desktop-handoff.v1.json").read_text())
    registration = (ROOT / "scripts" / "register_certforge_caps.sql").read_text()

    for capability_id in handoff["operations"]:
        assert capability_id in registration
    assert "private_signing" not in registration.lower()
