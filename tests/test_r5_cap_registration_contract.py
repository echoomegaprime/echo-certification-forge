"""Static contract tests for the narrow R5 SDK capability registration."""
from __future__ import annotations

import json
import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_SQL = _ROOT / "scripts" / "register_certification_forge_r5_cap.sql"
_CAP_ID = "echo.certification_forge.r5.run_negative_controls"
_ROUTE = "/sdk/certification-forge/r5/run-negative-controls"
_REQUIRED = {
    "expected_server_build_digest",
    "expected_registry_snapshot_digest",
    "expected_registry_revision",
    "expected_signing_key_id",
    "expected_base_model_digest",
    "expected_base_model_revision",
    "expected_gs343_digest",
    "expected_r2d2_digest",
    "evidence_run_id",
}


def _text() -> str:
    return _SQL.read_text(encoding="utf-8")


def _schema() -> dict:
    text = _text()
    match = re.search(r"'(\{.*?\})'::jsonb", text, re.DOTALL)
    assert match is not None, "input_schema_json JSON literal is missing"
    return json.loads(match.group(1))


def test_registration_is_exact_router_cap_and_not_predeclared_green() -> None:
    text = _text()
    assert _CAP_ID in text
    assert f"'{_ROUTE}'" in text
    assert "'router'" in text
    assert "'POST'" in text
    assert "'json_body'" in text
    assert "'forge'" in text
    assert "'tier:1'" in text
    assert re.search(r"'tier:1',\s*2,\s*1,\s*1,", text)
    assert "'active'" in text
    assert "'unknown'" in text
    assert "health_status = 'unknown'" in text
    assert "health_status = 'green'" not in text


def test_registration_schema_is_closed_and_identity_only() -> None:
    schema = _schema()
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == _REQUIRED
    assert set(schema["properties"]) == _REQUIRED | {"dry_run"}
    assert schema["properties"]["dry_run"] == {"type": "boolean", "default": True}

    forbidden = {
        "command",
        "shell",
        "script",
        "path",
        "url",
        "host",
        "port",
        "model",
        "adapter",
        "lease_token",
        "authorization",
        "x_echo_api_key",
        "private_key",
    }
    assert forbidden.isdisjoint(schema["properties"])


def test_registration_schema_pins_digest_key_and_run_id_shapes() -> None:
    props = _schema()["properties"]
    digest_fields = {
        "expected_server_build_digest",
        "expected_registry_snapshot_digest",
        "expected_base_model_digest",
        "expected_gs343_digest",
        "expected_r2d2_digest",
    }
    for field in digest_fields:
        assert props[field] == {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    assert props["expected_signing_key_id"] == {
        "type": "string",
        "pattern": "^ed25519:[0-9a-f]{32}$",
    }
    assert props["evidence_run_id"] == {
        "type": "string",
        "pattern": "^[A-Za-z0-9._-]{1,64}$",
    }
