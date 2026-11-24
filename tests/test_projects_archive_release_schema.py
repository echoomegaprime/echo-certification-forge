"""The archive capability keeps its SDK shape through a release (fix-cap 25412 / 39521).

A release applies the capability registrations first and the generated schema
SQL last, so the generated schema is what the registry ends up holding. These
checks replay that order from the files a release uses and test the schema that
survives.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
CAPABILITY = "echo.certforge.projects.archive"
CONTRACT = ROOT / "contracts" / "certforge-sdk-capabilities.v1.json"
CAPS_SQL = ROOT / "scripts" / "register_certforge_caps.sql"
SCHEMAS_SQL = ROOT / "scripts" / "register_certforge_sdk_schemas.sql"
DEPLOY = ROOT / "deploy" / "deploy_forge.sh"

Schemas = tuple[dict[str, Any], dict[str, Any]]


def _valid(schema: dict[str, Any], value: Any) -> bool:
    """Check a value against the JSON Schema keywords these two schemas use."""
    if "anyOf" in schema:
        return any(_valid(option, value) for option in schema["anyOf"])
    kind = schema.get("type")
    if kind == "null":
        return value is None
    if kind == "string":
        if not isinstance(value, str):
            return False
        if len(value) < schema.get("minLength", 0):
            return False
        if len(value) > schema.get("maxLength", len(value)):
            return False
        pattern = schema.get("pattern")
        return pattern is None or re.search(pattern, value) is not None
    if kind == "object":
        if not isinstance(value, dict):
            return False
        if any(name not in value for name in schema.get("required", [])):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties", True) is False and set(value) - set(properties):
            return False
        return all(_valid(properties[name], item) for name, item in value.items() if name in properties)
    raise AssertionError(f"schema keyword not covered by this check: {schema}")


def _jsonb(literal: str) -> dict[str, Any]:
    return json.loads(literal.replace("''", "'"))


def _caps_sql_schemas() -> Schemas:
    """Schemas the registration script leaves on the archive row (its last UPDATE)."""
    found: Schemas | None = None
    for statement in CAPS_SQL.read_text(encoding="utf-8").split(";\n"):
        if "UPDATE arcanum_sdk.sdk_capabilities" not in statement:
            continue
        if f"WHERE id = '{CAPABILITY}'" not in statement:
            continue
        match = re.search(
            r"input_schema_json = '(.*?)'::jsonb,\s*output_schema_json = '(.*?)'::jsonb",
            statement,
            re.DOTALL,
        )
        if match:
            found = (_jsonb(match.group(1)), _jsonb(match.group(2)))
    assert found is not None, "registration script no longer sets the archive schemas"
    return found


def _schemas_sql_schemas() -> Schemas:
    """Schemas the generated schema script writes over the archive row."""
    match = re.search(
        r"^\s*\('" + re.escape(CAPABILITY) + r"', '(.*)'::jsonb, '(.*)'::jsonb\),?$",
        SCHEMAS_SQL.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match is not None, "generated schema script has no archive row"
    return _jsonb(match.group(1)), _jsonb(match.group(2))


def _persisted_after_release() -> Schemas:
    """Replay the release order and return what the registry row ends up with."""
    deploy = DEPLOY.read_text(encoding="utf-8")
    caps_at = deploy.index("scripts/register_certforge_caps.sql")
    schemas_at = deploy.index("scripts/register_certforge_sdk_schemas.sql")
    assert caps_at < schemas_at, "release no longer applies the generated schemas last"
    row = _caps_sql_schemas()
    row = _schemas_sql_schemas()
    return row


VALID_INPUTS = [
    {"command": "archive", "project_id": "proj-1"},
    {"command": "archive", "project_id": "Org.team:proj_9"},
    {"command": "archive", "project_id": "a" * 128},
    {
        "command": "archive",
        "project_id": "proj-1",
        "options": {"command": "archive", "project_id": "proj-1"},
    },
    {"command": "archive", "project_id": "proj-1", "options": {"project_id": "proj-1", "trace": "abc"}},
]

INVALID_INPUTS = [
    {"command": "archive"},
    {"project_id": "proj-1"},
    {"command": "archive", "project_id": ""},
    {"command": "archive", "project_id": "-leading-dash"},
    {"command": "archive", "project_id": "has space"},
    {"command": "archive", "project_id": "a/b"},
    {"command": "archive", "project_id": "../etc"},
    {"command": "archive", "project_id": "a" * 129},
    {"command": "archive", "project_id": 7},
    {"command": "", "project_id": "proj-1"},
    {"command": "archive", "project_id": "proj-1", "unexpected": True},
    {"command": "archive", "project_id": "proj-1", "options": "not-an-object"},
    {"command": "archive", "project_id": "proj-1", "options": {"project_id": "a/b"}},
]


def test_release_leaves_the_generated_archive_schema_in_the_registry() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))["capabilities"][CAPABILITY]
    persisted_input, persisted_output = _persisted_after_release()
    assert persisted_input == contract["input_schema"]
    assert persisted_output == contract["output_schema"]


@pytest.mark.parametrize("payload", VALID_INPUTS)
def test_persisted_archive_input_accepts_flat_and_projected_calls(payload: dict[str, Any]) -> None:
    persisted_input, _ = _persisted_after_release()
    assert _valid(persisted_input, payload)


@pytest.mark.parametrize("payload", INVALID_INPUTS)
def test_persisted_archive_input_rejects_bad_calls(payload: dict[str, Any]) -> None:
    persisted_input, _ = _persisted_after_release()
    assert not _valid(persisted_input, payload)


def test_persisted_archive_output_allows_no_body_or_an_object() -> None:
    _, persisted_output = _persisted_after_release()
    assert _valid(persisted_output, None)
    assert _valid(persisted_output, {})
    assert _valid(persisted_output, {"archived": True, "project_id": "proj-1"})
    assert not _valid(persisted_output, "archived")
    assert not _valid(persisted_output, [])
    assert not _valid(persisted_output, 1)


def test_registration_and_generated_schema_agree_on_every_case() -> None:
    """The row is valid at both points of the release, not only at the end."""
    registered_input, registered_output = _caps_sql_schemas()
    generated_input, generated_output = _schemas_sql_schemas()
    for payload in VALID_INPUTS:
        assert _valid(registered_input, payload) and _valid(generated_input, payload), payload
    for payload in INVALID_INPUTS:
        assert not _valid(registered_input, payload) and not _valid(generated_input, payload), payload
    for body in (None, {}, {"archived": True}):
        assert _valid(registered_output, body) and _valid(generated_output, body), body
