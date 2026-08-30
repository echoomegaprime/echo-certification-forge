#!/usr/bin/env python3
"""Generate the complete Certification Forge SDK schema contract and registry SQL."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from echo_certification_forge.evidence import EvidenceStore  # noqa: E402
from echo_certification_forge.policy import RuleManifest  # noqa: E402
from echo_certification_forge.service import ServiceContext, create_app  # noqa: E402
from echo_certification_forge.signing import TrustedPublicKeyRegistry  # noqa: E402

SURFACE_PATH = ROOT / "contracts" / "certforge-capability-surface.v2.json"
CONTRACT_PATH = ROOT / "contracts" / "certforge-sdk-capabilities.v1.json"
SQL_PATH = ROOT / "scripts" / "register_certforge_sdk_schemas.sql"
COMMAND_SCHEMA = {"type": "string", "minLength": 1, "maxLength": 64}


def _object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": False,
    }


def _r5_input() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    properties = {
        "command": COMMAND_SCHEMA,
        "target_family": {"type": "string", "enum": ["gs343", "r2d2"]},
        "expected_server_build_digest": sha,
        "expected_registry_snapshot_digest": sha,
        "expected_registry_revision": {"type": "string", "minLength": 6, "maxLength": 128},
        "expected_signing_key_id": {"type": "string", "minLength": 8, "maxLength": 128},
        "expected_base_model_digest": sha,
        "expected_base_model_revision": {"type": "string", "minLength": 6, "maxLength": 128},
        "expected_gs343_digest": sha,
        "expected_r2d2_digest": sha,
        "evidence_run_id": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,64}$"},
        "evidence_run_nonce": {"type": "string", "minLength": 16, "maxLength": 128},
        "dry_run": {"type": "boolean"},
    }
    return _object_schema(
        properties,
        [name for name in properties if name != "dry_run"],
    )


def _manual_capabilities() -> dict[str, dict[str, Any]]:
    r5_result = _object_schema(
        {
            "schema": {"type": "string"},
            "mode": {"type": "string", "enum": ["preflight", "full"]},
            "evidence_run_id": {"type": "string"},
            "run_outcome": {"type": "string"},
            "release_verdict": {"type": "string", "enum": ["NOT_READY"]},
            "r5_gate": {"type": "string", "enum": ["PASS", "BLOCK"]},
            "deployment_authorized": {"type": "boolean"},
            "completion_marker": {"type": ["string", "null"]},
            "operator_report": {"type": "object", "additionalProperties": True},
            "forge_verification": {"type": "object", "additionalProperties": True},
            "operator_exit_code": {"type": "integer"},
            "stderr_tail": {"type": "string"},
        },
        [
            "schema", "mode", "evidence_run_id", "run_outcome", "release_verdict",
            "r5_gate", "deployment_authorized", "completion_marker", "operator_report",
            "forge_verification", "operator_exit_code",
        ],
    )
    return {
        "echo.certforge.run": {
            "operation": "POST /sdk/certification-forge/run",
            "input_schema": _object_schema(
                {
                    "command": COMMAND_SCHEMA,
                    "run_id": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"},
                    "tenant": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"},
                },
                ["command", "run_id", "tenant"],
            ),
            "output_schema": _object_schema(
                {
                    "run_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["PENDING", "CLAIMED"]},
                    "tenant": {"type": "string"},
                    "sandboxed": {"type": "boolean"},
                    "poll_capability": {"type": "string", "enum": ["echo.certforge.status"]},
                },
                ["run_id", "status", "tenant", "sandboxed", "poll_capability"],
            ),
        },
        "echo.certforge.r5.submit_async": {
            "operation": "POST /sdk/certification-forge/r5/submit-async",
            "input_schema": _r5_input(),
            "output_schema": _object_schema(
                {
                    "run_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["RESERVED", "RUNNING"]},
                    "mode": {"type": "string", "enum": ["preflight", "full"]},
                    "poll_capability": {"type": "string", "enum": ["echo.certforge.r5.status"]},
                    "idempotent": {"type": "boolean"},
                },
                ["run_id", "status", "mode"],
            ),
        },
        "echo.certforge.r5.status": {
            "operation": "GET /sdk/certification-forge/r5/status/{run_id}",
            "input_schema": _object_schema(
                {
                    "command": COMMAND_SCHEMA,
                    "run_id": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,64}$"},
                },
                ["command", "run_id"],
            ),
            "output_schema": _object_schema(
                {
                    "run_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["RUNNING", "COMPLETE", "FAILED"]},
                    "result": {"anyOf": [r5_result, {"type": "null"}]},
                    "note": {"type": "string"},
                },
                ["run_id", "status"],
            ),
        },
        "echo.certification_forge.r5.run_negative_controls": {
            "operation": "POST /sdk/certification-forge/r5/run-negative-controls",
            "input_schema": _r5_input(),
            "output_schema": r5_result,
        },
    }


def _resolve(schema: Any, components: dict[str, Any]) -> Any:
    if isinstance(schema, list):
        return [_resolve(value, components) for value in schema]
    if not isinstance(schema, dict):
        return schema
    if "$ref" in schema:
        prefix = "#/components/schemas/"
        reference = schema["$ref"]
        if not reference.startswith(prefix):
            raise ValueError(f"unsupported OpenAPI reference: {reference}")
        return _resolve(components[reference.removeprefix(prefix)], components)
    return {
        key: _resolve(value, components)
        for key, value in schema.items()
        if key not in {"title", "description", "examples", "example", "default"}
    }


def _operation_input(operation: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    request_body = operation.get("requestBody")
    if request_body:
        schema = _resolve(
            request_body["content"]["application/json"]["schema"], components
        )
        if schema.get("type") != "object":
            raise ValueError("Certification Forge request bodies must be JSON objects")
        properties.update(schema.get("properties", {}))
        required.extend(schema.get("required", []))
    for parameter in operation.get("parameters", []):
        if parameter.get("in") not in {"path", "query"}:
            continue
        name = parameter["name"]
        properties[name] = _resolve(parameter.get("schema", {}), components)
        if parameter.get("required"):
            required.append(name)
    properties["command"] = COMMAND_SCHEMA
    required.append("command")
    return _object_schema(properties, sorted(set(required)))


def _operation_output(operation: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
    responses = operation.get("responses", {})
    response = next(
        (responses[code] for code in ("200", "201", "202", "204") if code in responses),
        None,
    )
    if response is None:
        raise ValueError("operation has no successful response")
    schema = response.get("content", {}).get("application/json", {}).get("schema")
    return {"type": "null"} if schema is None else _resolve(schema, components)


def build_contract() -> dict[str, Any]:
    surface = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="certforge-sdk-contract-") as temporary:
        temp = Path(temporary)
        app = create_app(
            ServiceContext(
                EvidenceStore(temp / "certforge.sqlite3", temp / "evidence"),
                RuleManifest.load(ROOT / "policies" / "mandatory-rules.v1.json"),
                TrustedPublicKeyRegistry.empty(),
            )
        )
        openapi = app.openapi()
    components = openapi.get("components", {}).get("schemas", {})
    capabilities: dict[str, dict[str, Any]] = {}
    for operation_name, capability in sorted(surface["capabilities"].items()):
        method, path = operation_name.split(" ", 1)
        operation = openapi["paths"][path][method.lower()]
        capabilities[capability] = {
            "operation": operation_name,
            "input_schema": _operation_input(operation, components),
            "output_schema": _operation_output(operation, components),
        }
    # Keep the least-privileged publishing capability used by the Certification Forge GitHub
    # App as a first-class compatibility alias. It targets the same fail-closed route as the
    # tier-2 administrative capability, but the service still re-evaluates the exact signed
    # PRODUCTION_READY verdict before publishing public verification material.
    publish = capabilities["echo.certforge.admin.publish"]
    capabilities["echo.certforge.publish"] = {
        "operation": publish["operation"],
        "input_schema": publish["input_schema"],
        "output_schema": publish["output_schema"],
    }
    capabilities.update(_manual_capabilities())
    return {
        "schema_version": "1.0.0",
        "policy": (
            "Every Certification Forge SDK action has a command-bearing strict input "
            "schema and an output schema derived from its production route contract."
        ),
        "capability_count": len(capabilities),
        "capabilities": dict(sorted(capabilities.items())),
    }


def render_json(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def _sql_literal(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "'" + encoded.replace("'", "''") + "'::jsonb"


def render_sql(contract: dict[str, Any]) -> str:
    rows = []
    for capability, item in contract["capabilities"].items():
        rows.append(
            f"  ('{capability}', {_sql_literal(item['input_schema'])}, "
            f"{_sql_literal(item['output_schema'])})"
        )
    values = ",\n".join(rows)
    count = contract["capability_count"]
    return f"""-- GENERATED by scripts/generate_certforge_sdk_contract.py. Do not hand-edit.
-- Apply with psql --single-transaction / -1 together with the capability registrations.
CREATE TEMP TABLE certforge_sdk_contract (
  id text PRIMARY KEY,
  input_schema_json jsonb NOT NULL,
  output_schema_json jsonb NOT NULL
) ON COMMIT DROP;
INSERT INTO certforge_sdk_contract(id, input_schema_json, output_schema_json) VALUES
{values};

DO $$
DECLARE live_count integer;
BEGIN
  SELECT count(*) INTO live_count
    FROM arcanum_sdk.sdk_capabilities
   WHERE id LIKE 'echo.certforge.%'
      OR id = 'echo.certification_forge.r5.run_negative_controls';
  IF live_count <> {count} THEN
    RAISE EXCEPTION 'Certification Forge SDK surface drift: live %, contract {count}', live_count;
  END IF;
  IF EXISTS (
    SELECT 1 FROM certforge_sdk_contract c
    LEFT JOIN arcanum_sdk.sdk_capabilities s USING (id)
    WHERE s.id IS NULL
  ) THEN
    RAISE EXCEPTION 'Certification Forge SDK contract contains an unregistered capability';
  END IF;
END $$;

UPDATE arcanum_sdk.sdk_capabilities s
   SET input_schema_json = c.input_schema_json,
       output_schema_json = c.output_schema_json,
       updated_at = now()
  FROM certforge_sdk_contract c
 WHERE s.id = c.id;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM certforge_sdk_contract c
    JOIN arcanum_sdk.sdk_capabilities s USING (id)
    WHERE NOT (s.input_schema_json->'required' ? 'command')
       OR s.output_schema_json IS NULL
       OR s.output_schema_json = '{{}}'::jsonb
  ) THEN
    RAISE EXCEPTION 'Certification Forge SDK schema persistence verification failed';
  END IF;
END $$;
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    contract = build_contract()
    rendered = {CONTRACT_PATH: render_json(contract), SQL_PATH: render_sql(contract)}
    if args.write:
        for path, content in rendered.items():
            path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {contract['capability_count']} capability contracts")
        return 0
    stale = [path for path, content in rendered.items() if not path.exists() or path.read_text(encoding="utf-8") != content]
    if stale:
        print("stale generated SDK contract: " + ", ".join(str(path.relative_to(ROOT)) for path in stale))
        return 1
    print(f"SDK contract current: {contract['capability_count']} capabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
