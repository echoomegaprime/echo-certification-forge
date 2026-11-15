from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
CONTRACT = ROOT / "contracts" / "certforge-sdk-capabilities.v1.json"
REGISTRATION_FILES = (
    ROOT / "scripts" / "register_certforge_caps.sql",
    ROOT / "scripts" / "register_certforge_run_cap.sql",
    ROOT / "scripts" / "register_certforge_r5_async_caps.sql",
    ROOT / "scripts" / "register_certification_forge_r5_cap.sql",
)


def test_generated_sdk_contract_is_current() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_certforge_sdk_contract.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_certforge_capability_has_command_and_output_schema() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    capabilities = contract["capabilities"]
    assert contract["capability_count"] == 61 == len(capabilities)
    for capability, item in capabilities.items():
        input_schema = item["input_schema"]
        output_schema = item["output_schema"]
        assert input_schema["type"] == "object", capability
        assert input_schema["additionalProperties"] is False, capability
        assert "command" in input_schema["required"], capability
        assert input_schema["properties"]["command"] == {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
        }
        assert isinstance(output_schema, dict) and output_schema, capability
        assert "type" in output_schema or "anyOf" in output_schema, capability


def test_github_app_publish_alias_is_exactly_schema_compatible() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    capabilities = contract["capabilities"]
    least_privileged = capabilities["echo.certforge.publish"]
    administrative = capabilities["echo.certforge.admin.publish"]
    assert least_privileged == administrative


def test_registered_capability_set_equals_sdk_contract() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    registered: set[str] = set()
    for path in REGISTRATION_FILES:
        registered.update(
            re.findall(r"'(echo\.(?:certforge|certification_forge)\.[^']+)'", path.read_text(encoding="utf-8"))
        )
    assert registered == set(contract["capabilities"])


def test_registry_sync_is_transactional_and_drift_blocking() -> None:
    sql = (ROOT / "scripts" / "register_certforge_sdk_schemas.sql").read_text(
        encoding="utf-8"
    )
    assert sql.startswith("-- GENERATED")
    assert "psql --single-transaction" in sql
    deploy = (ROOT / "deploy" / "deploy_forge.sh").read_text(encoding="utf-8")
    assert "psql -1 -v ON_ERROR_STOP=1" in deploy
    assert "output_schema_json = c.output_schema_json" in sql
    assert "Certification Forge SDK surface drift" in sql
    assert "? 'command'" in sql
