from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path

from echo_certification_forge.master_acceptance import (
    MasterAcceptanceInspector,
    MasterAcceptanceRunner,
)
from echo_certification_forge.sandbox import DockerSandbox
from echo_certification_forge.signing import Ed25519VerdictSigner


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "acceptance" / "master-imperfect-app"
VULNERABILITIES = ROOT / "policies" / "master-vulnerable-dependencies.v1.json"
MANIFEST = ROOT / "policies" / "mandatory-rules.v1.json"


def _master_script_module():
    script = ROOT / "scripts" / "master_acceptance.py"
    spec = importlib.util.spec_from_file_location("certforge_master_acceptance_cli", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_master_fixture_discovery_and_defects_are_complete() -> None:
    result = MasterAcceptanceInspector(VULNERABILITIES).inspect(FIXTURE)
    assert set(result.components) == {
        "administrator_role",
        "authentication",
        "cli_utility",
        "docker_compose",
        "file_upload",
        "mcp_endpoint",
        "postgresql",
        "python_api",
        "redis",
        "rest_schema",
        "typescript_web_frontend",
    }
    assert {item.code for item in result.defects} == {
        "accessibility_defect",
        "authorization_defect",
        "environment_trap",
        "harness_trap",
        "missing_tests",
        "packaging_defect",
        "vulnerable_dependency",
    }
    by_code = {item.code: item for item in result.defects}
    assert by_code["environment_trap"].classification == "CERTIFICATION_DEFECT"
    assert by_code["authorization_defect"].blocks_release is True
    assert by_code["vulnerable_dependency"].blocks_release is True


def test_final_sdk_gate_accepts_checked_exact_60_capability_map() -> None:
    contract = json.loads(
        (ROOT / "contracts" / "certforge-sdk-capabilities.v1.json").read_text(
            encoding="utf-8"
        )
    )

    _master_script_module()._sdk(contract)


def test_master_acceptance_full_chain_with_docker_protocol_stub(tmp_path: Path) -> None:
    stub = tmp_path / "docker_stub.py"
    stub.write_text(
        """from __future__ import annotations
import subprocess, sys
from pathlib import Path
args=sys.argv[1:]
volume=args[args.index('-v')+1]
host=Path(volume.split(':/work:ro',1)[0])
script=host / args[-1]
raise SystemExit(subprocess.call([sys.executable, str(script)], cwd=host))
""",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    runner = MasterAcceptanceRunner(
        fixture_root=FIXTURE,
        vulnerability_policy=VULNERABILITIES,
        rule_manifest=MANIFEST,
        output_directory=tmp_path / "output",
        signer=Ed25519VerdictSigner.generate(),
        sandbox=DockerSandbox(docker=(sys.executable, str(stub))),
        source_commit="a" * 40,
    )
    result = runner.run("master-unit")
    assert result.requirements_passed is True
    assert result.target_release_verdict == "NOT_READY"
    assert result.signed_verdict_verified is True
    assert result.evidence_chain_verified is True
    assert Path(result.artifact_path).is_file()
