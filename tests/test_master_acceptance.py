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
        r'''
import hashlib, json, os, re, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

argv = sys.argv[1:]
log_path = Path(__file__).with_suffix(".invocations.jsonl")
state_path = log_path.with_suffix(".daemon.json")
def load():
    return json.loads(state_path.read_text()) if state_path.exists() else None
def absent(identifier):
    print("Error response from daemon: No such container: " + identifier, file=sys.stderr)
    sys.exit(1)
if not argv:
    sys.exit(64)
if argv[0] != "run":
    with Path(str(log_path) + ".controls.jsonl").open("a") as out:
        out.write(json.dumps(argv) + "\n")
    current = load()
    if argv[:2] == ["image", "inspect"]:
        reference = argv[-1]
        print(json.dumps("sha256:" + hashlib.sha256(("synthetic-config:" + reference).encode()).hexdigest()))
    elif argv[0] == "inspect":
        identifier = argv[-1]
        if current is None or identifier not in (current["Id"], current["Name"].lstrip("/")):
            absent(identifier)
        print(json.dumps(current))
    elif argv[:2] == ["rm", "--force"]:
        if current is None or argv[-1] != current["Id"]:
            absent(argv[-1])
        state_path.unlink()
    elif argv[0] == "info":
        print(json.dumps("29.4.1"))
    elif argv[0] == "ps":
        if current is not None and any(current["Name"] in value for value in argv):
            print(current["Id"])
    else:
        sys.exit(64)
    sys.exit(0)

workdir = None
image = None
cmd = []
labels = {}
for index, arg in enumerate(argv):
    if arg == "-v" and argv[index + 1].endswith(":/work:ro"):
        workdir = argv[index + 1][: -len(":/work:ro")]
    if arg == "--label":
        key, value = argv[index + 1].split("=", 1)
        labels[key] = value
    if arg == "-w":
        cursor = index + 2
        while argv[cursor] == "--env":
            cursor += 2
        image = argv[cursor]
        cmd = argv[cursor + 1:]
if workdir is None or image is None or not cmd or "--name" not in argv or "--cidfile" not in argv:
    sys.exit(64)
name = argv[argv.index("--name") + 1]
cid = hashlib.sha256(name.encode()).hexdigest()
current = {"Id": cid, "Name": "/" + name,
           "Image": image if re.fullmatch(r"sha256:[0-9a-f]{64}", image) else "sha256:" + hashlib.sha256(("synthetic-config:" + image).encode()).hexdigest(),
           "Created": datetime.now(timezone.utc).isoformat(),
           "Config": {"Image": image, "Labels": labels}}
state_path.write_text(json.dumps(current))
Path(argv[argv.index("--cidfile") + 1]).write_text(cid + "\n")
with log_path.open("a", encoding="utf-8") as log:
    log.write(json.dumps({"argv": argv, "image": image, "workdir": workdir}) + "\n")
executable = sys.executable if cmd[0] in ("python", "python3") else cmd[0]
# Trusted synthetic image fixture only. A retained fake daemon record requires
# the real sandbox ownership protocol to close it after this client exits.
sys.exit(subprocess.run([executable, *cmd[1:]], cwd=workdir).returncode)
''',
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
    import json
    invocations = [json.loads(line) for line in stub.with_suffix(".invocations.jsonl").read_text().splitlines()]
    controls = [json.loads(line) for line in Path(str(stub.with_suffix(".invocations.jsonl")) + ".controls.jsonl").read_text().splitlines()]
    removals = [item[-1] for item in controls if item[:2] == ["rm", "--force"]]
    expected_cids = {__import__("hashlib").sha256(item["argv"][item["argv"].index("--name") + 1].encode()).hexdigest() for item in invocations}
    assert invocations and set(removals) == expected_cids
    assert len(removals) == len(invocations)
    assert not stub.with_suffix(".invocations.daemon.json").exists()
