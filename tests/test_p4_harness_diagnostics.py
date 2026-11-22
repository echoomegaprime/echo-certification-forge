from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/p4_hostile_acceptance.py"


def load_harness():
    spec = importlib.util.spec_from_file_location("p4_hostile_acceptance_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_key_generation_timeout_removes_partial_private_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_harness()
    executable = tmp_path / "cosign"
    executable.write_bytes(b"diagnostic executable")
    prefix = tmp_path / "image-signing"
    partial_private = Path(str(prefix) + ".key")

    class TimedOutProcess:
        pid = 4242
        returncode = None

        def __init__(self, command, **kwargs):
            assert kwargs["start_new_session"] is True
            partial_private.write_text("partial", encoding="utf-8")
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("cosign", timeout, output="partial stdout", stderr="partial stderr")
            return "trailing stdout", "trailing stderr"

        def poll(self):
            return self.returncode

    monkeypatch.setattr(module, "host_resource_snapshot", lambda path, cosign: {"path": str(path)})
    monkeypatch.setattr(module, "process_snapshot", lambda process_id, secret: [f"pid={process_id}"])
    monkeypatch.setattr(module, "terminate_process", lambda process: {"terminated": True})
    monkeypatch.setattr(module.subprocess, "Popen", TimedOutProcess)

    credential = "sentinel-value-must-not-appear"
    with pytest.raises(module.CosignKeyGenerationError) as captured:
        module.generate_cosign_key_pair(executable, prefix, password=credential, timeout_seconds=1)

    diagnostic = captured.value.diagnostic
    assert diagnostic["classification"] == "TIMEOUT"
    assert diagnostic["private_key_removed"] is True
    assert not partial_private.exists()
    serialized = json.dumps(diagnostic, sort_keys=True)
    assert credential not in serialized
    assert diagnostic["cosign_password_logged"] is False
    persisted = json.loads((tmp_path / "cosign-key-generation-diagnostic.json").read_text(encoding="utf-8"))
    assert persisted["classification"] == "TIMEOUT"
    assert persisted["private_key_removed"] is True


def test_signature_wrapper_removes_generated_private_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_harness()
    executable = tmp_path / "cosign"
    executable.write_bytes(b"diagnostic executable")
    prefix = tmp_path / "image-signing"
    generated_private = Path(str(prefix) + ".key")
    generated_public = Path(str(prefix) + ".pub")

    def fake_generate(cosign, output_prefix, *, password, timeout_seconds):
        generated_private.write_text("ephemeral", encoding="utf-8")
        generated_public.write_text("public", encoding="utf-8")
        return generated_private, generated_public, {
            "classification": "SUCCESS",
            "cosign_password_logged": False,
        }

    monkeypatch.setattr(module, "generate_cosign_key_pair", fake_generate)
    result = module.cosign_sign_and_verify(executable, {}, tmp_path)

    assert result["passed"] is True
    assert result["private_key_removed"] is True
    assert not generated_private.exists()
    assert generated_public.exists()
    persisted = json.loads((tmp_path / "cosign-key-generation-diagnostic.json").read_text(encoding="utf-8"))
    assert persisted["private_key_removed"] is True
    assert persisted["public_key_retained"] is True


def test_signature_wrapper_uses_cosign_v3_offline_compatibility_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_harness()
    executable = tmp_path / "cosign"
    executable.write_bytes(b"diagnostic executable")
    generated_private = tmp_path / "image-signing.key"
    generated_public = tmp_path / "image-signing.pub"
    statement = tmp_path / "runner.image-statement.json"
    statement.write_text("{}\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_generate(cosign, output_prefix, *, password, timeout_seconds):
        generated_private.write_text("ephemeral", encoding="utf-8")
        generated_public.write_text("public", encoding="utf-8")
        return generated_private, generated_public, {
            "classification": "SUCCESS",
            "cosign_password_logged": False,
        }

    def fake_run(command, **kwargs):
        commands.append(command)
        if "sign-blob" in command:
            bundle = Path(command[command.index("--bundle") + 1])
            bundle.write_text("bundle\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module, "generate_cosign_key_pair", fake_generate)
    monkeypatch.setattr(module, "run", fake_run)
    result = module.cosign_sign_and_verify(executable, {"runner": statement}, tmp_path)

    sign_command = next(command for command in commands if "sign-blob" in command)
    assert "--tlog-upload=false" in sign_command
    assert "--use-signing-config=false" in sign_command
    assert result["passed"] is True
    assert result["private_key_removed"] is True

def test_static_attack_matrix_records_traversal_rejection_as_contained(tmp_path: Path) -> None:
    module = load_harness()

    result = module.static_attack_matrix(tmp_path)

    traversal = result["archives"]["zip_traversal"]
    assert traversal["denied"] is True
    assert traversal["expected_reason"] == "archive_member_escapes_root"
    assert traversal["exception_type"] == "ValueError"
    assert "may not traverse parents" in traversal["reason"]
    assert all(item["denied"] for item in result["archives"].values())

def test_public_verifier_probe_uses_only_exact_read_only_artifacts(tmp_path: Path, monkeypatch) -> None:
    module = load_harness()
    artifacts = {}
    for name in ("attestation", "policy", "sbom"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        artifacts[name] = path
    captured = {}

    def fake_execute_container(**kwargs):
        captured.update(kwargs)
        return {
            "exit_code": 0,
            "timed_out": False,
            "oom_killed": False,
            "logs": '{"admission":{"allowed":true},"passed":true,"private_key_loaded":false,"sbom_valid":true}\n',
            "sanitized_logs": "TARGET|verified",
            "containment": {
                "read_only_root": True,
                "network_none": True,
                "all_capabilities_dropped": True,
                "no_new_privileges": True,
                "apparmor": True,
                "memory_limited": True,
                "pids_limited": True,
                "cpu_limited": True,
                "docker_socket_absent": True,
            },
        }

    monkeypatch.setattr(module, "execute_container", fake_execute_container)
    result = module.public_verifier_probe(
        image="verifier@sha256:" + "1" * 64,
        artifacts=artifacts,
        image_digest="sha256:" + "2" * 64,
        now=datetime(2026, 7, 17, tzinfo=UTC),
        ownership_token="owner.test",
    )

    assert result["passed"] is True
    assert result["private_key_mounted"] is False
    assert captured["timeout_seconds"] == 60
    assert captured["memory"] == "256m"
    assert captured["pids"] == 64
    assert captured["workspace_size"] == "8m"
    assert captured["nofile"] == 256
    assert captured["mounts"] == [
        (artifacts["attestation"].resolve(), "/input/runner.attestation.json", True),
        (artifacts["policy"].resolve(), "/input/runner.admission-policy.json", True),
        (artifacts["sbom"].resolve(), "/input/runner.spdx.json", True),
    ]
    assert all(item["read_only"] for item in result["artifacts"].values())


def test_public_verifier_probe_rejects_artifact_set_drift(tmp_path: Path) -> None:
    module = load_harness()
    with pytest.raises(RuntimeError, match="artifact set mismatch"):
        module.public_verifier_probe(
            image="verifier@sha256:" + "1" * 64,
            artifacts={"attestation": tmp_path / "missing.json"},
            image_digest="sha256:" + "2" * 64,
            now=datetime(2026, 7, 17, tzinfo=UTC),
            ownership_token="owner.test",
        )

