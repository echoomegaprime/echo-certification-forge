"""Runtime identity must describe executable inputs, not fixed labels."""
import dataclasses
import json
import shutil
from pathlib import Path

import pytest

from echo_certification_forge.canonical import sha256_bytes
from echo_certification_forge.policy import RuleManifest
from echo_certification_forge.run_worker import _worker_environment
from echo_certification_forge.sandbox import DockerSandbox

ROOT = Path(__file__).resolve().parents[1]


def test_environment_binds_selected_mandatory_manifest():
    manifest = RuleManifest.load(ROOT / "policies/mandatory-rules.v2.json")
    assert _worker_environment().policy_sha256 == manifest.digest


def test_environment_does_not_publish_static_harness_label_as_measurement():
    assert _worker_environment().harness_sha256 != sha256_bytes(
        b"certforge-worker-env:harness"
    )


def test_actual_pinned_image_and_journey_change_environment():
    first = DockerSandbox(image="python@sha256:" + "1" * 64)
    second = dataclasses.replace(first, image="python@sha256:" + "2" * 64)
    base = _worker_environment(sandbox=first, journey=["python", "journey.py"])
    assert base.runner_image_sha256 == "1" * 64
    assert base.identity_digest != _worker_environment(
        sandbox=second, journey=["python", "journey.py"]
    ).identity_digest
    assert base.test_plan_sha256 != _worker_environment(
        sandbox=first, journey=["python", "other.py"]
    ).test_plan_sha256


def test_local_content_image_id_is_measured_without_fabricating_repository_digest():
    from echo_certification_forge.runtime_identity import _sandbox_inputs

    sandbox = DockerSandbox(image="sha256:" + "a" * 64)
    environment = _worker_environment(sandbox=sandbox)
    assert environment.runner_image_sha256 == "a" * 64
    assert _sandbox_inputs(sandbox)["image_identifier_kind"] == "docker_content_id"
    repository = dataclasses.replace(sandbox, image="python@sha256:" + "a" * 64)
    assert _sandbox_inputs(repository)["image_identifier_kind"] == "repository_digest"
    assert environment.identity_digest != _worker_environment(sandbox=repository).identity_digest


def test_missing_runtime_dependency_metadata_fails_closed(monkeypatch, store, manifest):
    import importlib.metadata
    from echo_certification_forge import run_worker
    from echo_certification_forge.signing import Ed25519VerdictSigner

    def missing(name):
        raise importlib.metadata.PackageNotFoundError("do-not-disclose-metadata-detail")

    monkeypatch.setattr(importlib.metadata, "version", missing)
    with pytest.raises(ValueError, match="runtime_metadata_unavailable"):
        _worker_environment()
    result = run_worker.run(
        "runtime-missing", "runtime-test", {"type": "local", "path": "never-acquired"},
        store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
    )
    assert result == {"run_id": "runtime-missing", "error": "runtime_identity_unavailable"}


@pytest.mark.parametrize("field,value", [("memory", "768m"), ("timeout_s", 120), ("pids_limit", 64)])
def test_effective_sandbox_limits_change_environment(field, value):
    sandbox = DockerSandbox()
    assert _worker_environment(sandbox=sandbox).identity_digest != _worker_environment(
        sandbox=dataclasses.replace(sandbox, **{field: value})
    ).identity_digest


def test_harness_bytes_and_policy_changes_invalidate_identity(tmp_path):
    from echo_certification_forge.runtime_identity import measured_environment

    shutil.copytree(ROOT / "src/echo_certification_forge", tmp_path / "src/echo_certification_forge")
    shutil.copy2(ROOT / "pyproject.toml", tmp_path)
    shutil.copytree(ROOT / "images", tmp_path / "images")
    manifest = RuleManifest.load(ROOT / "policies/mandatory-rules.v2.json")
    before = measured_environment(manifest=manifest, source_root=tmp_path)
    harness = tmp_path / "src/echo_certification_forge/executor.py"
    harness.write_bytes(harness.read_bytes() + b"\n# changed executable harness\n")
    after = measured_environment(manifest=manifest, source_root=tmp_path)
    assert before.harness_sha256 != after.harness_sha256
    assert before.identity_digest != after.identity_digest
    assert after.identity_digest != measured_environment(
        manifest=dataclasses.replace(manifest, digest="e" * 64), source_root=tmp_path
    ).identity_digest


def test_profile_is_shared_public_configuration_and_checks_actual_execution(tmp_path, monkeypatch):
    from echo_certification_forge.runtime_identity import load_runtime_profile

    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps({
        "schema_version": "certforge.runtime.v1",
        "journey": ["python", "journey.py"],
        "sandbox": {"image": "python@sha256:" + "3" * 64, "memory": "768m"},
    }))
    monkeypatch.setenv("ECHO_CERTFORGE_RUNTIME_PROFILE", str(profile_path))
    profile = load_runtime_profile()
    assert profile.sandbox.memory == "768m"
    assert profile.journey == ("python", "journey.py")
    profile.check_execution(profile.sandbox, list(profile.journey))
    with pytest.raises(ValueError, match="runtime_profile_mismatch"):
        profile.check_execution(profile.sandbox, ["python", "different.py"])
    with pytest.raises(ValueError, match="runtime_profile_mismatch"):
        profile.check_execution(dataclasses.replace(profile.sandbox, memory="512m"), list(profile.journey))


@pytest.mark.parametrize("profile", [
    {"schema_version": "certforge.runtime.v1", "secret": "never-disclose-this"},
    {"schema_version": "certforge.runtime.v1", "sandbox": {"image": "python:latest"}},
    {"schema_version": "certforge.runtime.v1", "sandbox": {"extra_env": {"TOKEN": "never-disclose-this"}}},
])
def test_profile_rejects_unknown_secret_fields_and_mutable_images(tmp_path, profile):
    from echo_certification_forge.runtime_identity import load_runtime_profile

    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(ValueError) as caught:
        load_runtime_profile(path)
    assert "never-disclose-this" not in str(caught.value)


def test_arbitrary_environment_is_not_read_or_hashed(monkeypatch):
    before = _worker_environment()
    monkeypatch.setenv("SECRET_RUNTIME_TOKEN", "first-private-value")
    monkeypatch.setenv("ECHO_CERTFORGE_API_KEY_PEPPER", "second-private-value")
    assert before == _worker_environment()
    with pytest.raises(ValueError, match="runtime_extra_env_not_supported"):
        _worker_environment(sandbox=DockerSandbox(extra_env={"SECRET": "private"}))


def test_service_dispatcher_and_worker_share_the_effective_profile(tmp_path, monkeypatch):
    """Exercise real launcher/config/status/worker paths; stub only adapter trust and queue poll."""
    import importlib
    from fastapi.testclient import TestClient
    from echo_certification_forge import dispatch_worker, run_worker
    from echo_certification_forge.service import ServiceContext, create_app
    from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

    profile_path = tmp_path / "runtime.json"
    profile_path.write_text(json.dumps({
        "schema_version": "certforge.runtime.v1", "journey": None,
        "sandbox": {"image": "python@sha256:" + "4" * 64, "memory": "768m"},
    }))
    monkeypatch.setenv("ECHO_CERTFORGE_RUNTIME_PROFILE", str(profile_path))
    monkeypatch.setenv("ECHO_CERTFORGE_DB", str(tmp_path / "test.sqlite"))
    monkeypatch.setenv("ECHO_CERTFORGE_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv("ECHO_CERTFORGE_API_KEY_PEPPER", "explicit-test-pepper-" + "x" * 32)
    monkeypatch.setenv("ECHO_CERTFORGE_ADAPTER_MODE", "pending")
    app_module = importlib.import_module("echo_certification_forge.app")
    manifest = RuleManifest.load(ROOT / "policies/mandatory-rules.v2.json")
    monkeypatch.setattr(app_module, "_policy", ROOT / "policies/mandatory-rules.v2.json")
    monkeypatch.setenv("ECHO_CERTFORGE_ADAPTER_MODE", "required")
    for name in ("PROD_ADAPTER_RESPONSE", "PROD_ADAPTER_POLICY", "ADAPTER_REGISTRY"):
        monkeypatch.setenv("ECHO_CERTFORGE_" + name, str(tmp_path / name))
    # Verification itself is covered by the signed adapter tests; this isolates runtime wiring.
    monkeypatch.setattr(app_module, "load_adapter_execution_profile", lambda **kw: ((), None, None, None))
    public = app_module._load_certification_environment()
    captured = {}

    def observe_dispatch(*args, **kwargs):
        captured.update(kwargs["worker_options"])
        return None, None

    signer = Ed25519VerdictSigner.generate()
    monkeypatch.setattr(dispatch_worker, "dispatch_once", observe_dispatch)
    monkeypatch.setattr(dispatch_worker, "_load_signer", lambda path: signer)
    assert dispatch_worker.main([
        "--once", "--sandbox", "--adapter-runner-signing-key", str(tmp_path / "test-only-key"),
    ]) == 3  # explicitly empty stubbed queue, no worker claim
    assert captured["runtime_profile"].sandbox == captured["sandbox"]
    assert captured["sandbox"].memory == "768m"
    source = tmp_path / "target"
    source.mkdir()
    (source / "README.txt").write_text("trusted fixture; no journey executes")
    result = run_worker.run(
        "runtime-agreement", "runtime-test", {"type": "local", "path": str(source)},
        store=captured["store"], manifest=manifest, signer=signer,
        entitled=frozenset({"runtime-test"}),
        sandbox=captured["sandbox"], runtime_profile=captured["runtime_profile"],
        adapter_records=(),
    )
    assert "error" not in result
    assert result["release_verdict"] == "NOT_READY"
    context = ServiceContext(
        store=captured["store"], manifest=manifest,
        trusted_keys=TrustedPublicKeyRegistry.empty(), certification_environment=public,
    )
    status = TestClient(create_app(context)).get("/v1/status").json()
    assert status["certification_environment_identity_digest"] == result["environment_identity_digest"]
    assert status["runner_image_digest"] == "sha256:" + "4" * 64


def test_profile_mismatch_rejects_before_acquisition(tmp_path, monkeypatch, store, manifest):
    from echo_certification_forge import run_worker
    from echo_certification_forge.runtime_identity import RuntimeProfile
    from echo_certification_forge.signing import Ed25519VerdictSigner

    def forbidden_acquisition(*args, **kwargs):
        pytest.fail("mismatched execution must never acquire customer input")

    monkeypatch.setattr(run_worker, "acquire_target", forbidden_acquisition)
    profile = RuntimeProfile(DockerSandbox(), ("python", "approved.py"))
    result = run_worker.run(
        "runtime-reject", "runtime-test", {"type": "local", "path": str(tmp_path)},
        store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
        sandbox=profile.sandbox, runtime_profile=profile, journey=["python", "other.py"],
    )
    assert result == {"run_id": "runtime-reject", "error": "runtime_profile_mismatch"}


def test_acquired_oci_image_cannot_override_an_explicit_profile(tmp_path, monkeypatch, store, manifest):
    from echo_certification_forge import run_worker
    from echo_certification_forge.acquisition import AcquiredTarget
    from echo_certification_forge.runtime_identity import RuntimeProfile
    from echo_certification_forge.sandbox import SandboxResult
    from echo_certification_forge.signing import Ed25519VerdictSigner

    executed = []
    monkeypatch.setattr(DockerSandbox, "run", lambda *args: executed.append(True) or SandboxResult(0, "", "", False))
    monkeypatch.setattr(run_worker, "acquire_target", lambda *args: AcquiredTarget(
        tmp_path, "oci", "registry.test/acquired@sha256:" + "b" * 64, "b" * 64,
    ))
    profile = RuntimeProfile(DockerSandbox(image="registry.test/approved@sha256:" + "a" * 64), ("python", "app.py"))
    result = run_worker.run(
        "oci-runtime-fence", "runtime-test", {"type": "oci"},
        store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset({"runtime-test"}), sandbox=profile.sandbox,
        runtime_profile=profile, journey=list(profile.journey),
    )
    assert result.get("error") == "runtime_profile_mismatch"
    assert not executed
    assert not any((store.evidence_root / ".worker").iterdir())
