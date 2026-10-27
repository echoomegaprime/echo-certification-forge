"""Shared jobs resolve their own bounded plans while operator runtime choices stay pinned."""
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.run_worker import _worker_environment
from echo_certification_forge.runtime_identity import RuntimeProfile
from echo_certification_forge.sandbox import DockerSandbox
from echo_certification_forge.service import RuntimeEnvironmentResponse, ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import SubscriberGovernance, SubscriberPolicy

ROOT = Path(__file__).resolve().parents[1]


def test_image_only_profile_accepts_separate_job_plans_but_rejects_changed_runtime():
    profile = RuntimeProfile(DockerSandbox(image="sha256:" + "a" * 64))
    for journey in (["python3", "first.py"], ["python3", "second.py"]):
        profile.check_execution(profile.sandbox, journey)
    with pytest.raises(ValueError, match="runtime_profile_mismatch"):
        profile.check_execution(dataclasses.replace(profile.sandbox, image="sha256:" + "b" * 64), ["python3", "first.py"])
    with pytest.raises(ValueError, match="runtime_journey_invalid"):
        profile.check_execution(profile.sandbox, [""])


@pytest.fixture
def runtime_api(tmp_path, manifest):
    store = EvidenceStore(tmp_path / "runtime.sqlite", tmp_path / "evidence")
    governance = SubscriberGovernance(
        store.db_path, SubscriberPolicy.load(ROOT / "policies/subscriber-governance.v1.json"),
        b"runtime-planning-test-only-pepper-32-bytes",
    )
    owner = governance.provision_organization(
        slug="runtime-plan", display_name="Runtime planning test", owner_email="owner@example.test",
        owner_display_name="Owner", plan_code="developer",
    )
    profile = RuntimeProfile(DockerSandbox(image="sha256:" + "a" * 64))
    context = ServiceContext(
        store, manifest, TrustedPublicKeyRegistry.empty(), governance,
        certification_environment={"adapter_set_sha256": "b" * 64, "adapter_execution_profile_sha256": "c" * 64},
        runtime_profile=profile,
    )
    headers = {"X-Tenant-ID": owner.organization_id, "Authorization": "Bearer " + owner.bootstrap_api_key}
    return TestClient(create_app(context)), context, headers


def test_authenticated_environment_resolution_distinguishes_jobs_without_execution(runtime_api):
    client, context, headers = runtime_api
    plans = [["python3", "-B", "scripts/first.py"], ["python3", "-B", "scripts/second.py"]]
    replies = [client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": plan}) for plan in plans]
    assert [reply.status_code for reply in replies] == [200, 200]
    first, second = [reply.json() for reply in replies]
    assert first["submit_environment"]["identity_digest"] != second["submit_environment"]["identity_digest"]
    assert first["submit_environment"]["runner_image_digest"] == "sha256:" + "a" * 64
    measured = _worker_environment(
        "b" * 64, "c" * 64, manifest=context.manifest,
        sandbox=context.runtime_profile.sandbox, journey=plans[0],
    )
    assert first["environment"] == measured.to_dict()
    assert first["submit_environment"]["identity_digest"] == measured.identity_digest
    assert not context.store.list_runs(headers["X-Tenant-ID"])
    assert client.post("/v1/subscriber/runtime/environment", json={"journey": plans[0]}).status_code == 401
    other = dict(headers, **{"X-Tenant-ID": "other-tenant"})
    assert client.post("/v1/subscriber/runtime/environment", headers=other, json={"journey": plans[0]}).status_code == 404


def test_sdk_command_selector_is_removed_before_runtime_resolution(runtime_api):
    client, context, headers = runtime_api
    plan = ["python3", "test.py"]
    direct = client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": plan})
    sdk = client.post(
        "/v1/subscriber/runtime/environment", headers=headers,
        json={"command": "runtime_environment", "journey": plan},
    )
    assert direct.status_code == sdk.status_code == 200
    assert direct.json() == sdk.json()
    assert not context.store.list_runs(headers["X-Tenant-ID"])


@pytest.mark.parametrize("change", [{"unexpected": "x"}, {"harness_sha256": "invalid"}])
def test_runtime_response_components_reject_extras_and_invalid_hashes(runtime_api, change):
    client, _context, headers = runtime_api
    response = client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": ["python3", "test.py"]}).json()
    response["environment"].update(change)
    with pytest.raises(ValidationError):
        RuntimeEnvironmentResponse.model_validate(response)


def test_two_resolved_job_plans_agree_with_worker_and_keep_release_gates(runtime_api, tmp_path, monkeypatch):
    from echo_certification_forge import run_worker
    from echo_certification_forge.acquisition import acquire_target
    from echo_certification_forge.models import TargetIdentity
    from echo_certification_forge.sandbox import SandboxResult

    client, context, headers = runtime_api
    # Adapter verification is covered by P5. This wiring case has no qualified bundle
    # and must retain NOT_READY even when its stubbed sandbox transport succeeds.
    context.certification_environment = {}
    source = tmp_path / "trusted-target"
    source.mkdir()
    (source / "README.txt").write_text("trusted fixture; customer code never runs on host")
    acquired = acquire_target({"type": "local", "path": str(source)}, tmp_path / "unused")
    target = TargetIdentity(headers["X-Tenant-ID"], acquired.target_type, acquired.canonical_ref, acquired.artifact_sha256)
    project = client.post("/v1/subscriber/projects", headers=headers, json={
        "slug": "runtime-target", "name": "Runtime target", "target_reference": target.canonical_ref,
    }).json()
    executed = []
    monkeypatch.setattr(DockerSandbox, "run", lambda self, argv, *args: executed.append(argv) or SandboxResult(0, "fixture", "", False))
    plans = [["python3", "first.py"], ["python3", "second.py"]]
    for index, plan in enumerate(plans):
        declaration = client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": plan}).json()["submit_environment"]
        submitted = client.post("/v1/certifications", headers=headers, json={
            "tenant_id": headers["X-Tenant-ID"], "project_id": project["project_id"],
            "target": {"target_type": "local", "reference": target.canonical_ref, "identity_digest": target.identity_digest},
            "environment": declaration, "policy_version": context.manifest.manifest_id,
            "idempotency_key": "resolved-runtime-job-" + str(index), "journey": plan,
        })
        assert submitted.status_code == 201
        result = run_worker.run(
            submitted.json()["run_id"], headers["X-Tenant-ID"], {"type": "local", "path": str(source)},
            store=context.store, manifest=context.manifest, signer=Ed25519VerdictSigner.generate(),
            subscribers=context.subscribers, sandbox=context.runtime_profile.sandbox,
            runtime_profile=context.runtime_profile, journey=plan,
        )
        assert "error" not in result
        assert result["environment_identity_digest"] == declaration["identity_digest"]
        assert result["release_verdict"] == "NOT_READY"
    assert executed == plans


@pytest.mark.parametrize("body", [
    {"journey": ["python3"], "image": "sha256:" + "d" * 64},
    {"journey": []}, {"journey": [""]}, {"journey": ["bad\u0000argument"]},
    {"journey": ["x" * 2049]}, {"journey": ["python3"] * 33}, {"journey": [7]},
])
def test_environment_resolution_rejects_invalid_or_caller_selected_runtime(runtime_api, body):
    client, context, headers = runtime_api
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json=body).status_code == 422
    assert not context.store.list_runs(headers["X-Tenant-ID"])


def test_explicit_operator_journey_remains_pinned(runtime_api):
    client, context, headers = runtime_api
    context.runtime_profile = RuntimeProfile(context.runtime_profile.sandbox, ("python3", "approved.py"))
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": ["python3", "other.py"]}).status_code == 422
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": ["python3", "approved.py"]}).status_code == 200


def test_environment_resolution_requires_configured_runtime(runtime_api):
    client, context, headers = runtime_api
    context.runtime_profile = None
    reply = client.post("/v1/subscriber/runtime/environment", headers=headers, json={"journey": ["python3", "test.py"]})
    assert reply.status_code == 503
    assert reply.json()["detail"] == "runtime_profile_unavailable"


@pytest.mark.parametrize("with_bearer", [False, True])
def test_environment_resolution_requires_subscriber_governance(runtime_api, with_bearer):
    client, context, headers = runtime_api
    context.subscribers = None
    request_headers = headers if with_bearer else {"X-Tenant-ID": headers["X-Tenant-ID"]}
    reply = client.post(
        "/v1/subscriber/runtime/environment", headers=request_headers,
        json={"journey": ["python3", "test.py"]},
    )
    assert reply.status_code == 503
    assert reply.json()["detail"] == "subscriber_governance_disabled"
    assert not context.store.list_runs(headers["X-Tenant-ID"])


def test_declared_job_runtime_mismatch_rejects_before_acquisition(monkeypatch, store, manifest):
    from echo_certification_forge import run_worker

    store.register_declared_run(
        run_id="wrong-runtime", tenant_id="runtime-test", target_type="git",
        target_identity_digest="d" * 64, target_reference="https://example.test/repo@abc",
        environment_identity_digest="e" * 64, environment_json={"identity_digest": "e" * 64},
        policy_version=manifest.manifest_id, manifest_id=manifest.manifest_id, manifest_digest=manifest.digest,
    )
    monkeypatch.setattr(run_worker, "acquire_target", lambda *args: pytest.fail("changed runtime must not acquire customer code"))
    profile = RuntimeProfile(DockerSandbox(image="sha256:" + "a" * 64))
    reply = run_worker.run(
        "wrong-runtime", "runtime-test", {"type": "git", "url": "https://example.test/repo", "ref": "abc"},
        store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
        sandbox=profile.sandbox, runtime_profile=profile,
    )
    assert reply["error"] == "runtime_environment_mismatch"


def test_changed_job_argv_cannot_reuse_another_resolved_environment(monkeypatch, store, manifest):
    from echo_certification_forge import run_worker

    profile = RuntimeProfile(DockerSandbox(image="sha256:" + "a" * 64))
    declared = _worker_environment(manifest=manifest, sandbox=profile.sandbox, journey=["python3", "first.py"])
    store.register_declared_run(
        run_id="changed-plan", tenant_id="runtime-test", target_type="git",
        target_identity_digest="d" * 64, target_reference="https://example.test/repo@abc",
        environment_identity_digest=declared.identity_digest, environment_json={"identity_digest": declared.identity_digest},
        policy_version=manifest.manifest_id, manifest_id=manifest.manifest_id, manifest_digest=manifest.digest,
    )
    monkeypatch.setattr(run_worker, "acquire_target", lambda *args: pytest.fail("changed plan must not acquire customer code"))
    reply = run_worker.run(
        "changed-plan", "runtime-test", {"type": "git", "url": "https://example.test/repo", "ref": "abc"},
        store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
        sandbox=profile.sandbox, runtime_profile=profile, journey=["python3", "second.py"],
    )
    assert reply["error"] == "runtime_environment_mismatch"


def test_built_wheel_measures_public_packaged_harness(tmp_path, manifest):
    wheels = tmp_path / "wheels"
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels), str(ROOT)],
        check=True, capture_output=True, text=True,
    )
    wheel = next(wheels.glob("echo_certification_forge-*.whl"))
    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(installed)
    package = installed / "echo_certification_forge"
    assert (package / "runtime_data/pyproject.toml").read_bytes() == (ROOT / "pyproject.toml").read_bytes()
    assert (package / "runtime_data/requirements.lock").read_bytes() == (ROOT / "images/requirements.lock").read_bytes()
    probe = tmp_path / "wheel_probe.py"
    probe.write_text(
        "import json, sys\nfrom pathlib import Path\n"
        "from echo_certification_forge.policy import RuleManifest\n"
        "from echo_certification_forge.runtime_identity import measured_environment\n"
        "from echo_certification_forge.sandbox import DockerSandbox\n"
        "environment = measured_environment(manifest=RuleManifest.load(Path(sys.argv[1])), sandbox=DockerSandbox(), journey=['python3', 'journey.py'])\n"
        "print(json.dumps({'harness': environment.harness_sha256, 'image': environment.runner_image_sha256}))\n",
        encoding="utf-8",
    )
    process = subprocess.run(
        [sys.executable, "-B", str(probe), str(ROOT / "policies/mandatory-rules.v2.json")],
        env=dict(os.environ, PYTHONPATH=str(installed), PYTHONDONTWRITEBYTECODE="1"),
        cwd=tmp_path, capture_output=True, text=True, check=True,
    )
    actual = json.loads(process.stdout)
    expected = _worker_environment(sandbox=DockerSandbox(), journey=["python3", "journey.py"])
    assert actual["harness"] == expected.harness_sha256
    assert actual["image"] == expected.runner_image_sha256
