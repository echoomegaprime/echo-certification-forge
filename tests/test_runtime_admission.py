import copy
import dataclasses
import json

import pytest

from echo_certification_forge.canonical import sha256_bytes
from echo_certification_forge.runtime_identity import load_runtime_profile, measured_environment
from echo_certification_forge.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxResult
from echo_certification_forge.signing import Ed25519VerdictSigner
from test_runtime_job_binding import runtime_api

SHA = "a" * 40
REPO = "https://github.com/example/fielddesk.git"
IMAGE = "sha256:" + "e" * 64
JOURNEY = ["python3", "-B", "scripts/certforge_journey.py"]


def config(tenant="tenant-a", project="project-a"):
    return {"schema_version": "certforge.runtime.v2", "project_bindings": [{
        "binding_id": "fielddesk-exact", "tenant_id": tenant, "project_id": project,
        "repository": REPO, "source_commit": SHA,
        "dependencies": {"package-lock.json": sha256_bytes(b"locked dependencies\n")},
        "sandbox": {"image": IMAGE, "memory": "2g", "timeout_s": 120}, "journey": JOURNEY,
    }]}


def profile(tmp_path, value):
    path = tmp_path / "operator.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return load_runtime_profile(path)


def spec(**changes):
    return dict({"type": "git", "url": REPO, "ref": SHA, "source_commit": SHA}, **changes)


def test_operator_selects_exact_source_and_keeps_default_isolation(tmp_path, manifest):
    catalog = profile(tmp_path, config())
    selected = catalog.select("tenant-a", "project-a", spec())
    assert selected.sandbox.image == IMAGE
    assert selected.sandbox.memory == "2g"
    selected.check_execution(selected.sandbox, JOURNEY)
    assert catalog.sandbox == DockerSandbox()
    assert catalog.sandbox.image == DEFAULT_IMAGE
    assert catalog.select("tenant-b", "project-a", spec()) is catalog
    assert catalog.select("tenant-a", "project-b", spec()) is catalog
    assert catalog.select("tenant-a", "project-a", spec(url="https://github.com/example/other.git")) is catalog
    base = measured_environment(manifest=manifest, sandbox=selected.sandbox, journey=JOURNEY)
    bound = measured_environment(manifest=manifest, sandbox=selected.sandbox, journey=JOURNEY,
                                 runtime_binding_sha256=selected.binding.digest)
    assert base.identity_digest != bound.identity_digest
    changed = config()
    changed["project_bindings"][0]["dependencies"]["package-lock.json"] = "f" * 64
    replacement = profile(tmp_path, changed).select("tenant-a", "project-a", spec())
    assert selected.binding.digest != replacement.binding.digest


@pytest.mark.parametrize("change", [{"ref": "main"}, {"source_commit": "b" * 40}, {"type": "local"}])
def test_configured_project_rejects_unadmitted_source(tmp_path, change):
    with pytest.raises(ValueError, match="runtime_binding_target_mismatch"):
        profile(tmp_path, config()).select("tenant-a", "project-a", spec(**change))


@pytest.mark.parametrize("change", [
    {"sandbox": {"image": "python:latest"}}, {"sandbox": {"image": IMAGE, "user": "0:0"}},
    {"sandbox": {"image": IMAGE, "network": "host"}}, {"sandbox": {"image": IMAGE, "extra_env": {}}},
    {"dependencies": {"../outside": "a" * 64}}, {"dependencies": {"C:/outside": "a" * 64}},
    {"dependencies": {}}, {"journey": None}, {"source_commit": "main"},
    {"dependencies": {"bad\u0000path": "a" * 64}},
    {"repository": "https://user:password@example.test/repo"}, {"unexpected": True},
])
def test_operator_binding_rejects_unsafe_or_incomplete_input(tmp_path, change):
    value = config()
    value["project_bindings"][0].update(change)
    with pytest.raises(ValueError):
        profile(tmp_path, value)


def test_duplicate_admission_and_v1_extension_rejected(tmp_path):
    value = config()
    value["project_bindings"].append(copy.deepcopy(value["project_bindings"][0]))
    with pytest.raises(ValueError, match="runtime_binding_duplicate"):
        profile(tmp_path, value)
    value = config()
    value["schema_version"] = "certforge.runtime.v1"
    with pytest.raises(ValueError, match="runtime_profile_fields_invalid"):
        profile(tmp_path, value)


@pytest.mark.parametrize("content", [b"changed", b"x" * (2 * 1024 * 1024 + 1), None], ids=["changed", "too-large", "missing"])
def test_dependency_mismatch_or_missing_file_denied(tmp_path, content):
    selected = profile(tmp_path, config()).select("tenant-a", "project-a", spec())
    if content is not None:
        (tmp_path / "package-lock.json").write_bytes(content)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        selected.binding.check_source(tmp_path, SHA)


@pytest.mark.parametrize("tampered", [False, True])
def test_api_and_worker_select_same_profile_and_fence_dependencies(runtime_api, tmp_path, monkeypatch, tampered):
    from echo_certification_forge import run_worker
    from echo_certification_forge.acquisition import acquire_target
    from echo_certification_forge.models import TargetIdentity, declared_target_identity_digest

    client, context, headers = runtime_api
    context.certification_environment = {}
    source = tmp_path / "source"
    source.mkdir()
    (source / "package-lock.json").write_bytes(b"changed" if tampered else b"locked dependencies\n")
    acquired = dataclasses.replace(acquire_target({"type": "local", "path": str(source)}, tmp_path / "unused"),
                                   target_type="git", canonical_ref=REPO + "@" + SHA, source_commit=SHA)
    target = TargetIdentity(headers["X-Tenant-ID"], "git", acquired.canonical_ref, acquired.artifact_sha256, source_commit=SHA)
    project = client.post("/v1/subscriber/projects", headers=headers, json={
        "slug": "fielddesk", "name": "FieldDesk fixture", "target_reference": target.canonical_ref,
    }).json()["project_id"]
    context.runtime_profile = profile(tmp_path, config(headers["X-Tenant-ID"], project))
    target_body = {"target_type": "git", "reference": target.canonical_ref, "url": REPO, "ref": SHA,
                   "source_commit": SHA, "identity_digest": declared_target_identity_digest(
                       headers["X-Tenant-ID"], "git", None, SHA, target.canonical_ref)}
    body = {"journey": JOURNEY, "project_id": project, "target": target_body}
    response = client.post("/v1/subscriber/runtime/environment", headers=headers, json=body)
    assert response.status_code == 200, response.text
    declaration = response.json()["submit_environment"]
    assert declaration["runner_image_digest"] == IMAGE
    wrong = copy.deepcopy(body)
    wrong["target"]["ref"] = "b" * 40
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json=wrong).status_code == 422
    wrong = dict(body, project_id="other-project")
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json=wrong).status_code == 404
    assert not context.store.list_runs(headers["X-Tenant-ID"])
    submitted = client.post("/v1/certifications", headers=headers, json={
        "tenant_id": headers["X-Tenant-ID"], "project_id": project, "target": target_body,
        "environment": declaration, "policy_version": context.manifest.manifest_id,
        "idempotency_key": "bound-fielddesk-fixture", "journey": JOURNEY,
    })
    assert submitted.status_code == 201, submitted.text
    monkeypatch.setattr(run_worker, "acquire_target", lambda *args: acquired)
    executions = []
    monkeypatch.setattr(DockerSandbox, "run", lambda self, argv, *args:
                        executions.append((self.image, self.memory, argv)) or SandboxResult(0, "fixture", "", False))
    result = run_worker.run(submitted.json()["run_id"], headers["X-Tenant-ID"], spec(),
        store=context.store, manifest=context.manifest, signer=Ed25519VerdictSigner.generate(),
        subscribers=context.subscribers, sandbox=context.runtime_profile.sandbox,
        runtime_profile=context.runtime_profile, journey=JOURNEY)
    if tampered:
        assert result["error"] == "runtime_binding_source_mismatch"
        assert not executions
    else:
        assert "error" not in result, result
        assert result["environment_identity_digest"] == declaration["identity_digest"]
        assert result["release_verdict"] == "NOT_READY"  # Fixture transport cannot certify production.
        assert executions == [(IMAGE, "2g", JOURNEY)]


@pytest.mark.parametrize("extra", [{"project_id": "project-a"}, {"target": {
    "target_type": "git", "reference": REPO, "identity_digest": "a" * 64}}, {"profile": "fielddesk"}])
def test_resolution_rejects_partial_binding_or_caller_profile(runtime_api, extra):
    client, _context, headers = runtime_api
    assert client.post("/v1/subscriber/runtime/environment", headers=headers,
                       json=dict({"journey": JOURNEY}, **extra)).status_code == 422
