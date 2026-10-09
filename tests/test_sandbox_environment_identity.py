"""Actual runtime identity changes invalidate reuse; no customer code runs on host."""
from dataclasses import replace
import json

import pytest

from echo_certification_forge.run_worker import _worker_environment, run
from echo_certification_forge.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxError, SandboxResult
from echo_certification_forge.signing import Ed25519VerdictSigner


def test_image_override_cannot_reuse_default_environment():
    first = DockerSandbox()
    other = replace(first, image="example/runner@sha256:" + "b" * 64)
    a = _worker_environment(sandbox=first)
    b = _worker_environment(sandbox=other)
    assert a.runner_image_sha256 == DEFAULT_IMAGE.rsplit(":", 1)[1]
    assert b.runner_image_sha256 == "b" * 64
    assert a.identity_digest != b.identity_digest
    assert a.identity_digest != _worker_environment().identity_digest


@pytest.mark.parametrize("change", [
    {"memory": "1024m"}, {"cpus": "0.5"}, {"pids_limit": 64},
    {"tmpfs_size": "32m"}, {"timeout_s": 45.0}, {"user": "1000:1000"},
    {"docker": ("sudo", "docker")},
    {"extra_env": {"ECHO_TEST_PYTHON": "/opt/python/bin/python3"}},
])
def test_execution_change_invalidates_identity_without_revealing_env(change):
    original = _worker_environment(sandbox=DockerSandbox())
    changed = _worker_environment(sandbox=replace(DockerSandbox(), **change))
    assert original.identity_digest != changed.identity_digest
    assert "/opt/python" not in json.dumps(changed.to_dict())


def test_environment_order_does_not_change_identity():
    one = DockerSandbox(extra_env={"A": "1", "B": "2"})
    two = DockerSandbox(extra_env={"B": "2", "A": "1"})
    assert _worker_environment(sandbox=one) == _worker_environment(sandbox=two)


@pytest.mark.parametrize("image", ["node:24.19.0", "node@sha256:bad", "sha256:" + "a" * 63])
def test_invalid_image_rejected_before_any_acquisition(image, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("target acquisition must not occur for an unpinned runner")
    monkeypatch.setattr("echo_certification_forge.run_worker.acquire_target", forbidden)
    with pytest.raises(SandboxError, match="pinned"):
        run("invalid-runtime", "fixture", {"type": "local", "path": "unused"},
            store=None, manifest=None, signer=None, sandbox=DockerSandbox(image=image))


def test_real_worker_persists_selected_image_and_refuses_production_without_e2e(
    tmp_path, store, manifest, monkeypatch,
):
    source = tmp_path / "inert-target"
    source.mkdir()
    (source / "README.md").write_text("inert synthetic fixture\n", encoding="utf-8")
    selected = DockerSandbox(image="example/runner@sha256:" + "b" * 64)
    seen = []
    def sandbox_run(self, argv, workdir, execution_guard=None):
        seen.append((self.image, argv))
        assert workdir == source  # Local acquisition is inert; Docker mounts this read-only.
        return SandboxResult(0, "fixture journey completed", "", False)
    monkeypatch.setattr(DockerSandbox, "run", sandbox_run)
    result = run("cert-bound-runtime", "fixture", {"type": "local", "path": str(source)},
                 store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
                 entitled=frozenset({"fixture"}), journey=["node", "--version"], sandbox=selected)
    recorded = store.get_run("cert-bound-runtime", "fixture")
    assert seen == [(selected.image, ["node", "--version"])]
    assert recorded["environment_identity_digest"] == _worker_environment(sandbox=selected).identity_digest
    assert result["release_verdict"] == "NOT_READY"
    assert result["runner_image_digest"] == "sha256:" + "b" * 64
    assert result["sandbox_execution_profile_sha256"] == selected.execution_profile_sha256()
    rules = store.list_rule_results("cert-bound-runtime", "fixture")
    assert rules["critical_journeys"].passed
    assert not rules["production_e2e"].passed
