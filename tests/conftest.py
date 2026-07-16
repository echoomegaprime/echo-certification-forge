from __future__ import annotations

from pathlib import Path

import pytest

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.models import EnvironmentIdentity, TargetIdentity
from echo_certification_forge.policy import RuleManifest


def digest(label: str) -> str:
    import hashlib
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture
def manifest() -> RuleManifest:
    return RuleManifest.load(Path(__file__).parents[1] / "policies" / "mandatory-rules.v1.json")


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence")


@pytest.fixture
def target() -> TargetIdentity:
    return TargetIdentity(
        tenant_id="tenant-alpha",
        target_type="git",
        canonical_ref="https://github.com/example/project@abc123",
        artifact_sha256=digest("artifact"),
        source_commit="abc123",
        dependency_sha256=digest("dependencies"),
        configuration_sha256=digest("configuration"),
    )


@pytest.fixture
def environment() -> EnvironmentIdentity:
    return EnvironmentIdentity(
        runner_image_sha256=digest("runner"),
        adapter_set_sha256=digest("adapters"),
        test_plan_sha256=digest("test-plan"),
        policy_sha256=digest("policy"),
        harness_sha256=digest("harness"),
        prompt_set_sha256=digest("prompts"),
        model_route_sha256=digest("models"),
        os_runtime_sha256=digest("os-runtime"),
        egress_policy_sha256=digest("egress"),
    )
