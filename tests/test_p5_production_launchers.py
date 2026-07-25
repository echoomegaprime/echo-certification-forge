from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_production_router_requires_v2_and_all_adapter_inputs() -> None:
    text = (ROOT / "scripts" / "certforge_run_router.py").read_text(encoding="utf-8")
    launch = (
        ROOT / "src" / "echo_certification_forge" / "production_launch.py"
    ).read_text(encoding="utf-8")
    assert "mandatory-rules.v2.json" in text
    assert "mandatory-rules.v1.json" not in text
    for option in ("--adapter-response", "--adapter-policy", "--adapter-registry"):
        assert option in launch
    assert "--adapter-runner-signing-key" in launch
    assert "production_adapter_inputs_unavailable" in text


def test_production_deploy_requires_v2_adapter_artifacts() -> None:
    text = (ROOT / "deploy" / "deploy_forge.sh").read_text(encoding="utf-8")
    assert "mandatory-rules.v2.json" in text
    assert "mandatory-rules.v1.json" not in text
    for name in (
        "adapter-bundle-response.json",
        "adapter-policy.json",
        "trusted-adapter-registry.json",
        "adapter-runner-signing-key.pem",
    ):
        assert name in text


def test_runtime_defaults_use_v2_manifest() -> None:
    for relative in (
        "src/echo_certification_forge/app.py",
        "src/echo_certification_forge/run_worker.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "mandatory-rules.v2.json" in text
        assert "mandatory-rules.v1.json" not in text
