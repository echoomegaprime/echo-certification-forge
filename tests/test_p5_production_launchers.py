from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_production_dispatcher_requires_v2_and_all_adapter_inputs() -> None:
    router = (ROOT / "scripts" / "certforge_run_router.py").read_text(encoding="utf-8")
    dispatcher = (
        ROOT / "src" / "echo_certification_forge" / "dispatch_worker.py"
    ).read_text(encoding="utf-8")
    launch = (
        ROOT / "src" / "echo_certification_forge" / "production_launch.py"
    ).read_text(encoding="utf-8")
    assert "existing governed subscriber run" in router
    assert "mandatory-rules.v2.json" in dispatcher
    assert "mandatory-rules.v1.json" not in dispatcher
    for option in ("--adapter-response", "--adapter-policy", "--adapter-registry"):
        assert option in launch
        assert option in dispatcher
    assert "--adapter-runner-signing-key" in launch
    assert "--adapter-runner-signing-key" in dispatcher
    assert "production_adapter_inputs_unavailable" in dispatcher
    assert "--production-e2e-attestation-dir" in dispatcher
    assert "--trusted-production-e2e-keys" in dispatcher
    assert "DirectoryProductionE2EProvider" in dispatcher


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


def test_deploy_clears_stale_systemd_start_limits_before_start_and_rollback() -> None:
    text = (ROOT / "deploy" / "deploy_forge.sh").read_text(encoding="utf-8")
    rollback = text.split("rollback_production() {", 1)[1].split(
        'echo "== [7/9]', 1
    )[0]
    promotion = text.split('echo "== [7/9]', 1)[1]

    for service in ("$SERVICE.service", "$DISPATCH_SERVICE.service"):
        reset = f'systemctl reset-failed "{service}"'
        assert reset in rollback
        assert reset in promotion

    dispatcher_reset = 'systemctl reset-failed "$DISPATCH_SERVICE.service"'
    dispatcher_restart = 'systemctl restart "$DISPATCH_SERVICE.service"'
    assert promotion.index(dispatcher_reset) < promotion.index(dispatcher_restart)


def test_deploy_binds_dispatcher_to_root_owned_production_e2e_trust_roots() -> None:
    text = (ROOT / "deploy" / "deploy_forge.sh").read_text(encoding="utf-8")
    assert "ECHO_CERTFORGE_PRODUCTION_E2E_ATTESTATION_DIR" in text
    assert "ECHO_CERTFORGE_TRUSTED_PRODUCTION_E2E_KEYS" in text
    assert 'sudo install -d -o root -g root -m 0755 "$PRODUCTION_E2E_ATTESTATION_DIR"' in text
    assert 'sudo install -d -o root -g root -m 0755 "$PRODUCTION_E2E_TRUSTED_KEYS"' in text


def test_deploy_streams_private_sdk_sql_into_one_postgres_transaction() -> None:
    text = (ROOT / "deploy" / "deploy_forge.sh").read_text(encoding="utf-8")
    registration = text.split(
        'echo "== [9/9] persist and verify complete SDK schemas =="', 1
    )[1].split("PROMOTION_ARMED=0", 1)[0]

    assert registration.lstrip().startswith("cat \\")
    for name in (
        "register_certforge_caps.sql",
        "register_certforge_run_cap.sql",
        "register_certforge_r5_async_caps.sql",
        "register_certification_forge_r5_cap.sql",
        "register_certforge_sdk_schemas.sql",
    ):
        assert f'"$RELEASE_DIR/scripts/{name}"' in registration
    assert "| sudo -n -u postgres psql -1 -v ON_ERROR_STOP=1 -d echo" in registration
    assert '-f "$RELEASE_DIR/scripts/' not in registration


def test_runtime_defaults_use_v2_manifest() -> None:
    for relative in (
        "src/echo_certification_forge/app.py",
        "src/echo_certification_forge/run_worker.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "mandatory-rules.v2.json" in text
        assert "mandatory-rules.v1.json" not in text
