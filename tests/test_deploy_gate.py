from pathlib import Path


DEPLOY_SCRIPT = (
    Path(__file__).resolve().parents[1] / "deploy" / "deploy_forge.sh"
).read_text(encoding="utf-8")


def test_deploy_gate_locks_before_fetching_or_building() -> None:
    lock = DEPLOY_SCRIPT.index('flock -n 9')
    fetch = DEPLOY_SCRIPT.index('git "${GITC[@]}" fetch')
    assert lock < fetch
    assert 'exec 9>"$LOCK_FILE"' in DEPLOY_SCRIPT


def test_deploy_gate_can_pin_the_hosted_ci_approved_commit() -> None:
    fetch = DEPLOY_SCRIPT.index('git "${GITC[@]}" fetch')
    resolve = DEPLOY_SCRIPT.index('NEW_SHA="$(git rev-parse')
    reject = DEPLOY_SCRIPT.index('fetched commit does not match the hosted-CI-approved commit')
    release = DEPLOY_SCRIPT.index('RELEASE_ID="$NEW_SHA-')
    assert fetch < resolve < reject < release
    assert 'EXPECTED_COMMIT_SHA="${CERTFORGE_EXPECTED_COMMIT_SHA:-}"' in DEPLOY_SCRIPT
    assert '[ "$NEW_SHA" != "$EXPECTED_COMMIT_SHA" ]' in DEPLOY_SCRIPT


def test_deploy_gate_loads_readiness_trust_roots_from_directory() -> None:
    assert (
        "TrustedPublicKeyRegistry.from_directory(Path(sys.argv[2]))"
        in DEPLOY_SCRIPT
    )
    assert "TrustedPublicKeyRegistry(Path(sys.argv[2]))" not in DEPLOY_SCRIPT


def test_deploy_gate_binds_adapter_acceptance_to_readiness_and_runtime() -> None:
    """The exact adapter gate evidence must survive verification and promotion."""
    assert (
        'ADAPTER_ACCEPTANCE_REPORT="$ADAPTER_DIR/adapter-acceptance-report.json"'
        in DEPLOY_SCRIPT
    )
    assert '"$ADAPTER_ACCEPTANCE_REPORT"' in DEPLOY_SCRIPT
    assert "adapter_report_path=Path(sys.argv[4])" in DEPLOY_SCRIPT
    assert (
        'ECHO_CERTFORGE_ADAPTER_ACCEPTANCE_REPORT="$ADAPTER_ACCEPTANCE_REPORT"'
        in DEPLOY_SCRIPT
    )
    assert (
        "Environment=ECHO_CERTFORGE_ADAPTER_ACCEPTANCE_REPORT="
        "$ADAPTER_ACCEPTANCE_REPORT"
    ) in DEPLOY_SCRIPT


def test_deploy_gate_snapshots_and_restores_persistent_database() -> None:
    rollback_trap = DEPLOY_SCRIPT.index("trap rollback_production EXIT")
    quiesce = DEPLOY_SCRIPT.index(
        'if [ "$PREV_ACTIVE" = "active" ]; then',
        rollback_trap,
    )
    snapshot = DEPLOY_SCRIPT.index("source.backup(destination)")
    promotion = DEPLOY_SCRIPT.index('mv -Tf "$NEXT_LINK" "$CURRENT_LINK"')
    rollback_stop = DEPLOY_SCRIPT.index(
        'sudo systemctl stop "$SERVICE.service" >/dev/null 2>&1 || true'
    )
    rollback_restore = DEPLOY_SCRIPT.index('mv -f "$DB_RESTORE" "$DB_PATH"')
    rollback_start = DEPLOY_SCRIPT.index('sudo systemctl start "$SERVICE.service"')
    assert quiesce < snapshot < promotion
    assert rollback_stop < rollback_restore < rollback_start
    assert 'rm -f "$DB_PATH-wal" "$DB_PATH-shm"' in DEPLOY_SCRIPT
    assert 'DB_SNAPSHOT_READY=1' in DEPLOY_SCRIPT


def test_deploy_gate_restores_prior_service_lifecycle() -> None:
    assert (
        'PREV_ENABLED="$(systemctl is-enabled "$SERVICE.service"'
        in DEPLOY_SCRIPT
    )
    assert 'PREV_ACTIVE="$(systemctl is-active "$SERVICE.service"' in DEPLOY_SCRIPT
    assert 'UNIT_KIND="symlink"' in DEPLOY_SCRIPT
    assert 'UNIT_LINK_TARGET="$(sudo readlink "$UNIT_PATH")"' in DEPLOY_SCRIPT
    assert 'case "$PREV_ENABLED" in' in DEPLOY_SCRIPT
    assert 'sudo systemctl enable --runtime "$SERVICE.service"' in DEPLOY_SCRIPT
    assert 'sudo systemctl mask --runtime "$SERVICE.service"' in DEPLOY_SCRIPT
    assert 'if [ "$PREV_ACTIVE" = "active" ]; then' in DEPLOY_SCRIPT
    assert 'sudo systemctl disable --now "$SERVICE.service"' in DEPLOY_SCRIPT
    assert 'systemctl is-active --quiet "$SERVICE.service" && rollback_status=1' in DEPLOY_SCRIPT


def test_deploy_gate_rejects_dead_staging_process() -> None:
    port_free = DEPLOY_SCRIPT.index(
        'ss -H -ltn "sport = :$STAGING_PORT" | grep -q .'
    )
    process_check = DEPLOY_SCRIPT.index('kill -0 "$STAGING_PID"')
    health_check = DEPLOY_SCRIPT.index(
        'curl -sf "http://127.0.0.1:$STAGING_PORT/healthz"'
    )
    ownership_check = DEPLOY_SCRIPT.index(
        'grep -q "pid=$STAGING_PID,"'
    )
    assert port_free < process_check < health_check < ownership_check
    assert "staging process exited before readiness" in DEPLOY_SCRIPT
    assert "staging health came from a process other than candidate" in DEPLOY_SCRIPT


def test_deploy_gate_verifies_production_listener_ownership() -> None:
    assert "service_owns_port()" in DEPLOY_SCRIPT
    assert 'systemctl show "$SERVICE.service" --property MainPID --value' in DEPLOY_SCRIPT
    assert DEPLOY_SCRIPT.count('service_owns_port "$PROD_PORT"') >= 3
