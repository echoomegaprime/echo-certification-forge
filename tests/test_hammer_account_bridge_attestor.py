"""Acceptance regressions use synthetic evidence; no production key or target runs."""
import copy
import hashlib
import importlib.util
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "acb_attestor", Path(__file__).resolve().parents[1] / "scripts/hammer_account_bridge_attestor.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
SOURCE = "d410c61f11b5e15b30c9e2629f75838e38b5dc1c"
ASSERTIONS = {
    "repository_policy": 8, "account_continuity_core": 6,
    "provider_auth_monitor": 18, "provider_content_import": 9,
    "multiprovider_mcp": 35, "account_continuity_bridge": 22, "provider_registry": 21,
}
ATOMIC_CONTROLS = {
    "actual_windows_reader_recovers_without_target_delete",
    "EPERM_has_expected_platform_retry_boundary",
    "EACCES_has_expected_platform_retry_boundary",
    "EBUSY_has_expected_platform_retry_boundary",
    "EIO_has_expected_platform_retry_boundary",
    "persistent_failure_is_bounded_and_preserves_previous_state",
}


def atomic_rename_evidence():
    return {"ok": True, "platform": "win32",
            "assertions": {name: True for name in sorted(ATOMIC_CONTROLS)}}


def current_evidence():
    observed = datetime.now(UTC).isoformat()
    concurrency = {"ok": True, "concurrent_requests": 12, "concurrent_processes": 8,
                   "contended_lock_preserved": True}
    return {
        "schema_version": "echo.account-continuity.quench-evidence.v2",
        "host": "QUENCH", "observed_at": observed,
        "source_commit": SOURCE, "installed_cache_commit": SOURCE,
        "remote_branch_commit": SOURCE, "pull_request_head_commit": SOURCE,
        "pull_request": 4, "branch": "agent/grok47-provider-recovery-20261003",
        "installed_version": "1.1.0+codex.20261003191426",
        "installation_scope": "production", "installed_manifest_sha256": "a" * 64,
        "native_plugin_enabled": True, "fresh_native_session": True,
        "iterations": 3, "assertions_passed_per_iteration": [119, 119, 119],
        "critical_journeys": ["PASS", "PASS", "PASS"],
        "test_runs": [{"iteration": n, "source_commit": SOURCE, "total": 119,
                       "assertions": dict(ASSERTIONS), "critical_journey": "PASS",
                       "atomic_rename": atomic_rename_evidence(),
                       "router_concurrency": dict(concurrency), "observed_at": observed}
                      for n in range(1, 4)],
        "live_runs": [{"exact_canary_match": True, "selected_provider": "forge-qwen",
                       "selected_outcome": "success", "provenance": "LIVE_PROVIDER_BRIDGE",
                       "credential_copied_or_exposed": False, "canary_sha256": str(n) * 64,
                       "response_sha256": str(n) * 64, "observed_at": observed,
                       "session_id": f"synthetic-native-session-{n}", "model": "fixture-model",
                       "source_commit": SOURCE, "governance": "PASS"}
                      for n in range(1, 4)],
        "status_runs": [{"status_nonspending": True,
                         "server_name": "account_continuity_multiprovider_mcp",
                         "server_version": "0.5.0", "provider_count": 7, "tool_count": 17,
                         "observed_at": observed, "source_commit": SOURCE} for _ in range(3)],
        "gitleaks_exact_tree": "PASS", "codex_mcp_config": "ok",
        "private_key_exported": False, "credentials_in_evidence": False,
    }


def verify(tmp_path, document):
    path = tmp_path / "synthetic-evidence.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return collector.verify_quench_evidence(path, SOURCE)


def test_current_exact_installed_release_acceptance_is_supported(tmp_path):
    result = verify(tmp_path, current_evidence())
    assert result["assertions_passed_per_iteration"] == [119, 119, 119]
    assert result["live_canaries"] == 3
    assert result["installation_scope"] == "production"


def test_isolated_native_install_scope_is_preserved_not_promoted(tmp_path):
    document = current_evidence()
    document["installation_scope"] = "isolated_canary"
    assert verify(tmp_path, document)["installation_scope"] == "isolated_canary"


def prepare_main_fixture(tmp_path, monkeypatch, *, scope):
    document = current_evidence()
    document["installation_scope"] = scope
    evidence = tmp_path / "quench.json"
    evidence.write_text(json.dumps(document), encoding="utf-8")
    evidence_bytes = evidence.read_bytes()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("synthetic path only", encoding="utf-8")
    outputs = [tmp_path / name for name in ("envelope.json", "public.pem", "report.json")]
    args = SimpleNamespace(
        source_commit=SOURCE, base_commit="1" * 40,
        target_identity_digest="2" * 64, environment_identity_digest="3" * 64,
        bundle=placeholder, python=placeholder, pwsh=placeholder, node=placeholder,
        gitleaks=placeholder, workspace_root=workspace, quench_evidence=evidence,
        quench_evidence_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
        private_key=tmp_path / "unavailable-owner-key.pem", revision_receipt=placeholder,
        revision_receipt_sha256="4" * 64, hosted_delivery_id="synthetic-delivery",
        quench_address="127.0.0.1", quench_management_port=1,
        output=outputs[0], public_key_output=outputs[1], report_output=outputs[2])
    monkeypatch.setattr(collector, "parse_args", lambda: args)
    monkeypatch.setattr(collector.socket, "gethostname", lambda: "HAMMER")
    return args, evidence_bytes


def test_isolated_canary_cannot_reach_production_collection_or_signing(tmp_path, monkeypatch):
    args, evidence_bytes = prepare_main_fixture(tmp_path, monkeypatch, scope="isolated_canary")

    def forbidden(*args, **kwargs):
        pytest.fail("isolated canary reached a production collection/signing side effect")

    for name in ("verify_hosted_receipt", "verify_quench_reachability", "run",
                 "verify_private_key", "atomic_write"):
        monkeypatch.setattr(collector, name, forbidden)
    with pytest.raises(collector.AttestationError, match="production installation.*isolated_canary"):
        collector.main()
    assert args.quench_evidence.read_bytes() == evidence_bytes
    assert all(not path.exists() for path in (args.output, args.public_key_output, args.report_output))
    assert not list(args.workspace_root.iterdir())


def test_long_source_validation_cannot_refresh_expired_acceptance_before_signing(tmp_path, monkeypatch):
    args, evidence_bytes = prepare_main_fixture(tmp_path, monkeypatch, scope="production")
    elapsed = timedelta()

    class SimulatedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + elapsed

    monkeypatch.setattr(collector, "datetime", SimulatedClock)
    monkeypatch.setattr(collector, "verify_quench_reachability", lambda *args: None)
    monkeypatch.setattr(collector, "verify_hosted_receipt", lambda *args, **kwargs: {
        "document_sha256": "4" * 64, "receipt_hash": "5" * 64,
        "delivery_id": "synthetic-delivery", "check_run": 1})
    journeys = []

    def synthetic_run(command, **kwargs):
        nonlocal elapsed
        stdout = ""
        if "rev-parse" in command:
            stdout = SOURCE
        elif "list-heads" in command:
            stdout = f"{SOURCE} refs/heads/{collector.BRANCH}"
        elif "-File" in command:
            label = next(label for label, relative in collector.POWERSHELL_TESTS.items()
                         if command[-1].replace("\\", "/").endswith(relative))
            stdout = json.dumps({"ok": True, "assertions": ASSERTIONS[label]})
        elif command[-1].endswith("Test-ProviderRegistry.mjs"):
            stdout = json.dumps({"ok": True, "assertions": ASSERTIONS["provider_registry"]})
        elif command[-1].endswith("Test-RouterConcurrency.mjs"):
            stdout = json.dumps({"ok": True, "concurrent_requests": 12,
                                 "concurrent_processes": 8, "contended_lock_preserved": True})
        elif command[-1].endswith("Test-RouterAtomicRename.mjs"):
            stdout = json.dumps(atomic_rename_evidence())
        elif command[-1].endswith("certforge_journey.py"):
            journeys.append("PASS")
            stdout = "ACCOUNT_CONTINUITY_CRITICAL_JOURNEY_OK surfaces=26 apps=8 providers=7 secret_fields=0"
        elif "dir" in command:
            elapsed = timedelta(hours=2)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(collector, "run", synthetic_run)

    def forbidden(*args, **kwargs):
        pytest.fail("expired upstream evidence reached key access or signed output")

    monkeypatch.setattr(collector, "verify_private_key", forbidden)
    monkeypatch.setattr(collector, "atomic_write", forbidden)
    with pytest.raises(collector.AttestationError, match="current and timezone-aware"):
        collector.main()
    assert journeys == ["PASS"] * 3
    assert args.quench_evidence.read_bytes() == evidence_bytes
    assert all(not path.exists() for path in (args.output, args.public_key_output, args.report_output))
    assert not list(args.workspace_root.iterdir())


def test_workspace_without_native_installation_is_not_acceptance(tmp_path):
    document = current_evidence()
    document["installation_scope"] = "workspace"
    with pytest.raises(collector.AttestationError, match="scope"):
        verify(tmp_path, document)


def test_journey_surface_count_cannot_substitute_for_native_tool_inventory(tmp_path):
    document = current_evidence()
    document["status_runs"][0]["tool_count"] = 26
    with pytest.raises(collector.AttestationError, match="surface"):
        verify(tmp_path, document)


@pytest.mark.parametrize("field", ["source_commit", "installed_cache_commit",
                                  "remote_branch_commit", "pull_request_head_commit"])
def test_each_identity_substitution_fails_closed(tmp_path, field):
    document = current_evidence()
    document[field] = "0" * 40
    with pytest.raises(collector.AttestationError, match="exact-source"):
        verify(tmp_path, document)


@pytest.mark.parametrize("old_sha", ["def1828001c354bcf89f7d32bc987d6eba520cb6",
                                    "9f6e1b41cf548e62523baa020e3e1584610b704c",
                                    "6e92def9758eaea61c145d4b5e2465ec08eee30d"])
def test_superseded_installed_candidates_cannot_reuse_collector(tmp_path, old_sha):
    evidence = current_evidence()
    for field in ("source_commit", "installed_cache_commit", "remote_branch_commit", "pull_request_head_commit"):
        evidence[field] = old_sha
    with pytest.raises(collector.AttestationError, match="exact-source"):
        verify(tmp_path, evidence)


@pytest.mark.parametrize("field,value", [("installed_version", "old"), ("pull_request", 2),
                                        ("branch", "agent/old"), ("native_plugin_enabled", False),
                                        ("fresh_native_session", False)])
def test_uninstalled_or_wrong_native_release_is_rejected(tmp_path, field, value):
    document = current_evidence()
    document[field] = value
    with pytest.raises(collector.AttestationError):
        verify(tmp_path, document)


def test_duplicate_canary_cannot_count_as_three_runs(tmp_path):
    document = current_evidence()
    document["live_runs"] = [copy.deepcopy(document["live_runs"][0]) for _ in range(3)]
    with pytest.raises(collector.AttestationError, match="distinct"):
        verify(tmp_path, document)


@pytest.mark.parametrize("field,value", [("exact_canary_match", False),
    ("selected_provider", "fixture"), ("provenance", "MIRRORED"),
    ("governance", "UNKNOWN"), ("source_commit", "0" * 40),
    ("credential_copied_or_exposed", True), ("response_sha256", "f" * 64)])
def test_missing_real_canary_acceptance_cannot_pass(tmp_path, field, value):
    document = current_evidence()
    document["live_runs"][1][field] = value
    with pytest.raises(collector.AttestationError):
        verify(tmp_path, document)


def test_stale_and_naive_evidence_time_rejected(tmp_path):
    for observed in ((datetime.now(UTC) - timedelta(hours=2)).isoformat(), "2026-10-03T10:00:00"):
        document = current_evidence()
        document["observed_at"] = observed
        with pytest.raises(collector.AttestationError, match="current"):
            verify(tmp_path, document)


def test_failed_router_negative_control_rejected(tmp_path):
    document = current_evidence()
    document["test_runs"][1]["router_concurrency"]["contended_lock_preserved"] = False
    with pytest.raises(collector.AttestationError, match="router"):
        verify(tmp_path, document)


@pytest.mark.parametrize("mutation", ["missing", "failed", "non_windows", "partial", "false_ok"])
def test_atomic_rename_controls_require_real_complete_windows_acceptance(tmp_path, mutation):
    document = current_evidence()
    row = document["test_runs"][1]
    if mutation == "missing":
        row.pop("atomic_rename")
    elif mutation == "failed":
        row["atomic_rename"]["assertions"]["actual_windows_reader_recovers_without_target_delete"] = False
    elif mutation == "non_windows":
        row["atomic_rename"]["platform"] = "linux"
    elif mutation == "partial":
        row["atomic_rename"]["assertions"].pop("EIO_has_expected_platform_retry_boundary")
    else:
        row["atomic_rename"]["ok"] = False
    with pytest.raises(collector.AttestationError, match="atomic rename"):
        verify(tmp_path, document)


def test_one_missing_assertion_is_not_relabelled_pass(tmp_path):
    document = current_evidence()
    document["test_runs"][2]["assertions"]["provider_auth_monitor"] = 17
    with pytest.raises(collector.AttestationError, match="assertions"):
        verify(tmp_path, document)


def test_ok_flag_cannot_hide_failed_named_assertion():
    result = subprocess.CompletedProcess(["fixture"], 0,
        json.dumps({"ok": True, "assertions": {"negative_control": False}}), "")
    with pytest.raises(collector.AttestationError, match="assertion"):
        collector.parse_test_json(result, "fixture")


def test_zero_or_boolean_count_is_not_execution_evidence():
    for assertions in (0, -1, True, {}):
        result = subprocess.CompletedProcess(["fixture"], 0,
            json.dumps({"ok": True, "assertions": assertions}), "")
        with pytest.raises(collector.AttestationError, match="assertion"):
            collector.parse_test_json(result, "fixture")


@pytest.mark.parametrize("stdout", ["not json", "[]", "{}",
    '{"ok":true,"concurrent_requests":12,"concurrent_processes":8,"contended_lock_preserved":false}'])
def test_router_command_requires_real_success_and_negative_control(stdout):
    with pytest.raises(collector.AttestationError, match="router"):
        collector.read_router_command(subprocess.CompletedProcess(["fixture"], 0, stdout, ""))


@pytest.mark.parametrize("stdout", ["not json", "[]", "{}",
    '{"ok":true,"platform":"win32","assertions":6}',
    '{"ok":true,"platform":"linux","assertions":{}}'])
def test_atomic_rename_command_requires_all_real_windows_controls(stdout):
    with pytest.raises(collector.AttestationError, match="atomic rename"):
        collector.read_atomic_rename_command(subprocess.CompletedProcess(["fixture"], 0, stdout, ""))


def test_evidence_write_does_not_replace_an_existing_owner_file(tmp_path):
    destination = tmp_path / "receipt.json"
    destination.write_bytes(b"existing owner evidence")
    with pytest.raises(FileExistsError):
        collector.atomic_write(destination, b"replacement")
    assert destination.read_bytes() == b"existing owner evidence"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["receipt.json"]


def test_evidence_write_is_complete_and_removes_temporary_file(tmp_path):
    destination = tmp_path / "receipt.json"
    collector.atomic_write(destination, b"complete evidence")
    assert destination.read_bytes() == b"complete evidence"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["receipt.json"]


def test_owner_evidence_pin_rejects_changed_bytes(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text('{"host":"QUENCH"}')
    with pytest.raises(collector.AttestationError, match="custody"):
        collector.read_json(path, expected_sha256="0" * 64)


def test_parse_and_custody_hash_use_one_byte_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "evidence.json"
    original = b'{"host":"QUENCH"}'
    path.write_bytes(original)
    expected = hashlib.sha256(original).hexdigest()
    real_read = Path.read_bytes

    def replace_after_read(selected):
        data = real_read(selected)
        if selected == path:
            path.write_bytes(b'{"host":"changed-after-read"}')
        return data

    monkeypatch.setattr(Path, "read_bytes", replace_after_read)
    document, digest = collector.read_json(path, expected_sha256=expected)
    assert document == {"host": "QUENCH"}
    assert digest == expected
