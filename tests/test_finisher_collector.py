"""Synthetic authority fixtures exercise rejection paths; none is live evidence."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json
import hashlib
import os
import sys
import subprocess
import time
from pathlib import Path

import pytest

from echo_certification_forge.canonical import sha256_json
from echo_certification_forge.finisher_collector import (
    CollectorError, FRONTS, NEGATIVE_CONTROLS, FinisherCollector, PinnedOwnerProbe,
)
from echo_certification_forge.production_e2e import BASE_CHECKS, validate_attestation_trust_metadata

NOW = datetime(2026, 11, 7, 6, 0, tzinfo=UTC)


def policy():
    return {
        "schema": "echo.finisher.collector-policy.v1", "tenant_id": "tenant-fixture",
        "collector_id": "independent-fixture", "authority_id": "owner-fixture",
        "execution_id": "execution-fixture", "admission_id": "admission-fixture",
        "bindings": {"target_identity_digest": "1" * 64,
                     "environment_identity_digest": "2" * 64,
                     "source_commit": "3" * 40, "native_source_commit": "4" * 40,
                     "transport_source_commit": "3" * 40, "artifact_sha256": "5" * 64,
                     "image_digest": "sha256:" + "6" * 64,
                     "native_artifact_sha256": "7" * 64,
                     "installation_id": "installation-fixture", "owner_id": "owner-fixture",
                     "account_id": "a" * 32, "application_id": "application-fixture",
                     "durable_object_id": "b" * 64,
                     "cloudflare_origin": "https://finisher.example.test"},
        "rollback_artifact_sha256": "8" * 64,
        "rollback_source_commit": "9" * 40,
        "rollback_checkpoint_sha256": "1" * 64,
        "rollback_configuration_sha256": "3" * 64,
        "recovered_checkpoint_sha256": "2" * 64,
        "recovered_configuration_sha256": "4" * 64,
        "providers": {v: {"model": v + "-fixture-model", "account_sha256": "a" * 64}
                      for v in set(FRONTS.values())},
    }


class OwnerFixture:
    """In-memory test authority, not a provider, deployment or signing service."""
    def __init__(self, config):
        self.config = deepcopy(config)
        self.time = NOW
        self.receipts = {}
        self.calls = []
        self.modify = lambda value: value
        self.admitted = True
        self.nonce_override = None
        self.shared_run_id = False

    def run_id(self, name):
        return "run-shared-singleton" if self.shared_run_id else "run-" + name

    def clock(self):
        return self.time

    def snapshot(self, name):
        binding = self.config["bindings"]
        return {"schema": "echo.finisher.ui.snapshot.v1", "observed_at": self.time.isoformat(),
                "source_sha": binding["transport_source_commit"], "online": True,
                "lifecycle": "idle", "readback_verified": True,
                "checks": {key: True for key in ("installation_verified", "service_active",
                                                  "heartbeat_fresh", "resource_admitted")},
                "target": {"provider": "cloudflare", **{key: binding[key] for key in
                           ("account_id", "application_id", "durable_object_id", "installation_id")},
                           "source_sha": binding["transport_source_commit"], "run_id": self.run_id(name)}}

    def call(self, request):
        self.calls.append(deepcopy(request))
        self.time += timedelta(seconds=1)
        op = request["operation"]
        common = {"schema": "echo.finisher.owner-response.v1", "nonce": request["nonce"],
                  "request_sha256": sha256_json(request), "authority_id": self.config["authority_id"],
                  "authenticated": True, "authorized": True,
                  "observed_at": self.time.isoformat()}
        if self.nonce_override:
            common["nonce"] = self.nonce_override
        if op == "admission":
            value = {"allowed": self.admitted, "admission_id": self.config["admission_id"],
                     "collector_id": self.config["collector_id"],
                     "execution_id": self.config["execution_id"], "tenant_id": self.config["tenant_id"],
                     "bindings": self.config["bindings"], "expires_at": (self.time + timedelta(minutes=15)).isoformat(),
                     "operations": ["observe", "recall"], "independent": True,
                     "policy_sha256": request["policy_sha256"], "restoration_allowed": True}
        elif op == "observe":
            kind, name = request["kind"], request["name"]
            if kind == "stability":
                self.time += timedelta(seconds=15)
            receipt_id = "receipt-" + str(len(self.receipts))
            value = {"receipt_id": receipt_id}
            data = {"schema": "echo.finisher.observation.v1", "receipt_id": receipt_id,
                    "tenant_id": self.config["tenant_id"], "execution_id": self.config["execution_id"],
                    "collector_id": self.config["collector_id"], "bindings": deepcopy(self.config["bindings"]),
                    "challenge": request["challenge"], "kind": kind, "name": name,
                    "observed_at": self.time.isoformat(), "mode": "live"}
            if kind == "front":
                provider = FRONTS[name]
                data["result"] = {
                    "provider": provider, **self.config["providers"][provider],
                    "provider_invocation_id": "invoke-" + name,
                    "model_observed": True, "account_verified": True, "subscription_auth": True,
                    "run_id": self.run_id(name), "worker_id": "worker-" + name,
                    "session_id": "session-" + name, "resumed_session_id": "session-" + name,
                    "heartbeat_verified": True, "scoped_mcp_verified": True,
                    "hook_receipt_id": "hook-" + name, "capture_receipt_id": "capture-" + name,
                    "hook_readback_sha256": "b" * 64, "capture_readback_sha256": "c" * 64,
                    "uncertain_replay_suppressed": True, "status_inference_count": 0,
                    "status_snapshot": self.snapshot(name),
                    "start": {"state": "singleton_observed", "already_running": True,
                              "readback_verified": True, "target": self.snapshot(name)["target"]},
                    "controls": {action: {"request_id": name + "-" + action, "accepted": True,
                                           "applied": True, "state": state, "action": action,
                                           "native_request_id": "native-" + name + "-" + action,
                                           "submitted_at": self.time.isoformat(),
                                           "target": self.snapshot(name)["target"],
                                           "readback": {"observed_at": self.time.isoformat(),
                                               "target": self.snapshot(name)["target"],
                                               "source_sha": self.config["bindings"]["transport_source_commit"],
                                               "readback_verified": True, "terminal_halt_verified": action == "halt",
                                               "lifecycle": "halted" if action == "halt" else "running",
                                               "online": action != "halt",
                                               "checks": {"installation_verified": True,
                                                          "service_active": action != "halt", "heartbeat_fresh": action != "halt"},
                                               "controller": {"paused": action == "pause", "halted": action == "halt",
                                                              "last_control_id": "native-" + name + "-" + action}}}
                                 for action, state in {"pause": "paused", "resume": "running", "halt": "halted"}.items()},
                    "cleanup_verified": True,
                }
            elif kind == "restoration":
                data["result"] = {"method": "admitted_owner_operation", "operation_id": "restore-" + name,
                                  "admission_id": self.config["admission_id"],
                                  "previous_run_id": self.run_id(name), "snapshot": self.snapshot(name)}
            elif kind == "negative":
                data["result"] = {"denied": True, "side_effects": False,
                                  "before_sha256": "d" * 64, "after_sha256": "d" * 64}
            elif kind == "stability":
                data["result"] = {"healthy": True, "resource_admitted": True,
                                  "heartbeat_verified": True, "unexpected_restarts": 0}
            elif kind == "stability-front":
                probe_index, front = name.split(":", 1)
                assert probe_index in ("0", "1", "2")
                snapshot = self.snapshot(front)
                data["result"] = {"front": front, "provider": FRONTS[front],
                                  "route_readback_verified": True, "snapshot": snapshot,
                                  "snapshot_sha256": sha256_json(snapshot)}
            elif kind == "external":
                data["result"] = {"accepted": True, "reviewer_id": "other-reviewer",
                                  "ui_assets_verified": True, "access_session_verified": True,
                                  "origin": self.config["bindings"]["cloudflare_origin"]}
            elif kind == "rollback":
                data["result"] = {"restored_artifact_sha256": self.config["rollback_artifact_sha256"],
                                  "recovered_artifact_sha256": self.config["bindings"]["artifact_sha256"],
                                  "restored_source_commit": self.config["rollback_source_commit"],
                                  "recovered_source_commit": self.config["bindings"]["source_commit"],
                                  "restored_checkpoint_source_commit": self.config["rollback_source_commit"],
                                  "recovered_checkpoint_source_commit": self.config["bindings"]["source_commit"],
                                  "restored_checkpoint_sha256": "1" * 64,
                                  "recovered_checkpoint_sha256": "2" * 64,
                                  "restored_configuration_sha256": "3" * 64,
                                  "recovered_configuration_sha256": "4" * 64,
                                  "restored_readback_verified": True, "recovered_readback_verified": True,
                                  "verified": True}
            self.receipts[receipt_id] = self.modify(data)
        else:
            data = deepcopy(self.receipts[request["receipt_id"]])
            value = {"receipt_id": request["receipt_id"], "content": data, "content_sha256": sha256_json(data)}
        return {**common, "result": value}


def collect(config=None, fixture=None):
    config = config or policy()
    fixture = fixture or OwnerFixture(config)
    return FinisherCollector(config, fixture, clock=fixture.clock).collect()


def test_all_eight_fronts_are_observed_then_independently_recalled():
    config = policy()
    owner = OwnerFixture(config)
    result = collect(config, owner)
    assert result["status"] == "UNSIGNED_CANDIDATE"
    assert result["release_verdict"] == "NOT_READY"
    assert result["signature_verified"] is False
    assert result["owner_signing_required"] is True
    assert "signing_key_id" not in result["attestation_payload"]
    assert validate_attestation_trust_metadata(result["attestation_payload"]) == (False, "production_e2e_signature_not_verified")
    assert set(result["attestation_payload"]["checks"]) == BASE_CHECKS
    assert {x["name"] for x in owner.calls if x["operation"] == "observe" and x["kind"] == "front"} == set(FRONTS)
    observed = [x for x in owner.calls if x["operation"] == "observe"]
    recalled = [x for x in owner.calls if x["operation"] == "recall"]
    assert len(observed) == len(recalled) == 16 + len(NEGATIVE_CONTROLS) + 3 + 3 * len(FRONTS) + 2
    journey = [(x["kind"], x["name"]) for x in observed]
    for index, name in enumerate(FRONTS):
        assert journey[index * 2:index * 2 + 2] == [("front", name), ("restoration", name)]
    assert journey.index(("rollback", "restore-and-recover")) < journey.index(("stability", "0"))
    assert [(kind, name) for kind, name in journey if kind == "stability-front"] == [
        ("stability-front", f"{index}:{front}") for index in range(3) for front in FRONTS
    ]


def test_all_eight_routes_may_share_one_authorized_cloudflare_singleton_run():
    config = policy()
    owner = OwnerFixture(config)
    owner.shared_run_id = True
    result = collect(config, owner)
    assert result["status"] == "UNSIGNED_CANDIDATE"
    assert result["release_verdict"] == "NOT_READY"
    assert len([x for x in owner.calls if x["operation"] == "recall"]) == 16 + len(NEGATIVE_CONTROLS) + 3 + 3 * len(FRONTS) + 2


def test_missing_admission_stops_before_any_observation():
    owner = OwnerFixture(policy())
    owner.admitted = False
    with pytest.raises(CollectorError, match="admission_denied"):
        collect(fixture=owner)
    assert [x["operation"] for x in owner.calls] == ["admission"]


@pytest.mark.parametrize("field,value", [("nonce", "forged"), ("request_sha256", "0" * 64),
                                         ("authenticated", False), ("authority_id", "candidate-author")])
def test_forged_owner_response_rejected(field, value):
    owner = OwnerFixture(policy())
    original = owner.call
    owner.call = lambda request: {**original(request), field: value}
    with pytest.raises(CollectorError, match="owner_response"):
        collect(fixture=owner)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(mode="fixture"),
    lambda d: d.update(challenge="prior-run"),
    lambda d: d["bindings"].update(source_commit="f" * 40),
    lambda d: d["bindings"].update(durable_object_id="f" * 64),
    lambda d: d["result"]["status_snapshot"]["target"].update(account_id="f" * 32),
    lambda d: d["result"]["status_snapshot"].update(online=False),
    lambda d: d["result"]["status_snapshot"].update(request_id="not-a-mutation"),
    lambda d: d["result"]["controls"]["halt"].update(state="stopped"),
    lambda d: d.update(observed_at=(NOW - timedelta(hours=2)).isoformat()),
    lambda d: d["result"].update(model="invented"),
    lambda d: d["result"].update(account_sha256="f" * 64),
    lambda d: d["result"].update(subscription_auth=False),
    lambda d: d["result"].update(resumed_session_id="latest-other-session"),
    lambda d: d["result"]["controls"]["halt"].update(applied=False),
    lambda d: d["result"].update(status_inference_count=1),
    lambda d: d["result"].update(capture_readback_sha256="bad"),
])
def test_forged_or_incomplete_front_proof_is_not_promoted(mutation):
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "front":
            mutation(data)
        return data
    owner.modify = change
    with pytest.raises(CollectorError):
        collect(fixture=owner)


def test_recall_hash_mismatch_is_rejected():
    owner = OwnerFixture(policy())
    original = owner.call
    def wrong(request):
        value = original(request)
        if request["operation"] == "recall":
            value["result"]["content_sha256"] = "f" * 64
        return value
    owner.call = wrong
    with pytest.raises(CollectorError, match="receipt_hash"):
        collect(fixture=owner)


@pytest.mark.parametrize("kind,field,value", [
    ("negative", "side_effects", True), ("negative", "after_sha256", "e" * 64),
    ("stability", "unexpected_restarts", 1), ("stability", "healthy", False),
    ("external", "reviewer_id", "independent-fixture"),
    ("external", "access_session_verified", False),
    ("rollback", "restored_artifact_sha256", "f" * 64),
    ("rollback", "restored_checkpoint_source_commit", "f" * 40),
    ("rollback", "recovered_readback_verified", False),
    ("restoration", "method", "unadmitted_reset"),
    ("restoration", "previous_run_id", "wrong-run"),
])
def test_negative_stability_external_and_rollback_fail_closed(kind, field, value):
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == kind:
            data["result"][field] = value
        return data
    owner.modify = change
    with pytest.raises(CollectorError):
        collect(fixture=owner)


@pytest.mark.parametrize("field", [
    "rollback_checkpoint_sha256", "rollback_configuration_sha256",
    "recovered_checkpoint_sha256", "recovered_configuration_sha256",
])
def test_missing_owner_approved_rollback_digest_pin_fails_before_observation(field):
    config = policy()
    del config[field]
    with pytest.raises(CollectorError, match="policy_rollback_identity"):
        collect(config)


@pytest.mark.parametrize("field", [
    "restored_checkpoint_sha256", "restored_configuration_sha256",
    "recovered_checkpoint_sha256", "recovered_configuration_sha256",
])
def test_well_formed_but_wrong_rollback_digest_fails_closed(field):
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "rollback":
            data["result"][field] = "f" * 64
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="rollback_failed"):
        collect(fixture=owner)


def test_sensitive_receipt_content_is_rejected_without_echoing_value():
    owner = OwnerFixture(policy())
    owner.modify = lambda data: {**data, "authorization": "test-sensitive-value"}
    with pytest.raises(CollectorError) as error:
        collect(fixture=owner)
    assert "test-sensitive-value" not in str(error.value)


def test_pinned_probe_rejects_source_drift_before_execution(tmp_path):
    path = tmp_path / "probe.py"
    path.write_text("raise SystemExit('must not execute')")
    with pytest.raises(CollectorError, match="probe_pin"):
        PinnedOwnerProbe([sys.executable, str(path)], ["0" * 64, "0" * 64])


def test_policy_rejects_userinfo_origin_and_boolean_counts():
    config = policy()
    config["bindings"]["cloudflare_origin"] = "https://name:password@example.test"
    with pytest.raises(CollectorError, match="policy"):
        collect(config)


def test_duplicate_provider_invocation_receipt_is_rejected():
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "front":
            data["result"]["provider_invocation_id"] = "reused-invocation"
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="replay"):
        collect(fixture=owner)


def make_probe(tmp_path, source, timeout=1):
    path = tmp_path / "probe.py"
    path.write_text(source)
    command = [str(Path(sys.executable).resolve()), str(path)]
    pins = [hashlib.sha256(Path(item).read_bytes()).hexdigest() for item in command]
    return PinnedOwnerProbe(command, pins, timeout=timeout)


@pytest.mark.skipif(os.name != "posix", reason="Linux owner-probe transport")
def test_nonreading_probe_has_whole_request_deadline_with_small_pipe(tmp_path, monkeypatch):
    import fcntl
    probe = make_probe(tmp_path, "import time; time.sleep(4)")
    original = subprocess.Popen
    def small_pipe(*args, **kwargs):
        process = original(*args, **kwargs)
        fcntl.fcntl(process.stdin.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        return process
    monkeypatch.setattr(subprocess, "Popen", small_pipe)
    started = time.monotonic()
    with pytest.raises(CollectorError, match="probe_timeout"):
        probe.call({"padding": "x" * 6000})
    assert time.monotonic() - started < 2.5


@pytest.mark.skipif(os.name != "posix", reason="Linux owner-probe transport")
def test_normal_broker_state_db_is_preserved_and_route_overrides_removed(tmp_path, monkeypatch):
    monkeypatch.setenv("SOL_STATE_DB", "/private/fixture.db")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/must/not/inherit")
    probe = make_probe(tmp_path, "import json,os,sys; json.load(sys.stdin); print(json.dumps({'state_ok':os.environ.get('SOL_STATE_DB')=='/private/fixture.db','override_present':'GOOGLE_APPLICATION_CREDENTIALS' in os.environ}))")
    assert probe.call({"request": "fixture"}) == {"state_ok": True, "override_present": False}


@pytest.mark.skipif(os.name != "posix", reason="Linux owner-probe transport")
def test_probe_output_overflow_is_bounded(tmp_path):
    probe = make_probe(tmp_path, "import sys; sys.stdin.read(); sys.stdout.write('x'*140000); sys.stdout.flush()")
    with pytest.raises(CollectorError, match="probe_output_size"):
        probe.call({"request": "fixture"})


def test_healthy_boolean_cannot_replace_per_route_stability_readback():
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "stability-front" and data["name"] == "2:CFgrauto":
            snapshot = data["result"]["snapshot"]
            snapshot["online"] = False
            # A correct route digest cannot turn an unhealthy snapshot into health.
            data["result"]["snapshot_sha256"] = sha256_json(snapshot)
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="status_snapshot_unhealthy"):
        collect(fixture=owner)


def test_cloned_owner_route_result_is_rejected_for_another_front():
    owner = OwnerFixture(policy())
    first = {}
    def change(data):
        if data["kind"] == "stability-front" and data["name"] == "0:auto":
            first["result"] = deepcopy(data["result"])
        if data["kind"] == "stability-front" and data["name"] == "0:cauto":
            # The singleton target may match; route provenance still must not.
            data["result"] = deepcopy(first["result"])
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="stability_route_binding"):
        collect(fixture=owner)


@pytest.mark.parametrize("field,value", [
    ("front", "auto"), ("provider", "claude"), ("route_readback_verified", False),
    ("snapshot_sha256", "f" * 64),
])
def test_stability_route_provenance_tampering_fails_closed(field, value):
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "stability-front" and data["name"] == "0:cauto":
            data["result"][field] = value
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="stability_route_binding"):
        collect(fixture=owner)


def test_legacy_aggregate_snapshots_cannot_count_as_route_receipts():
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "stability":
            data["result"]["snapshots"] = {front: owner.snapshot(front) for front in FRONTS}
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="stability_snapshots_unadmitted"):
        collect(fixture=owner)


@pytest.mark.parametrize("field", ["account_id", "application_id", "durable_object_id"])
def test_policy_requires_the_complete_cloudflare_identity_tuple(field):
    config = policy()
    del config["bindings"][field]
    with pytest.raises(CollectorError, match="policy_bindings"):
        collect(config)


def test_admission_revocation_is_checked_before_exact_recall():
    owner = OwnerFixture(policy())
    original = owner.call
    def revoke(request):
        value = original(request)
        if request["operation"] == "observe":
            owner.admitted = False
        return value
    owner.call = revoke
    with pytest.raises(CollectorError, match="admission_denied"):
        collect(fixture=owner)
    assert not any(request["operation"] == "recall" for request in owner.calls)


def test_admission_cannot_authorize_a_different_journey_policy():
    owner = OwnerFixture(policy())
    original = owner.call
    def wrong(request):
        value = original(request)
        if request["operation"] == "admission":
            value["result"]["policy_sha256"] = "f" * 64
        return value
    owner.call = wrong
    with pytest.raises(CollectorError, match="admission_journey"):
        collect(fixture=owner)


@pytest.mark.skipif(os.name != "posix", reason="Linux collector CLI")
@pytest.mark.parametrize("case,reason", [("missing_probe", "owner_probe_unconfigured"),
                                        ("wrong_pin", "policy_pin_mismatch"),
                                        ("symlink", "policy_path_invalid")])
def test_cli_refuses_missing_authority_or_bad_policy_without_output(tmp_path, case, reason):
    tmp_path.chmod(0o700)
    path = tmp_path / "policy.json"
    raw = json.dumps(policy()).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    pin = hashlib.sha256(raw).hexdigest()
    if case == "wrong_pin":
        pin = "0" * 64
    if case == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    output = tmp_path / "unsigned.json"
    process = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/collect_finisher_e2e.py"),
                              "--policy", str(path), "--policy-sha256", pin, "--output", str(output)],
                             capture_output=True, text=True, timeout=5)
    assert process.returncode == 2
    assert json.loads(process.stdout) == {"status": "HELD", "release_verdict": "NOT_READY", "reason": reason}
    assert not output.exists()


@pytest.mark.parametrize("mutation", [
    lambda c: c["pause"]["target"].update(run_id="another-run"),
    lambda c: c["pause"]["readback"]["target"].update(durable_object_id="f" * 64),
    lambda c: c["pause"]["readback"].update(source_sha="f" * 40),
    lambda c: c["resume"]["readback"]["controller"].update(last_control_id="different-request"),
    lambda c: c["resume"]["readback"]["controller"].update(paused=True),
    lambda c: c["halt"]["readback"]["controller"].update(halted=False),
    lambda c: c["halt"]["readback"].update(terminal_halt_verified=False),
    lambda c: c["pause"]["readback"]["checks"].update(heartbeat_fresh=False),
    lambda c: c["pause"]["readback"].update(observed_at=(NOW - timedelta(seconds=31)).isoformat()),
    lambda c: c["pause"].update(submitted_at=(NOW + timedelta(minutes=5)).isoformat()),
    lambda c: c["resume"].update(action="pause"),
])
def test_action_readback_cannot_cross_target_run_time_or_actual_state(mutation):
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "front":
            mutation(data["result"]["controls"])
        return data
    owner.modify = change
    with pytest.raises(CollectorError):
        collect(fixture=owner)


def test_native_control_id_cannot_be_replayed_with_new_front_request_id():
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "front":
            control = data["result"]["controls"]["pause"]
            control["native_request_id"] = "reused-native-id"
            control["readback"]["controller"]["last_control_id"] = "reused-native-id"
        return data
    owner.modify = change
    with pytest.raises(CollectorError, match="control_replay"):
        collect(fixture=owner)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(terminal_halt_verified=False, checks={"installation_verified": True, "service_active": True, "heartbeat_fresh": True}),
    lambda d: d.update(lifecycle="running"),
    lambda d: d.update(online=True),
])
def test_terminal_halt_requires_actual_stopped_cleanup_proof(mutation):
    owner = OwnerFixture(policy())
    def change(data):
        if data["kind"] == "front":
            mutation(data["result"]["controls"]["halt"]["readback"])
        return data
    owner.modify = change
    with pytest.raises(CollectorError):
        collect(fixture=owner)
