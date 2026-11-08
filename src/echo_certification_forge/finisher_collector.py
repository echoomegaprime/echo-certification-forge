"""Finisher observation collection through a separately admitted owner probe.

This module never signs, deploys, enrolls a worker or changes a release policy.
The owner must independently review/admit the probe and pin its entire closure.
Successful collection produces an UNSIGNED_CANDIDATE, always NOT_READY.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from typing import Any, Protocol
from urllib.parse import urlsplit
import uuid

from .canonical import sha256_json
from .production_e2e import BASE_CHECKS, GENERIC_PROFILE, SCHEMA_VERSION, _contains_restricted_value

FRONTS = {"auto": "claude", "cauto": "codex", "gauto": "gemini", "grauto": "grok",
          "CFauto": "claude", "CFcauto": "codex", "CFgauto": "gemini", "CFgrauto": "grok"}
NEGATIVE_CONTROLS = ("unauthenticated", "wrong_owner", "wrong_installation", "wrong_source",
                     "invalid_token", "expired_token", "stale_control", "replayed_control",
                     "out_of_scope", "redirect", "forbidden_native_route")
CONTROL_STATES = {"pause": "paused", "resume": "running", "halt": "halted"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
LOG = logging.getLogger(__name__)


class CollectorError(RuntimeError):
    """A fixed nonsecret reason code; raw probe responses are never interpolated."""


class OwnerProbe(Protocol):
    def call(self, request: dict[str, Any]) -> dict[str, Any]: ...


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise CollectorError(reason)


def identifier(value: Any) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def timestamp(value: Any) -> datetime:
    require(isinstance(value, str) and len(value) <= 64, "time_invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None, "time_invalid")
        return result.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise CollectorError("time_invalid") from exc


def bounded_document(data: bytes, limit: int = 131072) -> dict[str, Any]:
    require(len(data) <= limit, "document_size")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "document_duplicate_key")
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(CollectorError("document_number")))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise CollectorError("document_invalid") from exc
    require(isinstance(result, dict), "document_invalid")
    try:
        require(not _contains_restricted_value(result), "restricted_content")
    except RecursionError as exc:
        raise CollectorError("document_depth") from exc
    return result


class PinnedOwnerProbe:
    """Bounded Linux process transport for a previously reviewed owner probe.

    Hashes are integrity pins, NOT administrative admission. The probe must query
    the real authenticated control plane for admission and every observation.
    No command, shell text, interpreter switch or provider argument is accepted
    from an observation. Dependencies must be pinned by the owner as well.
    """
    def __init__(self, command: list[str], pins: list[str], *,
                 dependencies: Mapping[str, str] | None = None, timeout: float = 120):
        require(isinstance(command, list) and len(command) == 2 and isinstance(pins, list) and len(pins) == 2,
                "probe_command_invalid")
        require(type(timeout) in (int, float) and 1 <= timeout <= 120, "probe_timeout_invalid")
        try:
            self.command = [str(Path(item).resolve(strict=True)) for item in command]
        except (OSError, ValueError, TypeError) as exc:
            raise CollectorError("probe_command_invalid") from exc
        self.pins = dict(zip(self.command, pins, strict=True))
        for path, pin in (dependencies or {}).items():
            resolved = str(Path(path).resolve(strict=True))
            require(resolved not in self.pins, "probe_pin_duplicate")
            self.pins[resolved] = pin
        self.timeout = timeout
        self._verify()

    def _verify(self) -> None:
        for name, expected in self.pins.items():
            require(digest(expected), "probe_pin_invalid")
            path = Path(name)
            require(path.is_file() and not path.is_symlink(), "probe_pin_file")
            value = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(65536), b""):
                    value.update(block)
            require(value.hexdigest() == expected, "probe_pin_mismatch")

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        self._verify()
        require(os.name == "posix", "probe_platform_unsupported")
        data = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        require(len(data) <= 8192, "probe_request_size")
        # Credentials remain opaque in the inherited normal scoped broker path.
        allowed = {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR",
                   "SOL_BROKER_TOKEN", "SOL_RUN_ID", "SOL_STATE", "SOL_STATE_DB", "SOL_ROLE"}
        environment = {name: value for name, value in os.environ.items() if name in allowed}
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        deadline = time.monotonic() + self.timeout
        process = subprocess.Popen([self.command[0], "-I", self.command[1]], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=environment, start_new_session=True, close_fds=True, bufsize=0)
        selector = selectors.DefaultSelector()
        output = bytearray()
        try:
            # Both directions share one deadline, including a child that never
            # reads stdin. No assumption about the actual pipe capacity is made.
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            sent = 0
            while selector.get_map():
                require(time.monotonic() < deadline, "probe_timeout")
                for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    try:
                        if key.fileobj is process.stdin:
                            sent += os.write(process.stdin.fileno(), data[sent:sent + 4096])
                            if sent == len(data):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                            continue
                        block = os.read(key.fileobj.fileno(), 16384)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(block)
                    require(len(output) <= 131072, "probe_output_size")
            try:
                process.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise CollectorError("probe_timeout") from exc
            require(process.returncode == 0, "probe_failed")
            self._verify()
            return bounded_document(bytes(output))
        except (OSError, subprocess.SubprocessError) as exc:
            raise CollectorError("probe_transport_failed") from exc
        finally:
            selector.close()
            # The probe owns this process group, including any unsettled children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            process.stdout.close()
            process.stdin.close()


class FinisherCollector:
    def __init__(self, policy: dict[str, Any], probe: OwnerProbe, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.policy = bounded_document(json.dumps(policy, allow_nan=False).encode(), 65536)
        self.probe, self.clock = probe, clock
        p = self.policy
        require(p.get("schema") == "echo.finisher.collector-policy.v1", "policy_schema")
        require(all(identifier(p.get(key)) for key in
                    ("tenant_id", "collector_id", "authority_id", "execution_id", "admission_id")), "policy_identity")
        bindings = p.get("bindings")
        require(isinstance(bindings, dict), "policy_bindings")
        expected_keys = {"target_identity_digest", "environment_identity_digest", "source_commit",
                         "native_source_commit", "transport_source_commit", "artifact_sha256",
                         "native_artifact_sha256", "image_digest", "installation_id", "owner_id", "cloudflare_origin",
                         "account_id", "application_id", "durable_object_id"}
        require(set(bindings) == expected_keys, "policy_bindings")
        require(all(digest(bindings[key]) for key in
                    ("target_identity_digest", "environment_identity_digest", "artifact_sha256", "native_artifact_sha256")), "policy_digest")
        require(all(isinstance(bindings[key], str) and COMMIT.fullmatch(bindings[key]) for key in
                    ("source_commit", "native_source_commit", "transport_source_commit")), "policy_source")
        require(bindings["source_commit"] in (bindings["native_source_commit"], bindings["transport_source_commit"]), "policy_source")
        require(isinstance(bindings["image_digest"], str) and bindings["image_digest"].startswith("sha256:")
                and digest(bindings["image_digest"][7:]), "policy_image")
        require(identifier(bindings["installation_id"]) and identifier(bindings["owner_id"]), "policy_installation")
        require(isinstance(bindings["account_id"], str) and re.fullmatch("[a-f0-9]{32}", bindings["account_id"])
                and digest(bindings["durable_object_id"]) and isinstance(bindings["application_id"], str)
                and re.fullmatch("[A-Za-z0-9_-]{1,128}", bindings["application_id"]), "policy_cloudflare_identity")
        origin = urlsplit(bindings["cloudflare_origin"])
        require(origin.scheme == "https" and bool(origin.hostname) and not origin.username and not origin.password
                and origin.path in ("", "/") and not origin.query and not origin.fragment, "policy_origin")
        require(digest(p.get("rollback_artifact_sha256")) and p["rollback_artifact_sha256"] != bindings["artifact_sha256"], "policy_rollback")
        require(isinstance(p.get("rollback_source_commit"), str)
                and COMMIT.fullmatch(p["rollback_source_commit"])
                and p["rollback_source_commit"] != bindings["source_commit"], "policy_rollback")
        require(isinstance(p.get("providers"), dict) and set(p["providers"]) == set(FRONTS.values()), "policy_providers")
        for provider in p["providers"].values():
            require(isinstance(provider, dict) and set(provider) == {"model", "account_sha256"}
                    and identifier(provider["model"]) and digest(provider["account_sha256"]), "policy_provider")
        self.policy_hash = sha256_json(p)
        self.challenge = uuid.uuid4().hex
        self.started = self.clock()
        require(self.started.tzinfo is not None, "clock_invalid")
        self.ids: set[str] = set()
        self.invocations: set[str] = set()
        self.control_ids: set[str] = set()
        self.native_control_ids: set[str] = set()
        self.restoration_ids: set[str] = set()
        self.evidence: list[dict[str, str]] = []

    def _query(self, operation: str, **extra: Any) -> dict[str, Any]:
        now = self.clock()
        require(0 <= (now - self.started).total_seconds() <= 1800, "collection_deadline")
        request = {"schema": "echo.finisher.owner-query.v1", "operation": operation,
                   "nonce": uuid.uuid4().hex, "policy_sha256": self.policy_hash,
                   **{key: self.policy[key] for key in
                      ("admission_id", "execution_id", "tenant_id", "collector_id", "bindings")}, **extra}
        LOG.info(json.dumps({"event": "owner_query", "operation": operation, "policy_sha256": self.policy_hash}))
        response = self.probe.call(request)
        require(isinstance(response, dict), "owner_response_invalid")
        response = bounded_document(json.dumps(response, allow_nan=False).encode())
        require(response.get("schema") == "echo.finisher.owner-response.v1"
                and response.get("nonce") == request["nonce"]
                and response.get("request_sha256") == sha256_json(request)
                and response.get("authority_id") == self.policy["authority_id"]
                and response.get("authenticated") is True and response.get("authorized") is True,
                "owner_response_binding")
        observed = timestamp(response.get("observed_at"))
        require(now - timedelta(seconds=1) <= observed <= self.clock() + timedelta(seconds=1), "owner_response_time")
        require(isinstance(response.get("result"), dict), "owner_response_result")
        return response["result"]

    def _admission(self) -> None:
        result = self._query("admission")
        require(result.get("allowed") is True and result.get("independent") is True, "admission_denied")
        require(all(result.get(key) == self.policy[key] for key in
                    ("admission_id", "collector_id", "execution_id", "tenant_id", "bindings")), "admission_binding")
        require(result.get("policy_sha256") == self.policy_hash and result.get("restoration_allowed") is True,
                "admission_journey_not_allowed")
        expiry = timestamp(result.get("expires_at"))
        require(self.clock() < expiry <= self.clock() + timedelta(hours=1), "admission_expired")
        require(result.get("operations") == ["observe", "recall"], "admission_operations")

    def _observe(self, kind: str, name: str) -> tuple[dict[str, Any], datetime]:
        self._admission()
        produced = self._query("observe", challenge=self.challenge, kind=kind, name=name)
        receipt_id = produced.get("receipt_id")
        require(identifier(receipt_id) and receipt_id not in self.ids, "receipt_replay")
        self.ids.add(receipt_id)
        self._admission()
        recalled = self._query("recall", receipt_id=receipt_id)
        content = recalled.get("content")
        require(recalled.get("receipt_id") == receipt_id and isinstance(content, dict), "receipt_readback")
        require(digest(recalled.get("content_sha256")) and recalled["content_sha256"] == sha256_json(content), "receipt_hash")
        require(content.get("schema") == "echo.finisher.observation.v1"
                and content.get("receipt_id") == receipt_id and content.get("mode") == "live"
                and content.get("challenge") == self.challenge and content.get("kind") == kind
                and content.get("name") == name, "observation_binding")
        require(all(content.get(key) == self.policy[key] for key in
                    ("tenant_id", "execution_id", "collector_id", "bindings")), "observation_identity")
        observed = timestamp(content.get("observed_at"))
        require(self.started <= observed <= self.clock() and (self.clock() - observed).total_seconds() <= 900, "observation_time")
        result = content.get("result")
        require(isinstance(result, dict), "observation_result")
        self.evidence.append({"kind": kind, "name": name, "receipt_id": receipt_id,
                              "sha256": recalled["content_sha256"], "observed_at": observed.isoformat()})
        LOG.info(json.dumps({"event": "observation_recalled", "kind": kind, "name": name,
                             "receipt_id": receipt_id, "sha256": recalled["content_sha256"]}))
        return result, observed

    def _target(self, target: Any, run_id: str | None = None) -> None:
        binding = self.policy["bindings"]
        expected = {"provider": "cloudflare", **{key: binding[key] for key in
                     ("account_id", "application_id", "durable_object_id", "installation_id")},
                    "source_sha": binding["transport_source_commit"]}
        require(isinstance(target, dict) and set(target) == {*expected, "run_id"}
                and all(target.get(key) == value for key, value in expected.items())
                and identifier(target.get("run_id")) and (run_id is None or target["run_id"] == run_id),
                "snapshot_target")

    def _observation_time(self, stamp: Any) -> datetime:
        if type(stamp) in (int, float):
            require(0 <= stamp <= 253402300799, "status_snapshot_time")
            stamp = datetime.fromtimestamp(stamp, UTC)
        else:
            stamp = timestamp(stamp)
        require(self.started <= stamp <= self.clock() and (self.clock() - stamp).total_seconds() <= 30,
                "status_snapshot_time")
        return stamp

    def _snapshot(self, value: Any, run_id: str | None = None) -> None:
        require(isinstance(value, dict) and value.get("schema") == "echo.finisher.ui.snapshot.v1"
                and not any(key in value for key in ("accepted", "applied", "request_id")), "status_snapshot_invalid")
        self._target(value.get("target"), run_id)
        require(value.get("source_sha") == self.policy["bindings"]["transport_source_commit"]
                and value.get("online") is True and value.get("readback_verified") is True
                and value.get("lifecycle") in ("online", "idle", "running", "executing"), "status_snapshot_unhealthy")
        checks = value.get("checks")
        require(isinstance(checks, dict) and all(checks.get(key) is True for key in
                ("service_active", "installation_verified", "heartbeat_fresh", "resource_admitted")), "status_snapshot_unhealthy")
        self._observation_time(value.get("observed_at"))

    def _control(self, action: str, control: Any, run_id: str) -> None:
        require(isinstance(control, dict) and identifier(control.get("request_id"))
                and identifier(control.get("native_request_id")) and control.get("action") == action,
                "front_control_invalid")
        require(control["request_id"] not in self.control_ids
                and control["native_request_id"] not in self.native_control_ids, "control_replay")
        self.control_ids.add(control["request_id"])
        self.native_control_ids.add(control["native_request_id"])
        self._target(control.get("target"), run_id)
        require(control.get("accepted") is True and control.get("applied") is True
                and control.get("state") == CONTROL_STATES[action], "front_control_not_applied")
        submitted = self._observation_time(control.get("submitted_at"))
        observed = control.get("readback")
        require(isinstance(observed, dict) and observed.get("target") == control["target"]
                and observed.get("source_sha") == self.policy["bindings"]["transport_source_commit"]
                and observed.get("readback_verified") is True, "control_readback_binding")
        require(self._observation_time(observed.get("observed_at")) >= submitted, "control_readback_stale")
        checks, controller = observed.get("checks"), observed.get("controller")
        require(isinstance(checks, dict) and checks.get("installation_verified") is True
                and isinstance(controller, dict) and controller.get("last_control_id") == control["native_request_id"],
                "control_readback_identity")
        require(type(controller.get("paused")) is bool and type(controller.get("halted")) is bool,
                "control_readback_state")
        expected = {"pause": controller["paused"] and not controller["halted"],
                    "resume": not controller["paused"] and not controller["halted"],
                    "halt": controller["halted"]}
        require(expected[action], "control_readback_state")
        live = checks.get("service_active") is True and checks.get("heartbeat_fresh") is True
        terminal = (observed.get("terminal_halt_verified") is True
                    and observed.get("lifecycle") == "halted" and observed.get("online") is False)
        # A legitimate fresh terminal observation proves process exit through
        # the owner observer. It must not fabricate a live controller heartbeat.
        require(terminal if action == "halt" else live, "control_readback_unavailable")

    def _front(self, name: str, result: dict[str, Any]) -> None:
        provider = FRONTS[name]
        require(result.get("provider") == provider and all(result.get(key) == value for key, value in
                    self.policy["providers"][provider].items()), "front_provider_identity")
        require(all(result.get(key) is True for key in ("model_observed", "account_verified", "subscription_auth",
                    "heartbeat_verified", "scoped_mcp_verified", "uncertain_replay_suppressed", "cleanup_verified")), "front_incomplete")
        require(type(result.get("status_inference_count")) is int and result["status_inference_count"] == 0, "front_status_inference")
        require(all(identifier(result.get(key)) for key in ("run_id", "worker_id", "session_id",
                    "provider_invocation_id", "hook_receipt_id", "capture_receipt_id")), "front_receipt_missing")
        require(result.get("resumed_session_id") == result["session_id"], "front_resume_mismatch")
        require(digest(result.get("hook_readback_sha256")) and digest(result.get("capture_readback_sha256")), "front_capture_readback")
        require(result["provider_invocation_id"] not in self.invocations, "provider_replay")
        self.invocations.add(result["provider_invocation_id"])
        self._snapshot(result.get("status_snapshot"), result["run_id"])
        start = result.get("start")
        require(isinstance(start, dict) and start.get("state") == "singleton_observed"
                and start.get("already_running") is True and start.get("readback_verified") is True,
                "front_start_unverified")
        self._target(start.get("target"), result["run_id"])
        controls = result.get("controls")
        require(isinstance(controls, dict) and set(controls) == set(CONTROL_STATES), "front_controls_missing")
        for action in CONTROL_STATES:
            self._control(action, controls[action], result["run_id"])

    def _restoration(self, name: str, previous_run_id: str) -> None:
        result, _ = self._observe("restoration", name)
        require(result.get("method") == "admitted_owner_operation"
                and result.get("admission_id") == self.policy["admission_id"]
                and result.get("previous_run_id") == previous_run_id
                and identifier(result.get("operation_id"))
                and result["operation_id"] not in self.restoration_ids, "restoration_unverified")
        self.restoration_ids.add(result["operation_id"])
        self._snapshot(result.get("snapshot"))

    def _rollback(self) -> None:
        rollback, _ = self._observe("rollback", "restore-and-recover")
        require(rollback.get("verified") is True and rollback.get("restored_readback_verified") is True
                and rollback.get("recovered_readback_verified") is True
                and rollback.get("restored_artifact_sha256") == self.policy["rollback_artifact_sha256"]
                and rollback.get("recovered_artifact_sha256") == self.policy["bindings"]["artifact_sha256"]
                and rollback.get("restored_source_commit") == self.policy["rollback_source_commit"]
                and rollback.get("restored_checkpoint_source_commit") == self.policy["rollback_source_commit"]
                and rollback.get("recovered_source_commit") == self.policy["bindings"]["source_commit"]
                and rollback.get("recovered_checkpoint_source_commit") == self.policy["bindings"]["source_commit"]
                and all(digest(rollback.get(key)) for key in ("restored_checkpoint_sha256", "recovered_checkpoint_sha256",
                        "restored_configuration_sha256", "recovered_configuration_sha256")), "rollback_failed")

    def collect(self) -> dict[str, Any]:
        require(not self.evidence, "collector_already_used")
        self._admission()
        for front in FRONTS:
            result, _ = self._observe("front", front)
            self._front(front, result)
            # A halted singleton cannot serve the next front. Its independent
            # owner must use an already admitted restoration operation; frontend
            # start reconciliation itself is not a bootstrap or reset grant.
            self._restoration(front, result["run_id"])
        for name in NEGATIVE_CONTROLS:
            result, _ = self._observe("negative", name)
            require(result.get("denied") is True and result.get("side_effects") is False
                    and digest(result.get("before_sha256")) and result.get("before_sha256") == result.get("after_sha256"), "negative_control_failed")
        # Restore the prior compatible checkpoint/config and then the candidate
        # before measuring final health. A Worker image rollback alone is not
        # checkpoint restoration.
        self._rollback()
        probes = []
        for index in range(3):
            result, observed = self._observe("stability", str(index))
            require(all(result.get(key) is True for key in ("healthy", "resource_admitted", "heartbeat_verified"))
                    and type(result.get("unexpected_restarts")) is int and result["unexpected_restarts"] == 0, "stability_failed")
            snapshots = result.get("snapshots")
            require(isinstance(snapshots, dict) and set(snapshots) == set(FRONTS), "stability_fronts_missing")
            for snapshot in snapshots.values():
                self._snapshot(snapshot)
            probes.append(observed)
        require(probes[0] < probes[1] < probes[2] and (probes[2] - probes[0]).total_seconds() >= 30, "stability_interval")
        external, _ = self._observe("external", "acceptance")
        require(external.get("accepted") is True and external.get("ui_assets_verified") is True
                and external.get("access_session_verified") is True
                and identifier(external.get("reviewer_id")) and external["reviewer_id"] != self.policy["collector_id"]
                and external.get("origin") == self.policy["bindings"]["cloudflare_origin"], "external_acceptance_failed")
        self._admission()
        finished = self.clock()
        require((finished - self.started).total_seconds() <= 1800, "collection_deadline")
        payload = {"schema_version": SCHEMA_VERSION, "profile": GENERIC_PROFILE,
                   "attestation_id": "finisher-" + self.challenge,
                   "target_identity_digest": self.policy["bindings"]["target_identity_digest"],
                   "environment_identity_digest": self.policy["bindings"]["environment_identity_digest"],
                   "source_commit": self.policy["bindings"]["source_commit"],
                   "deployment_sha": self.policy["bindings"]["source_commit"],
                   "observed_at": self.started.isoformat(),
                   "expires_at": (self.started + timedelta(hours=1)).isoformat(),
                   "required_checks": sorted(BASE_CHECKS), "checks": {key: True for key in sorted(BASE_CHECKS)},
                   "stability_probe_count": len(probes), "collector_execution_id": self.policy["execution_id"],
                   "observation_manifest_sha256": sha256_json(self.evidence), "policy_sha256": self.policy_hash}
        return {"schema": "echo.finisher.unsigned-collection.v1", "status": "UNSIGNED_CANDIDATE",
                "release_verdict": "NOT_READY", "signature_verified": False, "owner_signing_required": True,
                "attestation_payload": payload, "evidence": self.evidence,
                "finished_at": finished.isoformat(), "bindings": self.policy["bindings"]}
