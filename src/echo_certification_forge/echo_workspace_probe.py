"""Concrete, unsigned Echo workspace observations through the shipped owner API.

This observer runs only against a pinned, isolated Linux engineering lane. It
does not sign documents, create trust, invoke a model, borrow provider accounts,
or convert local-session acceptance into production Workspace acceptance.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import math
import os
import re
import stat
import tarfile
import time
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from .canonical import canonical_json, sha256_bytes, sha256_json, to_utc_iso, utc_now

MAX_BODY = 1024 * 1024
LOCAL_CHECKS = ("identity", "auth", "lifecycle", "memory", "schedules", "portability", "browser", "stability", "cleanup")
REMAINING = ("trusted_collector_admission", "real_sdk_journey", "oauth_consent_and_read", "external_owner_acceptance", "bounded_autonomous_turn")


class ObservationError(RuntimeError):
    """A fixed diagnostic code; no response body, cookie or provider detail."""


def require(condition: Any, code: str) -> None:
    if not condition:
        raise ObservationError(code)


def bounded_json(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= MAX_BODY, "response_too_large")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in items:
            require(name not in result, "duplicate_json_field")
            result[name] = value
        return result

    def finite(value: Any, depth: int = 0) -> None:
        require(depth <= 32, "json_depth")
        if isinstance(value, float):
            require(math.isfinite(value), "nonfinite_json")
        elif isinstance(value, dict):
            for item in value.values():
                finite(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                finite(item, depth + 1)

    try:
        result = json.loads(raw, object_pairs_hook=pairs)
        require(isinstance(result, dict), "json_object_required")
        finite(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ObservationError("invalid_json") from error


def file_digest(path: Path, expected: str | None = None) -> str:
    require(path.is_absolute(), "absolute_identity_path_required")
    for component in (path, *path.parents):
        require(not component.is_symlink(), "symlink_identity_refused")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024 * 1024, "identity_file_bound")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "identity_changed_during_read")
    value = digest.hexdigest()
    require(expected is None or value == expected, "identity_digest_mismatch")
    return value


def _origin(value: str) -> tuple[str, int]:
    parsed = urlsplit(value)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None and
            not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and
            not parsed.path and 1 <= parsed.port <= 65535, "literal_loopback_origin_required")
    return parsed.hostname, parsed.port


class PrimeSession:
    """Real HTTP, no proxy, DNS, redirects, response replay or credential export."""

    def __init__(self, origin: str, *, call_timeout_s: float = 30, timeout_s: float = 180) -> None:
        self.host, self.port = _origin(origin)
        require(0 < call_timeout_s <= 35 and 0 < timeout_s <= 300, "http_deadline_bound")
        self.origin = origin
        self.call_timeout_s = call_timeout_s
        self.deadline = time.monotonic() + timeout_s
        self.cookie = ""
        self.receipts: list[dict[str, Any]] = []

    def request(self, method: str, path: str, body: dict[str, Any] | None = None, *,
                authenticated: bool = True, headers: dict[str, str] | None = None,
                expected: tuple[int, ...] = (200,), raw: bool = False) -> Any:
        require(method in {"GET", "POST"} and path.startswith("/") and not path.startswith("//") and
                not any(char in path for char in ("\r", "\n", "#")), "request_route_refused")
        require(len(self.receipts) < 180, "http_call_limit")
        remaining = min(self.call_timeout_s, self.deadline - time.monotonic())
        require(remaining > 0, "http_deadline")
        request_headers = {"Accept": "application/json"}
        if authenticated:
            request_headers.update({"X-Prime-Request": "1", "Origin": self.origin})
            if self.cookie:
                request_headers["Cookie"] = self.cookie
        request_headers.update(headers or {})
        data = None if body is None else canonical_json(body).encode("utf-8")
        require(data is None or len(data) <= MAX_BODY, "request_too_large")
        if data is not None:
            request_headers.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=remaining)
        started = time.monotonic()
        receipt: dict[str, Any] = {"method": method, "path": path.split("?", 1)[0], "observed_at": to_utc_iso(utc_now())}
        self.receipts.append(receipt)
        try:
            connection.connect()
            transport_socket = connection.sock
            connection.request(method, path, data, request_headers)
            response = connection.getresponse()
            receipt["status"] = response.status
            require(not 300 <= response.status < 400, "redirect_refused")
            result_headers = response.getheaders()
            lengths = [value for name, value in result_headers if name.lower() == "content-length"]
            require(len(lengths) <= 1 and (not lengths or re.fullmatch(r"[0-9]{1,12}", lengths[0])), "invalid_response_length")
            known_length = int(lengths[0]) if lengths else None
            require(known_length is None or known_length <= MAX_BODY, "response_too_large")
            parts: list[bytes] = []
            size = 0
            deadline = min(self.deadline, started + self.call_timeout_s)
            while not response.isclosed():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "http_deadline")
                if transport_socket is not None:
                    transport_socket.settimeout(remaining)
                chunk = response.read1(min(65536, MAX_BODY + 1 - size))
                if not chunk:
                    break
                parts.append(chunk)
                size += len(chunk)
                require(size <= MAX_BODY, "response_too_large")
            require(time.monotonic() <= deadline, "http_deadline")
            require(known_length is None or size == known_length, "truncated_response")
            receipt["bytes"] = size
            require(response.status in expected, "unexpected_http_" + str(response.status))
            content = b"".join(parts)
            if raw:
                return response.status, result_headers, content
            result = bounded_json(content)
            require(result.get("ok") is not False or response.status >= 400, "nested_operation_failure")
            return result
        except (OSError, http.client.HTTPException) as error:
            receipt["outcome"] = "unknown" if method == "POST" else "failed"
            raise ObservationError("http_outcome_unknown" if method == "POST" else "http_unavailable") from error
        finally:
            receipt["duration_ms"] = round((time.monotonic() - started) * 1000)
            connection.close()

    def establish(self) -> None:
        _, headers, _ = self.request("GET", "/", authenticated=False, raw=True)
        values = [value for name, value in headers if name.lower() == "set-cookie"]
        cookies = SimpleCookie()
        seen = 0
        for value in values:
            parsed = SimpleCookie()
            parsed.load(value)
            if "echo_prime" in parsed:
                seen += 1
                cookies.load(value)
        require(seen == 1 and "echo_prime" in cookies, "native_session_missing_or_ambiguous")
        cookie = cookies["echo_prime"]
        require(re.fullmatch(r"[a-f0-9]{64}", cookie.value) and cookie["httponly"] and
                cookie["samesite"].lower() == "strict" and cookie["path"] == "/" and not cookie["domain"], "native_session_invalid")
        self.cookie = "echo_prime=" + cookie.value

    def workspace(self, operation: str, params: dict[str, Any], *, read: bool = False,
                  expected: tuple[int, ...] = (200,)) -> dict[str, Any]:
        require(re.fullmatch(r"[a-z.]{1,60}", operation), "workspace_operation_refused")
        path = "/api/prime/bots/workspace/" + operation
        if read and params:
            path += "?" + urlencode(params)
        return self.request("GET" if read else "POST", path, None if read else params, expected=expected)


def summarize_readiness(checks: dict[str, str]) -> dict[str, Any]:
    return {
        "engineering_passed": all(checks.get(name) == "PASS" for name in LOCAL_CHECKS),
        "release_verdict": "NOT_READY", "production_e2e": False, "signature_verified": False,
        "remaining_requirements": list(REMAINING),
    }


def _listener(pid: int, port: int) -> bool:
    sockets = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            sockets.add(target[8:-1])
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == f"0100007F:{port:04X}" and fields[3] == "0A" and fields[9] in sockets:
            return True
    return False


def verify_installed_python(root: Path, source_files: dict[str, str]) -> int:
    """Wheels omit source documentation; their executable module set must agree."""
    expected = {name.removeprefix("echo_adk/"): digest for name, digest in source_files.items()
                if name.startswith("echo_adk/") and name.endswith(".py")}
    require(bool(expected), "installed_module_manifest_empty")
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), "installed_symlink_refused")
        if path.is_file() and path.suffix == ".py":
            actual.add(path.relative_to(root).as_posix())
    require(actual == set(expected), "installed_module_set_mismatch")
    for relative, digest in expected.items():
        file_digest(root / relative, digest)
    return len(expected)


def verify_lane(lane: Path, running_sha256: str, manifest_sha256: str) -> dict[str, Any]:
    """Independently remeasure source archives, installed files, processes and ports."""
    file_digest(lane / "running.json", running_sha256)
    file_digest(lane / "runtime-files.json", manifest_sha256)
    running = bounded_json((lane / "running.json").read_bytes())
    manifest = bounded_json((lane / "runtime-files.json").read_bytes())
    require(running.get("scope") == "isolated_engineering_canary" and running.get("lane") == str(lane) and
            all(running.get(name) is False for name in ("production_activated", "production_state_copied", "production_credentials_loaded")), "isolated_lane_required")
    require(running.get("runtime_manifest_sha256") == manifest_sha256, "lane_manifest_binding")
    require(running.get("sdk_configured") is False and running.get("models_configured") is False and
            running.get("oauth_providers_configured") is False, "unreviewed_execution_authority")
    started = datetime.fromisoformat(running["started_at"].replace("Z", "+00:00"))
    require(started.tzinfo is not None and 0 <= (utc_now() - started).total_seconds() < running["ttl_s"] <= 1800, "lane_expired")
    identities: dict[str, Any] = {}
    for name in ("adk", "cli"):
        row = manifest[name]
        commit = row["source_sha"]
        require(re.fullmatch(r"[0-9a-f]{40}", commit) and commit == running["source"][name], "source_commit_binding")
        file_digest(Path(row["archive"]), row["archive_sha256"])
        file_hashes: dict[str, str] = {}
        with tarfile.open(row["archive"], "r:") as archive:
            require(archive.pax_headers.get("comment") == commit, "archive_commit_binding")
            for member in archive:
                relative = Path(member.name)
                require(not relative.is_absolute() and ".." not in relative.parts and (member.isdir() or member.isfile()), "archive_member_refused")
                if member.isfile():
                    require(member.size <= 32 * 1024 * 1024 and len(file_hashes) < 10000, "archive_bounds")
                    require(member.name not in file_hashes, "archive_duplicate")
                    stream = archive.extractfile(member)
                    require(stream is not None, "archive_member_missing")
                    file_hashes[member.name] = sha256_bytes(stream.read())
        require(file_hashes == row["files"], "archive_manifest_mismatch")
        for relative, digest in file_hashes.items():
            file_digest(Path(row["root"]) / relative, digest)
        if name == "adk":
            verify_installed_python(Path(row["installed"]), file_hashes)
        for relative, digest in row.get("artifacts", {}).items():
            file_digest(Path(row["root"]) / relative, digest)
        identities[name] = {"source_commit": commit, "archive_sha256": row["archive_sha256"],
                            "source_files": len(file_hashes), "artifact_files": len(row.get("artifacts", {})),
                            "runtime_manifest_sha256": sha256_json(row)}
    file_digest(Path(running["prime_config"]), running["prime_config_sha256"])
    for name in ("adk", "prime"):
        pid = running[name + "_pid"]
        require(type(pid) is int and pid > 1, "runtime_pid")
        proc = Path(f"/proc/{pid}")
        require(proc.stat().st_uid == os.getuid(), "runtime_owner_mismatch")
        argv = [item.decode("utf-8") for item in (proc / "cmdline").read_bytes().split(b"\0") if item]
        expected = running["prime_argv"] if name == "prime" else running["argv"]
        if name == "adk":
            require(argv[0] == running["python"] and argv[-len(expected):] == expected and
                    all(flag in {"-I", "-u", "-B"} for flag in argv[1:-len(expected)]), "runtime_argv_mismatch")
        else:
            require(argv == expected, "runtime_argv_mismatch")
        _, port = _origin(running[name + "_origin"])
        require(_listener(pid, port), "runtime_listener_identity")
        identities[name + "_process"] = {"pid": pid, "argv_sha256": sha256_json(argv),
                                         "executable_sha256": file_digest(Path(os.readlink(proc / "exe"))), "port": port}
    return {"source": identities, "running_sha256": running_sha256, "manifest_sha256": manifest_sha256,
            "prime_config_sha256": running["prime_config_sha256"]}


class WorkspaceObserver:
    def __init__(self, prime: PrimeSession, adk: PrimeSession) -> None:
        self.prime, self.adk = prime, adk
        self.nonce = uuid4().hex[:16]
        self.agent = "certprobe-" + self.nonce
        self.bots: list[str] = []
        self.agents: list[str] = []
        self.checks: dict[str, str] = {}
        self.details: dict[str, Any] = {}
        self.cleanup_errors: list[str] = []

    def _bot(self, value: dict[str, Any]) -> str:
        ident = value.get("bot_id")
        require(isinstance(ident, str) and re.fullmatch(r"[0-9a-f]{32}", ident), "invalid_bot_receipt")
        return ident

    def _paused(self, ident: str) -> dict[str, Any]:
        bot = self.prime.request("GET", "/api/prime/bots/" + ident)
        require(bot.get("bot_id") == ident and bot.get("status") == "paused" and
                bot.get("lease", {}).get("scopes") == [] and bot.get("daily_cost_cap_usd") == 0, "paused_empty_authority_required")
        return bot

    def auth(self) -> None:
        self.prime.request("GET", "/api/prime/bots/list", authenticated=False, expected=(403,))
        self.prime.establish()
        self.prime.request("GET", "/api/prime/bots/list", headers={"Origin": "https://untrusted.invalid"}, expected=(403,))
        self.prime.request("GET", "/api/prime/bots/list", headers={"X-Prime-Request": "0"}, expected=(403,))
        self.adk.request("GET", "/v2/health", authenticated=False, headers={"Host": "untrusted.invalid"}, expected=(403,))
        session = self.prime.request("GET", "/api/session")
        require(session.get("workspaceConfigured") is False, "native_mode_required")
        health = self.adk.request("GET", "/v2/health", authenticated=False)
        require(health.get("ok") is True and health.get("agents") == 0 and health.get("bots") == 0 and
                health.get("runs_active") == 0, "fresh_empty_lane_required")
        require(self.prime.request("GET", "/api/prime/bots/list").get("bots") == [], "fresh_empty_prime_required")
        self.details["authentication"] = "shipped native loopback session; external Workspace login not tested"
        self.checks["auth"] = "PASS"

    def lifecycle(self) -> None:
        definition = {"name": self.agent, "role": "researcher", "skills": [], "capabilities": [],
                      "lane": {"node": "local", "model": "qwen-local", "budget": {"max_calls": 2, "max_cost_usd": 0, "max_wall_s": 60}},
                      "max_steps": 2, "instruction": "Collector-owned paused definition. No model execution is authorized."}
        made = self.prime.request("POST", "/api/prime/adk/agents", definition, expected=(201,))
        require(made.get("name") == self.agent or made.get("agent", {}).get("name") == self.agent, "agent_receipt_mismatch")
        self.agents.append(self.agent)
        for label in ("A", "B"):
            bot = self.prime.request("POST", "/api/prime/bots/create", {"name": self.agent + " " + label,
                "agent": self.agent, "daily_cost_cap_usd": 0, "lease": {"scopes": [], "ttl_s": 60, "max_uses": 1}}, expected=(201,))
            ident = self._bot(bot)
            self.bots.append(ident)
            self._paused(ident)
        first, second = self.bots
        event = {"event_id": "probe-" + self.nonce, "source": "certforge-probe", "text": "Paused collector event; do not execute."}
        accepted = self.prime.request("POST", f"/api/prime/bots/{first}/events", event, expected=(202,))
        duplicate = self.prime.request("POST", f"/api/prime/bots/{first}/events", event, expected=(202,))
        require(accepted.get("duplicate") is False and duplicate.get("duplicate") is True and
                all(accepted.get(key) == duplicate.get(key) for key in ("runId", "messageId", "eventId")) and
                re.fullmatch(r"[0-9a-f]{32}", accepted.get("runId", "")), "event_idempotency_failed")
        run_id = accepted["runId"]
        run = self.prime.request("GET", "/api/prime/adk/runs/" + run_id)
        require(run.get("status") == "queued", "paused_event_executed")
        stop = self.prime.request("POST", f"/api/prime/bots/{first}/stop", {})
        require(stop.get("stopRequested") is True and run_id in stop.get("runIds", []), "stop_receipt_failed")
        terminal = self.prime.request("GET", "/api/prime/adk/runs/" + run_id)
        require(terminal.get("status") == "done" and terminal.get("done") is True and
                terminal.get("steps") == [] and terminal.get("spent", {}).get("calls") == 0 and
                terminal.get("spent", {}).get("cost_usd") == 0 and
                terminal.get("proof", {}).get("verdict") == "UNKNOWN", "queued_run_not_cancelled")
        resumed = self.prime.request("POST", f"/api/prime/bots/{second}/resume", {})
        require(resumed.get("status") == "idle", "resume_failed")
        self.prime.request("POST", f"/api/prime/bots/{second}/pause", {})
        self._paused(second)
        self.details["event"] = {"run_id": run_id, "message_id": accepted["messageId"], "duplicate_same_receipt": True, "cancelled_before_execution": True}
        self.checks["lifecycle"] = "PASS"

    def memory(self) -> None:
        first, second = self.bots[:2]
        initial = self.prime.workspace("memory.read", {"bot_id": first}, read=True)
        require(initial.get("revision") == 0 and initial.get("text") == "", "fresh_memory_required")
        text = "Collector note " + self.nonce
        saved = self.prime.workspace("memory.edit", {"bot_id": first, "text": text, "expected_revision": 0})
        require(saved.get("scope") == "bot:" + first and saved.get("revision") == 1 and saved.get("text") == text, "memory_write_mismatch")
        self.prime.workspace("memory.edit", {"bot_id": first, "text": "stale", "expected_revision": 0}, expected=(409,))
        readback = self.prime.workspace("memory.read", {"bot_id": first}, read=True)
        require(readback == saved, "memory_readback_mismatch")
        other = self.prime.workspace("memory.read", {"bot_id": second}, read=True)
        require(other.get("revision") == 0 and other.get("text") == "", "cross_bot_memory_leak")
        self.prime.workspace("memory.edit", {"bot_id": first, "text": text + " amended", "expected_revision": 1})
        restored = self.prime.workspace("memory.restore", {"bot_id": first, "revision": 1, "expected_revision": 2})
        require(restored.get("revision") == 3 and restored.get("text") == text, "memory_restore_mismatch")
        self.details["memory"] = {"bot_id": first, "revision": 3, "sha256": restored["sha256"], "other_bot_revision": 0}
        self.checks["memory"] = "PASS"

    def schedules(self) -> None:
        ident = self.bots[0]
        once_at = (utc_now() + timedelta(days=30)).strftime("%Y-%m-%dT09:15")
        specs = [{"once_at": once_at, "tz": "UTC", "missed": "skip"},
                 {"at": "09:15", "tz": "UTC", "monthdays": [1, 15], "missed": "once"},
                 {"at": "09:15", "tz": "UTC", "monthdays": [1], "months": [3, 9], "missed": "skip"},
                 {"cron": "15 9 * * 1-5", "tz": "America/New_York", "missed": "once"}]
        for spec in specs:
            self.prime.request("POST", f"/api/prime/bots/{ident}/update", {"schedule": spec})
            require(self._paused(ident).get("schedule") == spec, "schedule_readback_mismatch")
        self.prime.request("POST", f"/api/prime/bots/{ident}/update", {"schedule": {"cron": "* * * * * *", "tz": "UTC"}}, expected=(400,))
        require(self._paused(ident).get("schedule") == specs[-1], "invalid_schedule_mutated_bot")
        self.prime.request("POST", f"/api/prime/bots/{ident}/update", {"schedule": None})
        self.details["schedules"] = {"types": ["once", "monthly", "yearly", "cron"], "paused_only": True}
        self.checks["schedules"] = "PASS"

    def portability(self) -> None:
        exported = self.prime.workspace("team.export", {"bot_ids": self.bots[:2], "name": self.agent, "kind": "department", "include_memory": False})
        raw = exported.get("bundle_json", "")
        require(isinstance(raw, str) and sha256_bytes(raw.encode()) == exported.get("sha256"), "export_digest_mismatch")
        bundle = bounded_json(raw.encode())
        require(bundle.get("kind") == "department" and all(ident not in raw for ident in self.bots) and
                all(not (set(bot) & {"memory_text", "lease", "run_id", "bot_id"}) for bot in bundle["bots"]), "export_runtime_or_memory_leak")
        new_agent = self.agent + "-copy"
        names = {bot["ref"]: self.agent + " copy " + str(index) for index, bot in enumerate(bundle["bots"])}
        params = {"bundle_json": raw, "conflict": "reject", "rename_agents_json": canonical_json({self.agent: new_agent}),
                  "rename_bots_json": canonical_json(names)}
        preview = self.prime.workspace("team.preview", params)
        require(all(bot.get("status") == "paused" and bot.get("lease_scopes") == [] for bot in preview["bots"]), "import_preview_widens_authority")
        digest = preview.get("plan_sha256")
        require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest), "invalid_plan_digest")
        self.prime.workspace("team.import", {**params, "expected_plan_sha256": "0" * 64}, expected=(409,))
        require(len(self.prime.request("GET", "/api/prime/bots/list")["bots"]) == 2, "stale_plan_created_resources")
        imported = self.prime.workspace("team.import", {**params, "expected_plan_sha256": digest})
        require(imported.get("status") == "imported" and imported.get("plan_sha256") == digest and
                imported.get("created_agents") == [new_agent] and len(imported.get("bots", [])) == 2, "import_receipt_mismatch")
        self.agents.append(new_agent)
        for bot in imported["bots"]:
            ident = self._bot(bot)
            require(ident not in self.bots, "duplicate_import_identity")
            self.bots.append(ident)
            self._paused(ident)
        self.details["portability"] = {"export_sha256": exported["sha256"], "plan_sha256": digest, "import_id": imported["import_id"], "created_bots": 2, "included_memory": False}
        self.checks["portability"] = "PASS"

    def browser(self) -> None:
        first, second = self.bots[:2]
        for ident in (first, second):
            status = self.prime.workspace("browser.status", {"bot_id": ident}, read=True)
            require(status.get("available") is True and status.get("chromium_sandbox") is True and
                    status.get("network_policy", {}).get("allowed_origins") == [], "sandboxed_browser_unavailable")
            snapshot = self.prime.workspace("browser.act", {"bot_id": ident, "action": "snapshot", "timeout_ms": 15000})
            require(snapshot.get("bot_id") == ident and snapshot.get("status") == "ready" and snapshot.get("untrusted") is True, "browser_snapshot_failed")
        shot = self.prime.workspace("browser.act", {"bot_id": first, "action": "screenshot", "timeout_ms": 15000})
        artifact = shot["artifact"]["artifact_id"]
        value = self.prime.workspace("browser.artifact", {"bot_id": first, "artifact_id": artifact}, read=True)
        image = base64.b64decode(value["base64"], validate=True)
        require(image.startswith(b"\x89PNG\r\n\x1a\n") and len(image) == value.get("bytes") and
                sha256_bytes(image) == value.get("sha256"), "browser_artifact_mismatch")
        self.prime.workspace("browser.artifact", {"bot_id": second, "artifact_id": artifact}, read=True, expected=(404,))
        self.prime.workspace("browser.act", {"bot_id": first, "action": "navigate", "url": "https://collector-denied.invalid/", "timeout_ms": 5000}, expected=(403,))
        self.details["browser"] = {"bots": [first, second], "artifact_id": artifact, "sha256": value["sha256"], "bytes": len(image), "cross_bot_artifact_denied": True, "external_navigation_denied": True, "os_isolation": False}
        self.checks["browser"] = "PASS"

    def stability(self) -> None:
        observations = []
        for index in range(3):
            if index:
                time.sleep(1)
            health = self.adk.request("GET", "/v2/health", authenticated=False)
            require(health.get("ok") is True and health.get("runs_active") == 0, "active_work_in_no_model_lane")
            budgets = health.get("budgets", {})
            require(all(budgets.get(name) == 0 for name in ("reserved_usd", "spent_today_usd", "uncertain_charged_today_usd")), "unexpected_spend_or_hold")
            observations.append({"observed_at": to_utc_iso(utc_now()), "runs_active": 0, "spent_usd": 0, "reserved_usd": 0})
        market = self.prime.workspace("marketplace", {}, read=True)
        self.details["marketplace"] = {"configured": market.get("configured") is True,
                                      "providers": [{"id": row["id"], "available": row.get("available") is True} for row in market["providers"]],
                                      "consent_exercised": False}
        self.details["stability"] = observations
        self.checks["stability"] = "PASS"

    def cleanup(self) -> None:
        # A separate bounded cleanup allowance. Never infer IDs after an unknown
        # create/import result, and never retry a failed or uncertain deletion.
        self.prime.deadline = time.monotonic() + 90
        for ident in reversed(self.bots):
            try:
                self.prime.request("POST", f"/api/prime/bots/{ident}/stop", {})
                deleted = self.prime.request("POST", f"/api/prime/bots/{ident}/delete", {})
                require(deleted.get("botId") == ident and deleted.get("deleted") is True, "deletion_receipt_invalid")
            except (ObservationError, KeyError, OSError):
                self.cleanup_errors.append("bot_cleanup_unconfirmed:" + ident)
        if not self.cleanup_errors:
            for name in reversed(self.agents):
                try:
                    value = self.prime.request("POST", "/api/prime/adk/agents/" + name + "/delete", {})
                    require(value.get("deleted") is True, "agent_deletion_unconfirmed")
                except (ObservationError, KeyError, OSError):
                    self.cleanup_errors.append("agent_cleanup_unconfirmed:" + name)
        try:
            require(self.prime.request("GET", "/api/prime/bots/list").get("bots") == [], "remaining_bots")
            health = self.prime.request("GET", "/api/prime/bots/health")
            require(health.get("service", {}).get("runsActive") == 0 and
                    health.get("service", {}).get("agents") == 0, "remaining_active_runs_or_agents")
        except (ObservationError, KeyError, OSError):
            self.cleanup_errors.append("final_empty_lane_unconfirmed")
        self.checks["cleanup"] = "FAIL" if self.cleanup_errors else "PASS"


def observe(lane: Path, *, running_sha256: str, manifest_sha256: str) -> dict[str, Any]:
    try:
        identity = verify_lane(lane, running_sha256, manifest_sha256)
    except (ObservationError, OSError, KeyError, TypeError, ValueError) as error:
        return {"schema_version": "certforge.echo-workspace-observation.v1", "scope": "isolated_engineering_canary",
                "checks": {"identity": "FAIL"}, "failure": str(error) if isinstance(error, ObservationError) else "identity_unavailable",
                "http_receipts": [], "cleanup_errors": [], "running_sha256": running_sha256,
                "manifest_sha256": manifest_sha256, **summarize_readiness({"identity": "FAIL"})}
    running = bounded_json((lane / "running.json").read_bytes())
    observer = WorkspaceObserver(PrimeSession(running["prime_origin"]), PrimeSession(running["adk_origin"]))
    observer.checks["identity"] = "PASS"
    started = to_utc_iso(utc_now())
    failure = None
    try:
        for method in (observer.auth, observer.lifecycle, observer.memory, observer.schedules,
                       observer.portability, observer.browser, observer.stability):
            method()
    except (ObservationError, KeyError, TypeError, ValueError, OSError) as error:
        failure = str(error) if isinstance(error, ObservationError) else "unrecognized_operation_receipt"
    finally:
        if observer.prime.cookie:
            observer.cleanup()
        try:
            require(verify_lane(lane, running_sha256, manifest_sha256) == identity, "runtime_changed_during_observation")
        except (ObservationError, OSError, KeyError, ValueError):
            observer.checks["identity"] = "FAIL"
            failure = failure or "final_identity_unconfirmed"
    return {"schema_version": "certforge.echo-workspace-observation.v1", "scope": "isolated_engineering_canary",
            "observation_id": "echo-probe-" + observer.nonce, "started_at": started, "finished_at": to_utc_iso(utc_now()),
            "identity": identity, "checks": observer.checks, "observations": observer.details,
            "failure": failure, "cleanup_errors": observer.cleanup_errors,
            "http_receipts": observer.prime.receipts + observer.adk.receipts,
            "model_execution_requested": False, "runtime_model_counter_verified": False,
            "sdk_invoked": False, "provider_accounts_used": False,
            **summarize_readiness(observer.checks)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", type=Path, required=True)
    parser.add_argument("--running-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    require(args.output.is_absolute() and not args.output.exists(), "new_absolute_output_required")
    report = observe(args.lane, running_sha256=args.running_sha256, manifest_sha256=args.manifest_sha256)
    raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    with args.output.open("xb") as stream:
        os.chmod(args.output, 0o600)
        stream.write(raw)
    print(canonical_json({"output": str(args.output), "sha256": sha256_bytes(raw),
                          "engineering_passed": report["engineering_passed"], "release_verdict": "NOT_READY"}))
    return 0 if report["engineering_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
