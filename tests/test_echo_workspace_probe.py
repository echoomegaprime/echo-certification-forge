from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import tarfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from echo_certification_forge.echo_workspace_probe import (
    ObservationError, PrimeSession, bounded_json, file_digest, summarize_readiness,
    WorkspaceObserver, verify_installed_python, verify_lane, observe,
)


@pytest.fixture
def origin():
    class Handler(BaseHTTPRequestHandler):
        calls = []

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.calls.append((self.path, dict(self.headers)))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.end_headers()
                return
            if self.path == "/slow":
                time.sleep(0.15)
            self.send_response(200)
            if self.path == "/length-and-close":
                self.send_header("Content-Length", "11")
                self.send_header("Connection", "close")
            if self.path == "/truncated":
                self.send_header("Content-Length", "20")
                self.send_header("Connection", "close")
            if self.path == "/":
                self.send_header("Set-Cookie", "echo_prime=" + "a" * 64 + "; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            try:
                if self.path == "/trickle":
                    for char in b'{"ok":true}':
                        self.wfile.write(bytes([char]))
                        self.wfile.flush()
                        time.sleep(0.02)
                    return
                self.wfile.write(b'x' * (1024 * 1024 + 1) if self.path == "/large" else b'{"ok":true}')
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            self.calls.append((self.path, dict(self.headers)))
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", Handler.calls
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.mark.parametrize("value", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[]'])
def test_evidence_rejects_ambiguous_or_nonfinite_json(value):
    with pytest.raises(ObservationError):
        bounded_json(value)


@pytest.mark.parametrize("url", ["https://example.com", "http://localhost:1", "http://127.0.0.1:1/path", "http://user@127.0.0.1:1", "http://127.0.0.1:1?x=1"])
def test_local_observer_does_not_expand_network_authority(url):
    with pytest.raises(ObservationError):
        PrimeSession(url)


def test_real_http_cookie_stays_in_process_and_only_exact_origin(origin):
    url, calls = origin
    session = PrimeSession(url)
    session.establish()
    session.request("GET", "/api/prime/bots/list")
    assert calls[-1][1]["Cookie"] == "echo_prime=" + "a" * 64
    assert calls[-1][1]["Origin"] == url
    assert calls[-1][1]["X-Prime-Request"] == "1"
    assert "a" * 64 not in json.dumps(session.receipts)
    with pytest.raises(ObservationError):
        session.request("GET", "http://untrusted.invalid/")


def test_redirect_never_follows_or_leaks_cookie(origin):
    url, calls = origin
    session = PrimeSession(url)
    with pytest.raises(ObservationError, match="redirect"):
        session.request("GET", "/redirect")
    assert all(path != "/must-not-follow" for path, _ in calls)


def test_body_limit_and_deadline_are_real_network_limits(origin):
    url, _ = origin
    with pytest.raises(ObservationError, match="response_too_large"):
        PrimeSession(url).request("GET", "/large")
    started = time.monotonic()
    with pytest.raises(ObservationError):
        PrimeSession(url, call_timeout_s=0.03).request("GET", "/slow")
    assert time.monotonic() - started < 0.5


def test_body_trickle_cannot_extend_absolute_deadline(origin):
    url, _ = origin
    started = time.monotonic()
    with pytest.raises(ObservationError):
        PrimeSession(url, call_timeout_s=0.06).request("GET", "/trickle")
    assert time.monotonic() - started < 0.18


def test_uncertain_mutation_is_not_replayed(origin):
    url, calls = origin
    session = PrimeSession(url)
    with pytest.raises(ObservationError, match="http_outcome_unknown"):
        session.request("POST", "/api/prime/bots/create", {"name": "one attempt"})
    assert len(calls) == 1
    assert session.receipts[-1]["outcome"] == "unknown"


def test_complete_content_length_body_survives_server_close(origin):
    url, _ = origin
    assert PrimeSession(url).request("GET", "/length-and-close") == {"ok": True}


def test_parseable_but_truncated_body_is_not_success(origin):
    url, _ = origin
    with pytest.raises(ObservationError, match="truncated_response"):
        PrimeSession(url).request("GET", "/truncated")


def test_file_identity_refuses_symlink_and_changed_bytes(tmp_path: Path):
    file = tmp_path / "source.py"
    file.write_bytes(b"approved")
    digest = hashlib.sha256(b"approved").hexdigest()
    assert file_digest(file, digest) == digest
    file.write_bytes(b"changed")
    with pytest.raises(ObservationError, match="identity"):
        file_digest(file, digest)
    link = tmp_path / "link.py"
    link.symlink_to(file)
    with pytest.raises(ObservationError, match="symlink"):
        file_digest(link)


def test_local_observations_cannot_turn_into_production_attestation():
    report = summarize_readiness({name: "PASS" for name in ("identity", "auth", "lifecycle", "memory", "schedules", "portability", "browser", "stability", "cleanup")})
    assert report["engineering_passed"] is True
    assert report["release_verdict"] == "NOT_READY"
    assert report["production_e2e"] is False
    assert report["signature_verified"] is False
    assert {"trusted_collector_admission", "real_sdk_journey", "oauth_consent_and_read", "external_owner_acceptance", "bounded_autonomous_turn"} <= set(report["remaining_requirements"])


def test_missing_local_check_is_not_a_partial_green():
    report = summarize_readiness({"identity": "PASS", "cleanup": "PASS"})
    assert report["engineering_passed"] is False


def test_installed_wheel_verifies_all_modules_but_not_unshipped_docs(tmp_path: Path):
    root = tmp_path / "echo_adk"
    root.mkdir()
    (root / "__init__.py").write_bytes(b"# module\n")
    manifest = {"echo_adk/__init__.py": hashlib.sha256(b"# module\n").hexdigest(),
                "echo_adk/README.md": hashlib.sha256(b"source documentation").hexdigest()}
    assert verify_installed_python(root, manifest) == 1
    (root / "unexpected.py").write_bytes(b"# unapproved\n")
    with pytest.raises(ObservationError, match="installed_module_set"):
        verify_installed_python(root, manifest)


def test_identity_failure_records_no_network_or_mutation(tmp_path: Path):
    result = observe(tmp_path, running_sha256="a" * 64, manifest_sha256="b" * 64)
    assert result["checks"] == {"identity": "FAIL"}
    assert result["http_receipts"] == []
    assert result["release_verdict"] == "NOT_READY"


@pytest.fixture
def measured_lane(tmp_path: Path, origin):
    """Synthetic source fixture measured against an actual owned HTTP listener.

    This does not start Echo or issue an attestation. Both declared process
    roles intentionally point to the controlled test server's real process.
    """
    url, _ = origin
    lane = tmp_path / "lane"
    lane.mkdir()
    manifest = {}
    for name, relative in (("adk", "echo_adk/__init__.py"), ("cli", "src/main.ts")):
        root = tmp_path / name
        path = root / relative
        path.parent.mkdir(parents=True)
        content = b"# synthetic source identity fixture\n"
        path.write_bytes(content)
        commit = ("a" if name == "adk" else "c") * 40
        archive_path = tmp_path / (name + ".tar")
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as archive:
            member = tarfile.TarInfo(relative)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        row = {"root": str(root), "source_sha": commit, "archive": str(archive_path),
               "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
               "files": {relative: hashlib.sha256(content).hexdigest()}}
        if name == "adk":
            installed = tmp_path / "installed"
            installed.mkdir()
            (installed / "__init__.py").write_bytes(content)
            row["installed"] = str(installed)
        else:
            built = root / "dist/main.js"
            built.parent.mkdir()
            built.write_bytes(b"// synthetic built identity\n")
            row["artifacts"] = {"dist/main.js": hashlib.sha256(built.read_bytes()).hexdigest()}
        manifest[name] = row
    config = lane / "prime.json"
    config.write_text("{}")
    argv = [part.decode() for part in Path(f"/proc/{os.getpid()}/cmdline").read_bytes().split(b"\0") if part]
    running = {"scope": "isolated_engineering_canary", "lane": str(lane),
               "production_activated": False, "production_state_copied": False, "production_credentials_loaded": False,
               "sdk_configured": False, "models_configured": False, "oauth_providers_configured": False,
               "started_at": datetime.now(timezone.utc).isoformat(), "ttl_s": 60,
               "source": {name: row["source_sha"] for name, row in manifest.items()},
               "prime_config": str(config), "prime_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
               "adk_pid": os.getpid(), "prime_pid": os.getpid(), "python": argv[0], "argv": argv[1:], "prime_argv": argv,
               "adk_origin": url, "prime_origin": url}

    def pin():
        manifest_raw = json.dumps(manifest).encode()
        (lane / "runtime-files.json").write_bytes(manifest_raw)
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        running["runtime_manifest_sha256"] = manifest_sha
        running_raw = json.dumps(running).encode()
        (lane / "running.json").write_bytes(running_raw)
        return hashlib.sha256(running_raw).hexdigest(), manifest_sha

    return lane, running, manifest, pin


def test_identity_reads_actual_archive_installed_bytes_process_and_listener(measured_lane):
    lane, running, _, pin = measured_lane
    identity = verify_lane(lane, *pin())
    assert identity["source"]["adk_process"]["pid"] == os.getpid()
    assert identity["source"]["prime_process"]["port"] == int(running["prime_origin"].rsplit(":", 1)[1])
    assert identity["source"]["adk"]["source_files"] == 1
    assert identity["source"]["cli"]["artifact_files"] == 1


@pytest.mark.parametrize("change", ["source", "built", "installed", "configuration", "argv", "expired", "sdk", "archive_commit"])
def test_measured_identity_rejects_drift_in_each_independent_binding(measured_lane, change):
    lane, running, manifest, pin = measured_lane
    pins = pin()
    if change == "source":
        (Path(manifest["adk"]["root"]) / "echo_adk/__init__.py").write_bytes(b"changed source")
    elif change == "built":
        (Path(manifest["cli"]["root"]) / "dist/main.js").write_bytes(b"changed build")
    elif change == "installed":
        (Path(manifest["adk"]["installed"]) / "unexpected.py").write_bytes(b"# unapproved module")
    elif change == "configuration":
        Path(running["prime_config"]).write_text('{"unexpected":true}')
    elif change == "argv":
        running["prime_argv"] = ["unrelated-process"]
        pins = pin()
    elif change == "expired":
        running["started_at"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        pins = pin()
    elif change == "sdk":
        running["sdk_configured"] = True
        pins = pin()
    elif change == "archive_commit":
        manifest["adk"]["source_sha"] = running["source"]["adk"] = "b" * 40
        pins = pin()
    with pytest.raises(ObservationError):
        verify_lane(lane, *pins)


def test_owned_bound_socket_is_not_a_listening_service(measured_lane):
    lane, running, _, pin = measured_lane
    with socket.socket() as bound:
        bound.bind(("127.0.0.1", 0))
        running["adk_origin"] = f"http://127.0.0.1:{bound.getsockname()[1]}"
        with pytest.raises(ObservationError, match="runtime_listener_identity"):
            verify_lane(lane, *pin())


def test_real_auth_failure_stays_failed_and_records_the_observed_http(measured_lane):
    lane, _, _, pin = measured_lane
    running_sha, manifest_sha = pin()
    report = observe(lane, running_sha256=running_sha, manifest_sha256=manifest_sha)
    # The controlled server returns 200 to unauthenticated requests, so this
    # real negative control fails. A healthy listener cannot become a PASS.
    assert report["failure"] == "unexpected_http_200"
    assert report["engineering_passed"] is False
    assert report["checks"] == {"identity": "PASS"}
    assert report["http_receipts"][0]["status"] == 200
    assert report["release_verdict"] == "NOT_READY"


@pytest.mark.parametrize("uncertain", [False, True])
def test_cleanup_uses_only_acknowledged_ids_and_never_retries_unknown_delete(uncertain):
    ident = "a" * 32
    state = {"bots": [ident], "agents": 1, "calls": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, value):
            raw = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            state["calls"].append(self.path)
            if self.path == f"/api/prime/bots/{ident}/stop":
                self.reply({"stopRequested": True})
            elif self.path == f"/api/prime/bots/{ident}/delete":
                state["bots"].remove(ident)
                if uncertain:
                    self.close_connection = True
                    return
                self.reply({"botId": ident, "deleted": True})
            elif self.path == "/api/prime/adk/agents/owned/delete":
                state["agents"] = 0
                self.reply({"deleted": True})
            else:
                raise AssertionError("unexpected resource mutation")

        def do_GET(self):
            self.reply({"bots": list(state["bots"])} if self.path.endswith("/list") else
                       {"service": {"agents": state["agents"], "runsActive": 0}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = PrimeSession(f"http://127.0.0.1:{server.server_port}")
    observer = WorkspaceObserver(session, session)
    observer.bots, observer.agents = [ident], ["owned"]
    try:
        observer.cleanup()
        assert state["calls"].count(f"/api/prime/bots/{ident}/delete") == 1
        assert observer.checks["cleanup"] == ("FAIL" if uncertain else "PASS")
        if uncertain:
            assert state["agents"] == 1
            assert "/api/prime/adk/agents/owned/delete" not in state["calls"]
            assert observer.cleanup_errors == ["bot_cleanup_unconfirmed:" + ident, "final_empty_lane_unconfirmed"]
        else:
            assert state["agents"] == 0 and observer.cleanup_errors == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
