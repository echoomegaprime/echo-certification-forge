"""Exercise sandbox ownership/cleanup through an inert real CLI process, never Docker."""
from __future__ import annotations

import json
import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from echo_certification_forge.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxError

FAKE_DOCKER = r'''import hashlib
import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
root = Path(sys.argv[1])
args = sys.argv[2:]
config = json.loads((root / "config.json").read_text(encoding="utf-8"))
(root / "events" / (str(time.monotonic_ns()) + "-" + str(os.getpid()) + "-" + uuid.uuid4().hex + ".json")).write_text(
    json.dumps({"args": args, "pid": os.getpid()}), encoding="utf-8")

def respond(code=0, output="", error=""):
    sys.stdout.write(output)
    sys.stdout.flush()
    sys.stderr.write(error)
    sys.stderr.flush()
    raise SystemExit(code)

def option(flag, default=None):
    return args[args.index(flag) + 1] if flag in args else default

def owned():
    path = root / "owned.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

def foreign():
    return {"Id": "f" * 64, "Name": "/foreign-container",
            "Config": {"Image": "sha256:" + "9" * 64,
                       "Labels": {"echo.certforge.journey_owner": "foreign-owner"}},
            "Image": "sha256:" + "9" * 64, "Created": datetime.now(UTC).isoformat(),
            "State": {"Running": True}}

def find(target):
    item = owned()
    if item and target in (item["Id"], item["Name"], item["Name"].lstrip("/")) and (root / "owned-live").exists():
        return item
    item = foreign()
    if target in (item["Id"], item["Name"], item["Name"].lstrip("/")) and (root / "foreign-live").exists():
        return item
    return None

action = args[0]
if action == "run":
    name = option("--name", "untracked-old-run")
    labels = {}
    for index, token in enumerate(args[:-1]):
        if token == "--label":
            key, _, value = args[index + 1].partition("=")
            labels[key] = value
    image = None
    for token in args:
        if (token.startswith("sha256:") or "@sha256:" in token):
            image = token
            break
    no_container = config.get("mode") == "no-container-hang" or config.get("mode") == "no-container"
    if not no_container:
        cid = hashlib.sha256(name.encode("utf-8")).hexdigest()
        item = {"Id": cid, "Name": "/" + name,
                "Config": {"Image": image, "Labels": labels},
                "Image": image if image.startswith("sha256:") else "sha256:" + hashlib.sha256(image.encode()).hexdigest(),
                "Created": datetime.now(UTC).isoformat(), "State": {"Running": True}}
        (root / "owned.json").write_text(json.dumps(item), encoding="utf-8")
        (root / "owned-live").touch()
        cidfile = option("--cidfile")
        if cidfile:
            (root / "receipt-path").write_text(cidfile, encoding="utf-8")
            receipt = config.get("receipt", "valid")
            if receipt != "missing":
                value = {"valid": cid, "wrong": "f" * 64,
                         "malformed": "not-a-container-id", "oversized": "c" * 4096}[receipt]
                Path(cidfile).write_text(value + "\n", encoding="ascii")
    if config.get("large_output"):
        sys.stdout.write("λ" * 100000 + "stdout-tail-marker🙂")
        sys.stdout.flush()
        sys.stderr.write("雪" * 50000 + "stderr-tail-marker✓")
        sys.stderr.flush()
    else:
        print("synthetic-journey-output", flush=True)
    if config.get("mode") in ("hang", "no-container-hang"):
        while not (root / "stop").exists():
            if not no_container and not (root / "owned-live").exists():
                break
            time.sleep(0.02)
    if config.get("auto_remove") and not no_container:
        (root / "owned-live").unlink(missing_ok=True)
    respond(config.get("exit_code", 0), error=config.get("run_stderr", ""))
elif action == "inspect":
    if config.get("inspect_failure"):
        respond(1, error="Cannot connect to the Docker daemon\n")
    item = find(args[-1])
    if item is None:
        respond(1, error="Error: No such object: " + args[-1] + "\n")
    if item["Id"] != "f" * 64:
        alteration = config.get("metadata")
        if alteration == "owner":
            item["Config"]["Labels"]["echo.certforge.journey_owner"] = "foreign-owner"
        elif alteration == "name":
            item["Name"] = "/foreign-container"
        elif alteration == "image":
            item["Config"]["Image"] = "sha256:" + "9" * 64
        elif alteration == "id":
            item["Id"] = "short-id"
        elif alteration == "content-image":
            item["Image"] = "sha256:" + "9" * 64
    respond(output=json.dumps(item) + "\n")
elif action == "rm":
    target = args[-1]
    if config.get("refuse_remove"):
        respond(1, error="Error: removal refused by synthetic daemon\n")
    item = find(target)
    if item is None:
        respond(1, error="Error: No such container: " + target + "\n")
    flag = "foreign-live" if item["Id"] == "f" * 64 else "owned-live"
    (root / flag).unlink()
    respond(output=item["Id"] + "\n")
elif action == "image":
    if args[1:4] != ["inspect", "--format", "{{json .Id}}"]:
        respond(96, error="unexpected image inspection shape")
    resolution = config.get("image_resolution", "valid")
    if resolution == "unavailable":
        respond(1, error="synthetic pinned image unavailable")
    if resolution == "malformed":
        respond(output="{not-json")
    if resolution == "short":
        respond(output=json.dumps("sha256:short"))
    if resolution == "wrong":
        respond(output=json.dumps("sha256:" + "8" * 64))
    respond(output=json.dumps(owned()["Image"]) + "\n")
elif action == "info":
    if config.get("unhealthy"):
        respond(1, error="Cannot connect to the Docker daemon\n")
    respond(output=json.dumps("29.5.0-inert") + "\n")
elif action == "ps":
    if config.get("unhealthy"):
        respond(1, error="Cannot connect to the Docker daemon\n")
    requested = option("--filter", "")
    name = requested.removeprefix("name=^/").removesuffix("$")
    item = owned()
    output = item["Id"] + "\n" if item and item["Name"] == "/" + name and (root / "owned-live").exists() else ""
    respond(output=output)
else:
    respond(96, error="unsupported inert fake Docker action: " + repr(args) + "\n")
'''


@pytest.fixture
def fake_docker(tmp_path):
    root = tmp_path / "inert-docker"
    root.mkdir()
    (root / "events").mkdir()
    (root / "foreign-live").touch()
    script = root / "fake_docker.py"
    script.write_text(FAKE_DOCKER, encoding="utf-8")
    (root / "config.json").write_text("{}", encoding="utf-8")

    class Transport:
        def __init__(self):
            self.command = (sys.executable, "-u", str(script), str(root))

        def configure(self, **values):
            (root / "config.json").write_text(json.dumps(values), encoding="utf-8")
            return self

        def sandbox(self, **values):
            return DockerSandbox(docker=self.command, timeout_s=5, **values)

        def events(self):
            return [json.loads(path.read_text(encoding="utf-8"))
                    for path in sorted((root / "events").glob("*.json"))]

        def actions(self, action):
            return [event["args"] for event in self.events() if event["args"][0] == action]

        def metadata(self):
            return json.loads((root / "owned.json").read_text(encoding="utf-8"))

        def assert_owned_absent(self):
            assert not (root / "owned-live").exists(), "attached CLI exited but daemon container remains"

        def assert_foreign_preserved(self):
            assert (root / "foreign-live").exists(), "cleanup removed a foreign container"
            assert not any(args[-1] == "f" * 64 for args in self.actions("rm"))

        @property
        def root(self):
            return root

    transport = Transport()
    yield transport
    # Preserve observed daemon state before this test-only teardown releases fake actors.
    (root / "fixture-cleanup-state.json").write_text(json.dumps({
        "owned_live": (root / "owned-live").exists(),
        "foreign_live": (root / "foreign-live").exists(),
        "removals": transport.actions("rm"),
    }), encoding="utf-8")
    # Only inert fixture state is touched; this also releases any hung fake CLI.
    (root / "stop").touch()
    (root / "owned-live").unlink(missing_ok=True)
    # Dispose only receipts created for this inert test, after assertions preserve failure evidence.
    for args in transport.actions("run"):
        if "--cidfile" in args:
            receipt = Path(args[args.index("--cidfile") + 1])
            if receipt.is_file() and not receipt.is_symlink():
                receipt.unlink()
            owner_path = receipt.parent / "owner.json"
            if owner_path.is_file() and not owner_path.is_symlink():
                owner = json.loads(owner_path.read_text(encoding="utf-8"))
                name = args[args.index("--name") + 1]
                if owner.get("name") == name and owner.get("cid_path") == str(receipt):
                    owner_path.unlink()
            try:
                receipt.parent.rmdir()  # succeeds only for this now-empty private directory
            except OSError:
                pass


def _owned_removal(transport):
    removals = transport.actions("rm")
    assert len(removals) == 1
    assert removals[0] == ["rm", "--force", transport.metadata()["Id"]]
    transport.assert_owned_absent()
    transport.assert_foreign_preserved()


def _run(transport, workdir, *, timeout=5, guard=None, **sandbox):
    return replace(transport.sandbox(**sandbox), timeout_s=timeout).run(
        ["inert-journey", "fixture-only"], workdir, guard)


@pytest.mark.parametrize("exit_code", [0, 7])
def test_normal_and_nonzero_exit_remove_only_the_verified_owned_cid(fake_docker, tmp_path, exit_code):
    fake_docker.configure(exit_code=exit_code)
    result = _run(fake_docker, tmp_path)
    assert result.returncode == exit_code
    assert result.timed_out is False
    assert "synthetic-journey-output" in result.stdout
    _owned_removal(fake_docker)


def test_timeout_cleans_daemon_container_in_addition_to_attached_cli(fake_docker, tmp_path):
    fake_docker.configure(mode="hang")
    result = _run(fake_docker, tmp_path, timeout=0.7)
    assert result.returncode == 124
    assert result.timed_out is True
    _owned_removal(fake_docker)


def test_guard_exception_is_preserved_after_exact_owned_cleanup(fake_docker, tmp_path):
    fake_docker.configure(mode="hang")

    class Revoked(RuntimeError):
        pass

    failure = Revoked("synthetic entitlement revoked")

    def guard():
        if (fake_docker.root / "owned-live").exists():
            raise failure

    with pytest.raises(Revoked) as caught:
        _run(fake_docker, tmp_path, guard=guard)
    assert caught.value is failure
    _owned_removal(fake_docker)


def test_missing_cid_receipt_can_recover_only_through_verified_unique_name(fake_docker, tmp_path):
    fake_docker.configure(receipt="missing")
    result = _run(fake_docker, tmp_path)
    assert result.returncode == 0
    run = fake_docker.actions("run")[0]
    name = run[run.index("--name") + 1]
    assert any(args[-1] == name for args in fake_docker.actions("inspect"))
    _owned_removal(fake_docker)


@pytest.mark.parametrize("receipt", ["wrong", "malformed", "oversized"])
def test_invalid_or_foreign_cid_receipt_never_authorizes_foreign_removal(fake_docker, tmp_path, receipt):
    fake_docker.configure(receipt=receipt)
    with pytest.raises(SandboxError):
        _run(fake_docker, tmp_path)
    fake_docker.assert_foreign_preserved()
    assert not fake_docker.actions("rm")


@pytest.mark.parametrize("metadata", ["owner", "name", "image", "id"])
def test_any_ownership_identity_mismatch_refuses_cleanup_and_cannot_return_success(
        fake_docker, tmp_path, metadata):
    fake_docker.configure(metadata=metadata)
    with pytest.raises(SandboxError):
        _run(fake_docker, tmp_path)
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()


@pytest.mark.parametrize("mode", [None, "hang"])
def test_cleanup_refusal_is_a_harness_error_even_after_zero_exit_or_timeout(
        fake_docker, tmp_path, mode):
    fake_docker.configure(mode=mode, refuse_remove=True)
    with pytest.raises(SandboxError):
        _run(fake_docker, tmp_path, timeout=0.7)
    assert (fake_docker.root / "owned-live").exists()
    fake_docker.assert_foreign_preserved()


def test_guard_exception_keeps_cleanup_failure_as_cause(fake_docker, tmp_path):
    fake_docker.configure(mode="hang", refuse_remove=True)
    failure = LookupError("synthetic guard failure")

    def guard():
        if (fake_docker.root / "owned-live").exists():
            raise failure

    with pytest.raises(LookupError) as caught:
        _run(fake_docker, tmp_path, guard=guard)
    assert caught.value is failure
    assert isinstance(caught.value.__cause__, SandboxError)
    fake_docker.assert_foreign_preserved()


def test_unknown_daemon_state_is_not_treated_as_container_absence(fake_docker, tmp_path):
    fake_docker.configure(inspect_failure=True, unhealthy=True)
    with pytest.raises(SandboxError):
        _run(fake_docker, tmp_path)
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()


def test_completed_auto_removal_requires_positive_daemon_and_anchored_name_absence(
        fake_docker, tmp_path):
    fake_docker.configure(auto_remove=True)
    result = _run(fake_docker, tmp_path)
    assert result.returncode == 0
    fake_docker.assert_owned_absent()
    assert fake_docker.actions("info")
    queries = fake_docker.actions("ps")
    assert queries
    name = fake_docker.actions("run")[0]
    name = name[name.index("--name") + 1]
    assert any("name=^/" + name + "$" in args for args in queries)
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()


def test_abort_before_any_cid_observation_is_unverified_even_with_healthy_absence(
        fake_docker, tmp_path):
    fake_docker.configure(mode="no-container-hang")
    with pytest.raises(SandboxError):
        _run(fake_docker, tmp_path, timeout=0.7)
    assert fake_docker.actions("inspect")
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()


@pytest.mark.parametrize("image", [DEFAULT_IMAGE, "registry.example/runtime@sha256:" + "a" * 64])
def test_owned_handshake_preserves_hardening_conditional_pull_and_private_receipt(
        fake_docker, tmp_path, image):
    fake_docker.configure()
    result = _run(fake_docker, tmp_path, image=image)
    assert result.returncode == 0
    args = fake_docker.actions("run")[0]
    name = args[args.index("--name") + 1]
    owner = args[args.index("--label") + 1]
    assert re.fullmatch(r"certforge-journey-[0-9a-f]{32}", name)
    assert owner == "echo.certforge.journey_owner=" + name.removeprefix("certforge-journey-")
    receipt = Path(args[args.index("--cidfile") + 1])
    assert not receipt.is_relative_to(tmp_path), "host ownership receipt must not be target-visible"
    assert not receipt.exists(), "verified completed run should remove its private ownership receipt"
    for flag, value in (("--network", "none"), ("--memory", "512m"), ("--memory-swap", "512m"),
                        ("--cpus", "1.0"), ("--pids-limit", "128"),
                        ("--user", "65534:65534"), ("--cap-drop", "ALL")):
        assert args[args.index(flag) + 1] == value
    assert "--read-only" in args and "--rm" in args
    assert "no-new-privileges" in args
    assert f"{tmp_path.resolve()}:/work:ro" in args
    assert "--pull=never" in args if image.startswith("sha256:") else "--pull=never" not in args
    _owned_removal(fake_docker)


def test_streamed_stdout_stderr_keep_bounded_correct_utf8_tails(fake_docker, tmp_path):
    fake_docker.configure(large_output=True)
    result = _run(fake_docker, tmp_path)
    assert result.returncode == 0
    assert len(result.stdout) <= 8000 and result.stdout.endswith("stdout-tail-marker🙂")
    assert len(result.stderr) <= 4000 and result.stderr.endswith("stderr-tail-marker✓")
    assert "\ufffd" not in result.stdout and "\ufffd" not in result.stderr
    _owned_removal(fake_docker)


def test_completed_launch_failure_without_container_keeps_nonzero_result_after_verified_absence(
        fake_docker, tmp_path):
    fake_docker.configure(mode="no-container", exit_code=125, run_stderr="synthetic missing local image")
    result = _run(fake_docker, tmp_path)
    assert result.returncode == 125 and result.timed_out is False
    assert "synthetic missing local image" in result.stderr
    assert fake_docker.actions("info") and fake_docker.actions("ps")
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()


REGISTRY_IMAGE = "registry.example/runtime@sha256:" + "a" * 64


def _assert_public_owner_receipt(transport, receipt, *, image=DEFAULT_IMAGE):
    run = transport.actions("run")[0]
    name = run[run.index("--name") + 1]
    assert set(receipt) == {"name", "owner_token", "image", "started_at", "cid_path"}
    assert receipt["name"] == name
    assert receipt["owner_token"] == name.removeprefix("certforge-journey-")
    assert receipt["image"] == image
    assert receipt["cid_path"] == run[run.index("--cidfile") + 1]
    assert receipt["started_at"]


def test_reflected_requested_image_does_not_authorize_a_different_local_content_id(
        fake_docker, tmp_path):
    fake_docker.configure(metadata="content-image")
    with pytest.raises(SandboxError) as caught:
        _run(fake_docker, tmp_path)
    observed = fake_docker.metadata()
    assert observed["Config"]["Image"] == DEFAULT_IMAGE
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()
    assert caught.value.container_absence_verified is False
    _assert_public_owner_receipt(fake_docker, caught.value.owner_receipt)


def test_registry_pin_is_resolved_to_actual_content_identity_before_owned_removal(
        fake_docker, tmp_path):
    fake_docker.configure()
    result = _run(fake_docker, tmp_path, image=REGISTRY_IMAGE)
    assert result.returncode == 0
    assert fake_docker.actions("image") == [
        ["image", "inspect", "--format", "{{json .Id}}", REGISTRY_IMAGE]]
    assert fake_docker.metadata()["Config"]["Image"] == REGISTRY_IMAGE
    assert fake_docker.metadata()["Image"].startswith("sha256:")
    _owned_removal(fake_docker)


@pytest.mark.parametrize("resolution", ["wrong", "unavailable", "malformed", "short"])
def test_registry_resolution_failure_or_mismatch_never_authorizes_deletion(
        fake_docker, tmp_path, resolution):
    fake_docker.configure(image_resolution=resolution)
    with pytest.raises(SandboxError) as caught:
        _run(fake_docker, tmp_path, image=REGISTRY_IMAGE)
    assert fake_docker.actions("image")
    assert not fake_docker.actions("rm")
    fake_docker.assert_foreign_preserved()
    assert caught.value.container_absence_verified is False
    _assert_public_owner_receipt(fake_docker, caught.value.owner_receipt, image=REGISTRY_IMAGE)


def test_adapter_retains_trusted_public_receipt_when_guard_sandboxerror_cleanup_is_refused(
        fake_docker, tmp_path):
    from echo_certification_forge.sandbox import sandboxed_journey_runner

    fake_docker.configure(mode="hang", refuse_remove=True)
    failure = SandboxError("synthetic trusted guard revoked")

    def guard():
        if (fake_docker.root / "owned-live").exists():
            raise failure

    passed, detail = sandboxed_journey_runner(fake_docker.sandbox(), guard)(
        ["inert-journey", "fixture-only"], tmp_path)
    assert passed is False
    assert detail["cleanup"]["container_absence_verified"] is False
    _assert_public_owner_receipt(fake_docker, detail["cleanup"]["owner_receipt"])
    assert isinstance(failure.__cause__, SandboxError)
    assert failure.owner_receipt == detail["cleanup"]["owner_receipt"]
    assert (fake_docker.root / "owned-live").exists()
    fake_docker.assert_foreign_preserved()


def test_partial_host_receipt_deletion_cannot_erase_structured_cleanup_evidence(
        fake_docker, tmp_path, monkeypatch):
    from echo_certification_forge import sandbox as module

    fake_docker.configure(mode="hang")
    failure = SandboxError("synthetic guard revoked before host cleanup")
    actual_rmtree = module.shutil.rmtree
    attempted = []

    def partial_rmtree(path, *args, **kwargs):
        selected = Path(path)
        owner_path = selected / "owner.json"
        if selected.name.startswith("certforge-sandbox-") and owner_path.is_file():
            attempted.append(selected)
            owner_path.unlink()  # model a real partially completed rmtree, not successful cleanup
            raise OSError("synthetic partial host receipt removal")
        return actual_rmtree(path, *args, **kwargs)

    def guard():
        if (fake_docker.root / "owned-live").exists():
            raise failure

    monkeypatch.setattr(module.shutil, "rmtree", partial_rmtree)
    passed, detail = module.sandboxed_journey_runner(fake_docker.sandbox(), guard)(
        ["inert-journey", "fixture-only"], tmp_path)
    assert passed is False
    assert attempted
    assert not (attempted[0] / "owner.json").exists()
    assert detail["cleanup"]["container_absence_verified"] is True
    _assert_public_owner_receipt(fake_docker, detail["cleanup"]["owner_receipt"])
    _owned_removal(fake_docker)


def test_adapter_does_not_traverse_or_reflect_receipts_from_arbitrary_guard_causes(
        fake_docker, tmp_path):
    from echo_certification_forge.sandbox import sandboxed_journey_runner

    class UntrustedCause(Exception):
        @property
        def owner_receipt(self):
            pytest.fail("adapter traversed arbitrary untrusted cause metadata")

        @property
        def container_absence_verified(self):
            pytest.fail("adapter accepted arbitrary cause cleanup claims")

    fake_docker.configure(mode="hang")
    failure = SandboxError("synthetic guard revoked")
    failure.__cause__ = UntrustedCause("untrusted-reflected-receipt-marker")

    def guard():
        if (fake_docker.root / "owned-live").exists():
            raise failure

    passed, detail = sandboxed_journey_runner(fake_docker.sandbox(), guard)(
        ["inert-journey", "fixture-only"], tmp_path)
    assert passed is False
    assert "cleanup" not in detail
    assert "untrusted-reflected-receipt-marker" not in json.dumps(detail)
    _owned_removal(fake_docker)
