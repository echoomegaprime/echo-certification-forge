import copy
import dataclasses
import json

import pytest

from echo_certification_forge.canonical import sha256_bytes
from echo_certification_forge.runtime_identity import load_runtime_profile, measured_environment
from echo_certification_forge.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxResult
from echo_certification_forge.signing import Ed25519VerdictSigner
from test_runtime_job_binding import runtime_api

SHA = "a" * 40
REPO = "https://github.com/example/fielddesk.git"
IMAGE = "sha256:" + "e" * 64
JOURNEY = ["python3", "-B", "scripts/certforge_journey.py"]


def config(tenant="tenant-a", project="project-a"):
    return {"schema_version": "certforge.runtime.v2", "project_bindings": [{
        "binding_id": "fielddesk-exact", "tenant_id": tenant, "project_id": project,
        "repository": REPO, "source_commit": SHA,
        "dependencies": {"package-lock.json": sha256_bytes(b"locked dependencies\n")},
        "sandbox": {"image": IMAGE, "memory": "2g", "timeout_s": 120}, "journey": JOURNEY,
    }]}


def profile(tmp_path, value):
    path = tmp_path / "operator.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return load_runtime_profile(path)


def spec(**changes):
    return dict({"type": "git", "url": REPO, "ref": SHA, "source_commit": SHA}, **changes)


def test_operator_selects_exact_source_and_keeps_default_isolation(tmp_path, manifest):
    catalog = profile(tmp_path, config())
    selected = catalog.select("tenant-a", "project-a", spec())
    assert selected.sandbox.image == IMAGE
    assert selected.sandbox.memory == "2g"
    selected.check_execution(selected.sandbox, JOURNEY)
    assert catalog.sandbox == DockerSandbox()
    assert catalog.sandbox.image == DEFAULT_IMAGE
    assert catalog.select("tenant-b", "project-a", spec()) is catalog
    assert catalog.select("tenant-a", "project-b", spec()) is catalog
    assert catalog.select("tenant-a", "project-a", spec(url="https://github.com/example/other.git")) is catalog
    base = measured_environment(manifest=manifest, sandbox=selected.sandbox, journey=JOURNEY)
    bound = measured_environment(manifest=manifest, sandbox=selected.sandbox, journey=JOURNEY,
                                 runtime_binding_sha256=selected.binding.digest)
    assert base.identity_digest != bound.identity_digest
    changed = config()
    changed["project_bindings"][0]["dependencies"]["package-lock.json"] = "f" * 64
    replacement = profile(tmp_path, changed).select("tenant-a", "project-a", spec())
    assert selected.binding.digest != replacement.binding.digest


@pytest.mark.parametrize("change", [{"ref": "main"}, {"source_commit": "b" * 40}, {"type": "local"}])
def test_configured_project_rejects_unadmitted_source(tmp_path, change):
    with pytest.raises(ValueError, match="runtime_binding_target_mismatch"):
        profile(tmp_path, config()).select("tenant-a", "project-a", spec(**change))


@pytest.mark.parametrize("change", [
    {"sandbox": {"image": "python:latest"}}, {"sandbox": {"image": IMAGE, "user": "0:0"}},
    {"sandbox": {"image": IMAGE, "network": "host"}}, {"sandbox": {"image": IMAGE, "extra_env": {}}},
    {"dependencies": {"../outside": "a" * 64}}, {"dependencies": {"C:/outside": "a" * 64}},
    {"dependencies": {}}, {"journey": None}, {"source_commit": "main"},
    {"dependencies": {"bad\u0000path": "a" * 64}},
    {"repository": "https://user:password@example.test/repo"}, {"unexpected": True},
])
def test_operator_binding_rejects_unsafe_or_incomplete_input(tmp_path, change):
    value = config()
    value["project_bindings"][0].update(change)
    with pytest.raises(ValueError):
        profile(tmp_path, value)


def test_duplicate_admission_and_v1_extension_rejected(tmp_path):
    value = config()
    value["project_bindings"].append(copy.deepcopy(value["project_bindings"][0]))
    with pytest.raises(ValueError, match="runtime_binding_duplicate"):
        profile(tmp_path, value)
    value = config()
    value["schema_version"] = "certforge.runtime.v1"
    with pytest.raises(ValueError, match="runtime_profile_fields_invalid"):
        profile(tmp_path, value)


def test_bound_catalog_preserves_operator_mismatch_before_tenant_selection(tmp_path, store, manifest, monkeypatch):
    from echo_certification_forge import run_worker

    catalog = profile(tmp_path, config())
    monkeypatch.setattr(run_worker, "acquire_target", lambda *args: pytest.fail("operator drift must not acquire"))
    result = run_worker.run("not-created", "tenant-a", spec(), store=store,
        manifest=manifest, signer=Ed25519VerdictSigner.generate(),
        sandbox=dataclasses.replace(catalog.sandbox, memory="7g"),
        runtime_profile=catalog, journey=JOURNEY)
    assert result == {"run_id": "not-created", "error": "runtime_operator_profile_mismatch"}


def test_subscriber_governance_guard_closes_its_real_sqlite_read(runtime_api, monkeypatch):
    import sqlite3
    from echo_certification_forge import run_worker

    _client, context, headers = runtime_api
    connect = sqlite3.connect
    opened = []

    def tracked_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(run_worker.sqlite3, "connect", tracked_connect)
    try:
        result = run_worker.run("governance-close-guard", headers["X-Tenant-ID"], spec(),
            store=context.store, manifest=context.manifest, signer=Ed25519VerdictSigner.generate())
        assert result["error"] == "subscriber_governance_required"
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            opened[0].execute("SELECT 1")
    finally:
        for connection in opened:
            connection.close()


@pytest.mark.parametrize("content", [b"changed", b"x" * (2 * 1024 * 1024 + 1), None], ids=["changed", "too-large", "missing"])
def test_dependency_mismatch_or_missing_file_denied(tmp_path, content):
    selected = profile(tmp_path, config()).select("tenant-a", "project-a", spec())
    if content is not None:
        (tmp_path / "package-lock.json").write_bytes(content)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        selected.binding.check_source(tmp_path, SHA)


@pytest.mark.parametrize("tampered", [False, True])
def test_api_and_worker_select_same_profile_and_fence_dependencies(runtime_api, tmp_path, monkeypatch, tampered):
    from echo_certification_forge import run_worker
    from echo_certification_forge.acquisition import acquire_target
    from echo_certification_forge.models import TargetIdentity, declared_target_identity_digest

    client, context, headers = runtime_api
    context.certification_environment = {}
    source = tmp_path / "source"
    source.mkdir()
    (source / "package-lock.json").write_bytes(b"changed" if tampered else b"locked dependencies\n")
    acquired = dataclasses.replace(acquire_target({"type": "local", "path": str(source)}, tmp_path / "unused"),
                                   target_type="git", canonical_ref=REPO + "@" + SHA, source_commit=SHA)
    target = TargetIdentity(headers["X-Tenant-ID"], "git", acquired.canonical_ref, acquired.artifact_sha256, source_commit=SHA)
    project = client.post("/v1/subscriber/projects", headers=headers, json={
        "slug": "fielddesk", "name": "FieldDesk fixture", "target_reference": target.canonical_ref,
    }).json()["project_id"]
    context.runtime_profile = profile(tmp_path, config(headers["X-Tenant-ID"], project))
    target_body = {"target_type": "git", "reference": target.canonical_ref, "url": REPO, "ref": SHA,
                   "source_commit": SHA, "identity_digest": declared_target_identity_digest(
                       headers["X-Tenant-ID"], "git", None, SHA, target.canonical_ref)}
    body = {"journey": JOURNEY, "project_id": project, "target": target_body}
    response = client.post("/v1/subscriber/runtime/environment", headers=headers, json=body)
    assert response.status_code == 200, response.text
    declaration = response.json()["submit_environment"]
    assert declaration["runner_image_digest"] == IMAGE
    wrong = copy.deepcopy(body)
    wrong["target"]["ref"] = "b" * 40
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json=wrong).status_code == 422
    wrong = dict(body, project_id="other-project")
    assert client.post("/v1/subscriber/runtime/environment", headers=headers, json=wrong).status_code == 404
    assert not context.store.list_runs(headers["X-Tenant-ID"])
    submitted = client.post("/v1/certifications", headers=headers, json={
        "tenant_id": headers["X-Tenant-ID"], "project_id": project, "target": target_body,
        "environment": declaration, "policy_version": context.manifest.manifest_id,
        "idempotency_key": "bound-fielddesk-fixture", "journey": JOURNEY,
    })
    assert submitted.status_code == 201, submitted.text
    monkeypatch.setattr(run_worker, "acquire_target", lambda *args: acquired)
    executions = []
    monkeypatch.setattr(DockerSandbox, "run", lambda self, argv, *args:
                        executions.append((self.image, self.memory, argv)) or SandboxResult(0, "fixture", "", False))
    result = run_worker.run(submitted.json()["run_id"], headers["X-Tenant-ID"], spec(),
        store=context.store, manifest=context.manifest, signer=Ed25519VerdictSigner.generate(),
        subscribers=context.subscribers, sandbox=context.runtime_profile.sandbox,
        runtime_profile=context.runtime_profile, journey=JOURNEY)
    if not SECURE_READER:
        # Missing descriptor capabilities must deny even clean admitted bytes.
        assert result["error"] == "runtime_binding_source_mismatch"
        assert not executions
    elif tampered:
        assert result["error"] == "runtime_binding_source_mismatch"
        assert not executions
    else:
        assert "error" not in result, result
        assert result["environment_identity_digest"] == declaration["identity_digest"]
        assert result["release_verdict"] == "NOT_READY"  # Fixture transport cannot certify production.
        assert executions == [(IMAGE, "2g", JOURNEY)]


@pytest.mark.parametrize("extra", [{"project_id": "project-a"}, {"target": {
    "target_type": "git", "reference": REPO, "identity_digest": "a" * 64}}, {"profile": "fielddesk"}])
def test_resolution_rejects_partial_binding_or_caller_profile(runtime_api, extra):
    client, _context, headers = runtime_api
    assert client.post("/v1/subscriber/runtime/environment", headers=headers,
                       json=dict({"journey": JOURNEY}, **extra)).status_code == 422


# The actual dependency reader is descriptor-based on supported POSIX hosts.
# Windows must reject this security boundary rather than silently follow paths.
import os
import stat
from collections import Counter

SECURE_READER = (
    all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
    and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)
requires_secure_reader = pytest.mark.skipif(
    not SECURE_READER, reason="secure dependency reader requires POSIX descriptor capabilities")


def _binding(tmp_path, content=b"locked dependencies\n", *, name="package-lock.json"):
    value = config()
    value["project_bindings"][0]["dependencies"] = {name: sha256_bytes(content)}
    return profile(tmp_path, value).select("tenant-a", "project-a", spec()).binding


def _patch_os(monkeypatch, module, name, replacement):
    """Keep genuine capability membership when instrumenting a supported OS function."""
    original = getattr(module.os, name)
    for capability in ("supports_dir_fd", "supports_follow_symlinks", "supports_fd"):
        supported = getattr(module.os, capability, set())
        if original in supported:
            monkeypatch.setattr(module.os, capability, (supported - {original}) | {replacement})
    monkeypatch.setattr(module.os, name, replacement)


@requires_secure_reader
@pytest.mark.parametrize("size", [0, 20, 2 * 1024 * 1024])
def test_reader_hashes_actual_regular_single_link_bytes_through_exact_limit(tmp_path, size):
    data = b"x" * size
    binding = _binding(tmp_path, data)
    (tmp_path / "package-lock.json").write_bytes(data)
    assert binding.check_source(tmp_path, SHA) is None


def test_reader_source_commit_mismatch_is_rejected_before_any_input_open(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("wrong source commit reached dependency input")

    _patch_os(monkeypatch, module, "open", forbidden)
    with pytest.raises(ValueError, match="runtime_binding_source_mismatch"):
        binding.check_source(tmp_path, "f" * 40)


@pytest.mark.skipif(SECURE_READER, reason="control applies to hosts missing mandatory descriptor support")
def test_unsupported_reader_platform_fails_closed_without_path_read(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b"locked dependencies\n")

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported secure-reader platform tried opening input")

    _patch_os(monkeypatch, module, "open", forbidden)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)


@requires_secure_reader
@pytest.mark.parametrize("position", ["root", "root-ancestor", "component", "file"])
def test_reader_rejects_symlinks_before_any_path_resolution(tmp_path, monkeypatch, position):
    binding = _binding(tmp_path, name="nested/package-lock.json" if position == "component" else "package-lock.json")
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "package-lock.json").write_bytes(b"locked dependencies\n")
    root = actual
    if position == "root":
        root = tmp_path / "root-link"
        root.symlink_to(actual, target_is_directory=True)
    elif position == "root-ancestor":
        parent = tmp_path / "real-parent"
        parent.mkdir()
        actual.rename(parent / "source")
        alias = tmp_path / "parent-link"
        alias.symlink_to(parent, target_is_directory=True)
        root = alias / "source"
    elif position == "component":
        (actual / "nested").symlink_to(actual, target_is_directory=True)
    else:
        (actual / "package-lock.json").rename(actual / "real-lock")
        (actual / "package-lock.json").symlink_to(actual / "real-lock")

    def forbidden_resolution(*args, **kwargs):
        pytest.fail("reader resolved a symlink before rejecting it")

    monkeypatch.setattr(type(root), "resolve", forbidden_resolution)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(root, SHA)


@requires_secure_reader
def test_reader_rejects_parent_components_in_supplied_root_before_open(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    root = tmp_path / "source"
    root.mkdir()

    def forbidden(*args, **kwargs):
        pytest.fail("parent traversal reached os.open")

    _patch_os(monkeypatch, module, "open", forbidden)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(root / ".." / "source", SHA)


@requires_secure_reader
@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_reader_rejects_nonregular_inputs_without_blocking(tmp_path, monkeypatch, kind):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    path = tmp_path / "package-lock.json"
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    actual_open = module.os.open
    final_opens = []

    def guarded_open(name, flags, *args, **kwargs):
        if str(name) == "package-lock.json":
            final_opens.append(flags)
            assert flags & os.O_NOFOLLOW
            assert flags & os.O_NONBLOCK  # fail before opening a FIFO if the guard regresses
        return actual_open(name, flags, *args, **kwargs)

    _patch_os(monkeypatch, module, "open", guarded_open)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)
    # A pre-open lstat rejection is also safe; every actual final open was guarded.
    assert all(flags & os.O_NONBLOCK for flags in final_opens)


@requires_secure_reader
@pytest.mark.parametrize("kind", [stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFDIR])
def test_reader_checks_actual_descriptor_type_before_reading(tmp_path, monkeypatch, kind):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b"locked dependencies\n")
    actual_fstat = module.os.fstat
    observed = []

    class TypeChanged:
        def __init__(self, original):
            self.original = original
            self.st_mode = kind | stat.S_IMODE(original.st_mode)

        def __getattr__(self, name):
            return getattr(self.original, name)

    def changed_fstat(fd):
        result = actual_fstat(fd)
        if stat.S_ISREG(result.st_mode):
            observed.append(fd)
            return TypeChanged(result)
        return result

    _patch_os(monkeypatch, module, "fstat", changed_fstat)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)
    assert observed


@requires_secure_reader
def test_reader_rejects_hardlinked_dependency(tmp_path):
    binding = _binding(tmp_path)
    path = tmp_path / "package-lock.json"
    path.write_bytes(b"locked dependencies\n")
    os.link(path, tmp_path / "second-link")
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)


@requires_secure_reader
def test_reader_rejects_one_byte_over_limit_even_when_declared_hash_matches(tmp_path):
    data = b"x" * (2 * 1024 * 1024 + 1)
    binding = _binding(tmp_path, data)
    (tmp_path / "package-lock.json").write_bytes(data)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)


@requires_secure_reader
def test_reader_uses_nofollow_nonblocking_flags_for_the_regular_file(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b"locked dependencies\n")
    actual_open = module.os.open
    observed = []

    def record_open(name, flags, *args, **kwargs):
        if str(name) == "package-lock.json":
            observed.append(flags)
        return actual_open(name, flags, *args, **kwargs)

    _patch_os(monkeypatch, module, "open", record_open)
    assert binding.check_source(tmp_path, SHA) is None
    assert len(observed) == 1
    assert observed[0] & os.O_NOFOLLOW
    assert observed[0] & os.O_NONBLOCK


@requires_secure_reader
@pytest.mark.parametrize("when", ["before-open", "after-read"])
def test_reader_rejects_replacement_even_when_new_file_has_identical_bytes(
        tmp_path, monkeypatch, when):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    path = tmp_path / "package-lock.json"
    data = b"locked dependencies\n"
    path.write_bytes(data)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(data)
    triggered = []
    actual_open, actual_read = module.os.open, module.os.read

    def replaced_open(name, flags, *args, **kwargs):
        if str(name) == "package-lock.json" and when == "before-open" and not triggered:
            triggered.append(True)
            os.replace(replacement, path)
        return actual_open(name, flags, *args, **kwargs)

    def replaced_read(fd, size):
        result = actual_read(fd, size)
        if result and when == "after-read" and not triggered:
            triggered.append(True)
            os.replace(replacement, path)
        return result

    _patch_os(monkeypatch, module, "open", replaced_open)
    _patch_os(monkeypatch, module, "read", replaced_read)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)
    assert triggered
    assert path.read_bytes() == data


@requires_secure_reader
def test_reader_detects_same_size_mutation_after_bytes_were_read(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    path = tmp_path / "package-lock.json"
    path.write_bytes(b"locked dependencies\n")
    initial = path.stat()
    triggered = []
    actual_read = module.os.read

    def changed_read(fd, size):
        result = actual_read(fd, size)
        if result and not triggered:
            triggered.append(True)
            path.write_bytes(b"changed-dependency!\n")
            assert path.stat().st_size == initial.st_size
            os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000))
        return result

    _patch_os(monkeypatch, module, "read", changed_read)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)
    assert triggered


@requires_secure_reader
def test_reader_rechecks_final_descriptor_metadata_even_when_hash_matches(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b"locked dependencies\n")
    actual_fstat = module.os.fstat
    regular_calls = []

    class ChangedMetadata:
        def __init__(self, original):
            self.original = original
            self.st_ctime_ns = original.st_ctime_ns + 1

        def __getattr__(self, name):
            return getattr(self.original, name)

    def changed_fstat(fd):
        result = actual_fstat(fd)
        if stat.S_ISREG(result.st_mode):
            regular_calls.append(fd)
            if len(regular_calls) > 1:
                return ChangedMetadata(result)
        return result

    _patch_os(monkeypatch, module, "fstat", changed_fstat)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)
    assert len(regular_calls) >= 2


@requires_secure_reader
def test_reader_closes_every_owned_descriptor_on_hash_failure(tmp_path, monkeypatch):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b"wrong bytes")
    actual_open, actual_close = module.os.open, module.os.close
    opened, closed = [], []

    def recorded_open(*args, **kwargs):
        fd = actual_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def recorded_close(fd):
        closed.append(fd)
        return actual_close(fd)

    _patch_os(monkeypatch, module, "open", recorded_open)
    _patch_os(monkeypatch, module, "close", recorded_close)
    with pytest.raises(ValueError, match="runtime_binding_dependency_mismatch"):
        binding.check_source(tmp_path, SHA)
    assert opened
    assert Counter(opened) == Counter(closed)


@requires_secure_reader
@pytest.mark.parametrize("error_type", [NotImplementedError, RuntimeError])
@pytest.mark.parametrize("boundary", ["read", "fstat"])
def test_reader_normalizes_runtime_descriptor_failures_and_closes_all_fds(
        tmp_path, monkeypatch, error_type, boundary):
    from echo_certification_forge import runtime_admission as module
    binding = _binding(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b"locked dependencies\n")
    actual_open, actual_close = module.os.open, module.os.close
    actual_boundary = getattr(module.os, boundary)
    actual_fstat = module.os.fstat
    opened, closed, injected = [], [], []

    def recorded_open(*args, **kwargs):
        descriptor = actual_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def recorded_close(descriptor):
        closed.append(descriptor)
        return actual_close(descriptor)

    def unavailable(*args, **kwargs):
        result = actual_boundary(*args, **kwargs)  # Exercise the genuine descriptor first.
        if args[0] in opened and args[0] not in closed and not injected:
            injected.append(args[0])
            raise error_type("synthetic unsupported descriptor operation")
        return result

    _patch_os(monkeypatch, module, "open", recorded_open)
    _patch_os(monkeypatch, module, "close", recorded_close)
    _patch_os(monkeypatch, module, boundary, unavailable)
    with pytest.raises(ValueError, match="^runtime_binding_dependency_mismatch$") as denied:
        binding.check_source(tmp_path, SHA)
    assert type(denied.value.__cause__) is error_type
    assert injected and opened
    assert Counter(opened) == Counter(closed)
    for descriptor in set(opened):
        with pytest.raises(OSError):
            actual_fstat(descriptor)
