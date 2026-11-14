"""Real SQLite/file regressions for concurrent, append-only evidence publication."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from echo_certification_forge import evidence
from echo_certification_forge.evidence import EvidenceStore


def _register(store, manifest, target, environment):
    store.register_run("concurrent-run", target, environment, manifest.manifest_id, manifest.digest)
    return "concurrent-run"


def test_concurrent_store_instances_preserve_one_verified_chain(
    tmp_path, manifest, target, environment,
):
    first = EvidenceStore(tmp_path / "store.sqlite3", tmp_path / "evidence")
    run_id = _register(first, manifest, target, environment)
    stores = [EvidenceStore(first.db_path, first.evidence_root) for _ in range(8)]
    start = threading.Barrier(len(stores))

    def append(index):
        start.wait(timeout=10)
        return stores[index].append_artifact(
            run_id, target.tenant_id, f"artifact-{index}", f"proof-{index}".encode(),
            "text/plain", "concurrency-test",
        )

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        descriptors = list(pool.map(append, range(len(stores))))

    rows = first.list_evidence(run_id, target.tenant_id)
    assert len(rows) == len(stores)
    assert sorted(row["ordinal"] for row in rows) == list(range(1, len(stores) + 1))
    assert {row["artifact_id"] for row in rows} == {row["artifact_id"] for row in descriptors}
    assert first.verify_evidence(run_id, target.tenant_id).valid
    for descriptor in descriptors:
        index = int(descriptor["artifact_id"].split("-")[-1])
        assert (first.evidence_root / descriptor["relative_path"]).read_bytes() == f"proof-{index}".encode()


def test_publish_never_overwrites_a_file_created_after_preflight(
    store, manifest, target, environment, monkeypatch,
):
    run_id = _register(store, manifest, target, environment)
    artifact_id = "publication-race"
    destination = store.evidence_root / target.tenant_id / run_id / "artifacts" / f"{artifact_id}.bin"
    actual_fsync = evidence.os.fsync
    sentinel = b"unowned concurrent publication"

    def publish_competitor(fd):
        actual_fsync(fd)
        # A file appears after the initial existence check but before publication.
        # The appender has no ownership of it, even without a metadata descriptor.
        with destination.open("xb") as handle:
            handle.write(sentinel)

    monkeypatch.setattr(evidence.os, "fsync", publish_competitor)
    with pytest.raises(FileExistsError):
        store.append_artifact(
            run_id, target.tenant_id, artifact_id, b"attempted replacement",
            "text/plain", "publication-test",
        )

    assert destination.read_bytes() == sentinel
    assert store.list_evidence(run_id, target.tenant_id) == []
    assert list(destination.parent.glob(".artifact-*")) == []


def test_duplicate_artifact_cannot_remove_prior_bytes(
    store, manifest, target, environment,
):
    run_id = _register(store, manifest, target, environment)
    descriptor = store.append_artifact(
        run_id, target.tenant_id, "same-artifact", b"original",
        "text/plain", "duplicate-test",
    )
    with pytest.raises(FileExistsError):
        store.append_artifact(
            run_id, target.tenant_id, "same-artifact", b"replacement",
            "text/plain", "duplicate-test",
        )
    assert (store.evidence_root / descriptor["relative_path"]).read_bytes() == b"original"
    assert store.verify_evidence(run_id, target.tenant_id).valid


class _CommitFailure(sqlite3.Connection):
    """Inject a storage failure at the real transaction commit boundary."""

    def commit(self):
        if self.in_transaction:
            raise sqlite3.OperationalError("simulated commit storage failure")
        return super().commit()

    def __exit__(self, kind, value, traceback):
        if kind is None and self.in_transaction:
            raise sqlite3.OperationalError("simulated commit storage failure")
        return super().__exit__(kind, value, traceback)


def test_failed_commit_cleans_only_its_uncommitted_publication(
    store, manifest, target, environment, monkeypatch,
):
    run_id = _register(store, manifest, target, environment)
    original = store.append_artifact(
        run_id, target.tenant_id, "retained-proof", b"retained",
        "text/plain", "commit-test",
    )

    def connect():
        connection = sqlite3.connect(store.db_path, factory=_CommitFailure)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    with monkeypatch.context() as patched:
        patched.setattr(store, "_connect", connect)
        with pytest.raises(sqlite3.OperationalError, match="simulated commit"):
            store.append_artifact(
                run_id, target.tenant_id, "failed-proof", b"uncommitted",
                "text/plain", "commit-test",
            )

    artifacts = store.evidence_root / target.tenant_id / run_id / "artifacts"
    assert not (artifacts / "failed-proof.bin").exists()
    assert (store.evidence_root / original["relative_path"]).read_bytes() == b"retained"
    assert list(artifacts.glob(".artifact-*")) == []
    assert len(store.list_evidence(run_id, target.tenant_id)) == 1
    assert store.verify_evidence(run_id, target.tenant_id).valid


def test_lock_budget_exhaustion_publishes_no_artifact(
    store, manifest, target, environment, monkeypatch,
):
    run_id = _register(store, manifest, target, environment)
    original_connect = store._connect

    def short_wait_connect():
        connection = original_connect()
        connection.execute("PRAGMA busy_timeout = 25")
        return connection

    blocker = sqlite3.connect(store.db_path)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        monkeypatch.setattr(store, "_connect", short_wait_connect)
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            store.append_artifact(
                run_id, target.tenant_id, "blocked-proof", b"blocked",
                "text/plain", "contention-test",
            )
    finally:
        blocker.rollback()
        blocker.close()

    artifacts = store.evidence_root / target.tenant_id / run_id / "artifacts"
    assert not (artifacts / "blocked-proof.bin").exists()
    assert list(artifacts.glob(".artifact-*")) == []
    assert store.list_evidence(run_id, target.tenant_id) == []


def test_cross_tenant_append_creates_no_file(store, manifest, target, environment):
    run_id = _register(store, manifest, target, environment)
    with pytest.raises(KeyError):
        store.append_artifact(
            run_id, "tenant-other", "denied-proof", b"denied",
            "text/plain", "tenant-test",
        )
    assert not (store.evidence_root / "tenant-other").exists()


def test_concurrent_duplicate_has_one_winner_and_keeps_its_bytes(
    tmp_path, manifest, target, environment,
):
    first = EvidenceStore(tmp_path / "store.sqlite3", tmp_path / "evidence")
    run_id = _register(first, manifest, target, environment)
    stores = [EvidenceStore(first.db_path, first.evidence_root) for _ in range(4)]
    start = threading.Barrier(len(stores))

    def append(index):
        start.wait(timeout=10)
        try:
            descriptor = stores[index].append_artifact(
                run_id, target.tenant_id, "same-proof", f"proof-{index}".encode(),
                "text/plain", "duplicate-test",
            )
            return index, descriptor
        except FileExistsError:
            return index, None

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        outcomes = list(pool.map(append, range(len(stores))))
    winners = [(index, descriptor) for index, descriptor in outcomes if descriptor is not None]
    assert len(winners) == 1
    index, descriptor = winners[0]
    assert (first.evidence_root / descriptor["relative_path"]).read_bytes() == f"proof-{index}".encode()
    assert len(first.list_evidence(run_id, target.tenant_id)) == 1
    assert first.verify_evidence(run_id, target.tenant_id).valid


def test_sql_failure_cleanup_keeps_a_replacement_file(
    store, manifest, target, environment, monkeypatch,
):
    run_id = _register(store, manifest, target, environment)
    destination = store.evidence_root / target.tenant_id / run_id / "artifacts" / "replaced-proof.bin"
    sentinel = b"not owned by this appender"

    class ReplacedPublication(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if "INSERT INTO evidence_artifacts" in sql:
                destination.unlink()
                destination.write_bytes(sentinel)
                raise sqlite3.OperationalError("simulated publication replacement")
            return super().execute(sql, *args, **kwargs)

    def connect():
        connection = sqlite3.connect(store.db_path, factory=ReplacedPublication)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    with monkeypatch.context() as patched:
        patched.setattr(store, "_connect", connect)
        with pytest.raises(sqlite3.OperationalError, match="simulated publication replacement"):
            store.append_artifact(
                run_id, target.tenant_id, "replaced-proof", b"owned temporary",
                "text/plain", "replacement-test",
            )
    assert destination.read_bytes() == sentinel
    assert store.list_evidence(run_id, target.tenant_id) == []
    assert list(destination.parent.glob(".artifact-*")) == []


def test_exception_after_commit_never_removes_committed_evidence(
    store, manifest, target, environment, monkeypatch,
):
    run_id = _register(store, manifest, target, environment)

    class CommittedThenFailure(sqlite3.Connection):
        def commit(self):
            was_active = self.in_transaction
            result = super().commit()
            if was_active:
                raise sqlite3.OperationalError("simulated ambiguous commit outcome")
            return result

    def connect():
        connection = sqlite3.connect(store.db_path, factory=CommittedThenFailure)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    with monkeypatch.context() as patched:
        patched.setattr(store, "_connect", connect)
        with pytest.raises(sqlite3.OperationalError, match="ambiguous commit"):
            store.append_artifact(
                run_id, target.tenant_id, "committed-proof", b"committed",
                "text/plain", "commit-test",
            )
    destination = store.evidence_root / target.tenant_id / run_id / "artifacts" / "committed-proof.bin"
    assert destination.read_bytes() == b"committed"
    assert len(store.list_evidence(run_id, target.tenant_id)) == 1
    assert store.verify_evidence(run_id, target.tenant_id).valid
