"""Connection ownership controls use real temporary SQLite files, never live telemetry."""
import sqlite3
from contextlib import closing

import pytest

from echo_certification_forge.operational_telemetry import OperationalTelemetryRegistry


@pytest.mark.parametrize("fail_initialization", [False, True])
def test_registry_initialization_closes_owned_connection(tmp_path, monkeypatch, fail_initialization):
    connect = sqlite3.connect
    opened = []

    class ObservedConnection(sqlite3.Connection):
        def executescript(self, script, /):
            if fail_initialization:
                raise sqlite3.OperationalError("synthetic initialization failure")
            return super().executescript(script)

    def tracked_connect(*args, **kwargs):
        connection = connect(*args, **kwargs, factory=ObservedConnection)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    try:
        if fail_initialization:
            with pytest.raises(sqlite3.OperationalError, match="synthetic"):
                OperationalTelemetryRegistry(tmp_path / "owned.sqlite3")
        else:
            OperationalTelemetryRegistry(tmp_path / "owned.sqlite3")
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            opened[0].execute("SELECT 1")
    finally:
        for connection in opened:
            connection.close()


@pytest.mark.parametrize("fail_transaction", [False, True])
def test_registry_connection_preserves_commit_and_rollback(tmp_path, monkeypatch, fail_transaction):
    path = tmp_path / "transaction.sqlite3"
    registry = OperationalTelemetryRegistry(path)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE owned_connection_control (value INTEGER)")
        connection.commit()
    connect = registry._connect
    opened = []

    def tracked_connect():
        connection = connect()
        opened.append(connection)
        return connection

    monkeypatch.setattr(registry, "_connect", tracked_connect)
    try:
        if fail_transaction:
            with pytest.raises(RuntimeError, match="synthetic rollback"):
                with registry._connection() as connection:
                    connection.execute("INSERT INTO owned_connection_control VALUES (1)")
                    raise RuntimeError("synthetic rollback")
        else:
            with registry._connection() as connection:
                connection.execute("INSERT INTO owned_connection_control VALUES (1)")
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            opened[0].execute("SELECT 1")
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute("SELECT COUNT(*) FROM owned_connection_control").fetchone()[0] == (0 if fail_transaction else 1)
    finally:
        for connection in opened:
            connection.close()
