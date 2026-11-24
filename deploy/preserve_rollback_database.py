"""Preserve the accepted-write database before a source-only rollback.

The deployment owner must stop both API and dispatcher before calling this helper.
It never replaces the live database or deletes an earlier recovery snapshot.
"""
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys


def preserve_database(source: Path, destination: Path) -> dict:
    if not source.is_file() or source.is_symlink() or destination.exists():
        raise ValueError('rollback_snapshot_path_invalid')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True)) as live:
        with closing(sqlite3.connect(destination)) as snapshot:
            live.backup(snapshot)
            if snapshot.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise ValueError('rollback_snapshot_integrity_failed')
    with destination.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'preserved': True, 'live_database_replaced': False,
            'snapshot_sha256': digest, 'snapshot_bytes': destination.stat().st_size}


if __name__ == '__main__':
    try:
        print(json.dumps(preserve_database(Path(sys.argv[1]), Path(sys.argv[2]))))
    except (OSError, ValueError, sqlite3.Error):
        print(json.dumps({'preserved': False, 'error': 'rollback_snapshot_failed'}))
        raise SystemExit(1)
