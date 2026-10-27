import importlib.util
from pathlib import Path
import sqlite3

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('rollback_snapshot_test', ROOT/'deploy/preserve_rollback_database.py')
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


def test_post_promotion_snapshot_keeps_acknowledged_writes_and_previous_backup(tmp_path):
    live = tmp_path/'live.sqlite'
    before = tmp_path/'before.sqlite'
    after = tmp_path/'after.sqlite'
    with sqlite3.connect(live) as db:
        db.execute('CREATE TABLE accepted(value TEXT)')
        db.execute("INSERT INTO accepted VALUES ('before')")
    HELPER.preserve_database(live, before)
    baseline = before.read_bytes()
    with sqlite3.connect(live) as db:
        db.execute("INSERT INTO accepted VALUES ('acknowledged-during-promotion')")
    receipt = HELPER.preserve_database(live, after)
    assert receipt['preserved'] and receipt['live_database_replaced'] is False
    for path in [live, after]:
        with sqlite3.connect(path) as db:
            assert db.execute('SELECT value FROM accepted ORDER BY rowid').fetchall() == [('before',), ('acknowledged-during-promotion',)]
    assert before.read_bytes() == baseline
    with pytest.raises(ValueError):
        HELPER.preserve_database(live, before)
    assert before.read_bytes() == baseline


def test_deployment_fences_database_restore_before_first_possible_api_write():
    script = (ROOT/'deploy/deploy_forge.sh').read_text(encoding='utf-8')
    assert script.index('PROD_API_STARTED=1') < script.index('sudo systemctl restart "$SERVICE.service"')
    rollback = script.split('rollback_production() {', 1)[1].split('trap rollback_production EXIT', 1)[0]
    assert '[ "$DB_SNAPSHOT_READY" = 1 ] && [ "$PROD_API_STARTED" = 1 ]' in rollback
    assert rollback.index('preserve_rollback_database.py') < rollback.index('elif [ "$DB_SNAPSHOT_READY" = 1 ]') < rollback.index('mv -f "$DB_RESTORE" "$DB_PATH"')
    assert '"$DISPATCH_RELEASE_DROPIN_BACKUP" "$DB_BACKUP"' not in script
    assert 'rm -f "$UNIT_BACKUP" "$DISPATCH_UNIT_BACKUP" "$DB_BACKUP"' not in script
