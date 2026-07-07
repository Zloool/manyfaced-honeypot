"""Tests for scripts/migrate_db.py -- idempotent SQLite schema migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest import mock

import pytest

from manyfaced.db.sql_builder import CREATE_TABLE_SQL

import scripts.migrate_db as migrate_db


def _make_table(conn: sqlite3.Connection, columns: list[str]) -> None:
    """Create honeypot_bears with exactly the given (fake) columns.

    `id` is the PRIMARY KEY and always present; it is excluded from the
    provided list to mirror the real schema.
    """
    cols = ['id INTEGER PRIMARY KEY'] + [f'{c} TEXT' for c in columns if c != 'id']
    conn.execute('DROP TABLE IF EXISTS honeypot_bears')
    conn.execute('CREATE TABLE honeypot_bears (%s)' % ', '.join(cols))
    conn.commit()


def test_parse_target_columns_basic():
    sql = (
        'CREATE TABLE honeypot_bears (\n  id INTEGER PRIMARY KEY,\n  timestamp TEXT,\n  ip TEXT\n)'
    )
    cols = migrate_db._parse_target_columns(sql)
    assert cols == ['id', 'timestamp', 'ip']


def test_parse_target_columns_ignores_constraints():
    sql = (
        'CREATE TABLE honeypot_bears (\n'
        '  id INTEGER PRIMARY KEY AUTOINCREMENT,\n'
        '  bot_profile_data TEXT,\n'
        '  PRIMARY KEY (id),\n'
        '  UNIQUE(ip)\n'
        ')'
    )
    cols = migrate_db._parse_target_columns(sql)
    # Constraint lines (PRIMARY KEY, UNIQUE) must not appear as columns.
    assert 'PRIMARY KEY' not in cols
    assert 'UNIQUE' not in cols
    assert 'id' in cols
    assert 'bot_profile_data' in cols


def test_migrate_adds_missing_column(tmp_path: Path):
    db = tmp_path / 'h.db'
    conn = sqlite3.connect(db)
    _make_table(conn, ['timestamp', 'ip'])  # missing bot_profile_data
    conn.close()

    rc = migrate_db.migrate(str(db))

    assert rc == 0
    conn = sqlite3.connect(db)
    names = {r[1] for r in conn.execute('PRAGMA table_info(honeypot_bears)')}
    assert 'bot_profile_data' in names
    conn.close()


def test_migrate_idempotent_when_up_to_date(tmp_path: Path, capsys):
    db = tmp_path / 'h.db'
    # Seed with the REAL schema columns so nothing is missing.
    cols = migrate_db._parse_target_columns(CREATE_TABLE_SQL)
    conn = sqlite3.connect(db)
    _make_table(conn, cols)
    conn.close()

    rc = migrate_db.migrate(str(db))

    assert rc == 0
    out = capsys.readouterr().out
    assert 'already up to date' in out
    conn = sqlite3.connect(db)
    names = {r[1] for r in conn.execute('PRAGMA table_info(honeypot_bears)')}
    assert names == set(cols)
    conn.close()


def test_migrate_returns_error_on_db_failure(tmp_path: Path, capsys):
    # Point at a directory (not a file) so connect/operations fail.
    rc = migrate_db.migrate(str(tmp_path))
    assert rc == 1
    assert 'ERROR' in capsys.readouterr().err


def test_main_migrates_real_db_via_argv(tmp_path: Path):
    db = tmp_path / 'real.db'
    conn = sqlite3.connect(db)
    _make_table(conn, ['timestamp', 'ip'])  # missing bot_profile_data
    conn.close()

    # main() reads sys.argv; invoke it with --db pointing at our temp DB.
    import sys

    argv = ['migrate_db.py', f'--db={db}']
    with mock.patch.object(sys, 'argv', argv):
        rc = migrate_db.main()

    assert rc == 0
    conn = sqlite3.connect(db)
    names = {r[1] for r in conn.execute('PRAGMA table_info(honeypot_bears)')}
    assert 'bot_profile_data' in names
    conn.close()


def test_main_returns_error_code_on_failure(tmp_path: Path):
    import sys

    argv = ['migrate_db.py', f'--db={tmp_path}']  # directory -> open fails
    with mock.patch.object(sys, 'argv', argv):
        rc = migrate_db.main()
    assert rc == 1


def test_migrate_writes_backup_before_altering(tmp_path: Path):
    """migrate() writes a timestamped .bak copy of the live DB by default."""
    db = tmp_path / 'h.db'
    conn = sqlite3.connect(db)
    _make_table(conn, ['timestamp', 'ip'])  # missing bot_profile_data
    conn.close()

    before = list(tmp_path.glob('*.bak'))
    rc = migrate_db.migrate(str(db))
    after = list(tmp_path.glob('*.bak'))

    assert rc == 0
    # Exactly one new .bak file appeared and it is a copy of the pre-migration DB.
    assert len(after) == len(before) + 1
    bak = after[0]
    assert bak.name.startswith('h.db.') and bak.name.endswith('.bak')
    # The backup predates the migration: it lacks bot_profile_data.
    bconn = sqlite3.connect(bak)
    bnames = {r[1] for r in bconn.execute('PRAGMA table_info(honeypot_bears)')}
    bconn.close()
    assert 'bot_profile_data' not in bnames


def test_migrate_skips_backup_with_flag(tmp_path: Path):
    """backup=False leaves no .bak file behind."""
    db = tmp_path / 'h.db'
    conn = sqlite3.connect(db)
    _make_table(conn, ['timestamp', 'ip'])
    conn.close()

    rc = migrate_db.migrate(str(db), backup=False)
    assert rc == 0
    assert not list(tmp_path.glob('*.bak'))


def test_prune_backups_caps_retention(tmp_path: Path):
    """_prune_backups keeps only the newest `keep` backups.

    Regression guard for the 2026-07 disk-full silent-stop: an unbounded .bak
    on every deploy filled the droplet disk and stopped all writes. Capping
    retention keeps a revertible backup without growing without bound.
    """
    db = tmp_path / 'h.db'
    # Create 6 timestamped .bak files (oldest -> newest by name sort).
    stamps = [f'{d:014d}' for d in range(20260101000000, 20260101000000 + 6 * 100)]
    for s in stamps:
        (tmp_path / f'h.db.{s}.bak').write_text('x')

    migrate_db._prune_backups(str(db), keep=3)

    remaining = sorted(tmp_path.glob('h.db.*.bak'))
    assert len(remaining) == 3
    # The 3 newest stamps survive.
    assert [p.name for p in remaining] == [f'h.db.{s}.bak' for s in stamps[-3:]]


def test_migrate_retention_flag_default_keep(tmp_path: Path):
    """migrate() prunes to keep=3 by default so repeated deploys can't fill disk."""
    db = tmp_path / 'h.db'
    conn = sqlite3.connect(db)
    _make_table(conn, ['timestamp', 'ip'])
    conn.close()

    # Run migrate 5 times; each writes one .bak then prunes to keep=3.
    for _ in range(5):
        migrate_db.migrate(str(db))

    backups = sorted(tmp_path.glob('h.db.*.bak'))
    assert len(backups) <= 3, f'expected <=3 backups, found {len(backups)}'
