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
