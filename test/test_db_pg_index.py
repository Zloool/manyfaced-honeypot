"""Tests for the PostgreSQL dashboard timestamp index (issue #347).

These stay fully mocked (no real Postgres):

* (a) asserts the new ``sql_builder.CREATE_INDEXES_PG_SQL`` DDL contains the
  ``idx_bears_timestamp`` btree over ``honeypot_bears(timestamp)`` (and the
  other dashboard aggregate indexes).
* (b) mocks a psycopg2 cursor and verifies ``PostgreSQLStorage._init_db``
  actually issues that index DDL, and that a failed index create does NOT break
  startup (it is guarded by a try/except).
"""

import sys
import types
from unittest.mock import MagicMock

import pytest

from manyfaced.db import sql_builder
from manyfaced.db import storage as storage_mod


class _FakePsycopg2(types.ModuleType):
    """Stand-in psycopg2 with REAL exception classes (so ``except`` works)."""

    class Error(Exception):
        pass

    class OperationalError(Error):
        pass

    class InterfaceError(Error):
        pass

    class DatabaseError(Error):
        pass

    def __init__(self):
        super().__init__('psycopg2')
        self.connect = MagicMock()


@pytest.fixture
def fake_psycopg2(monkeypatch):
    fake = _FakePsycopg2()
    monkeypatch.setitem(sys.modules, 'psycopg2', fake)
    monkeypatch.setattr(storage_mod, 'psycopg2', fake)
    return fake


@pytest.fixture(autouse=True)
def _clear_singleton():
    from manyfaced.db.storage import reset_storage_singleton

    reset_storage_singleton()
    yield
    reset_storage_singleton()


def _fresh_settings():
    s = MagicMock()
    s.DB_BACKEND = ''
    s.DB_PG_HOST = '127.0.0.1'
    s.DB_PG_PORT = 5432
    s.DB_PG_DB = 'honeypot'
    s.DB_PG_USER = 'postgres'
    s.DB_PG_PASSWORD = 'postgres'
    s.DB_PG_SSLMODE = 'prefer'
    s.DB_PG_DSN = ''
    return s


class TestPgIndexDDL:
    def test_constant_defines_timestamp_index(self):
        ddl = sql_builder.CREATE_INDEXES_PG_SQL
        assert 'idx_bears_timestamp' in ddl
        # Must index the TEXT timestamp column on honeypot_bears.
        assert 'ON honeypot_bears(timestamp)' in ddl
        assert 'CREATE INDEX IF NOT EXISTS' in ddl

    def test_constant_mirrors_all_dashboard_indexes(self):
        ddl = sql_builder.CREATE_INDEXES_PG_SQL
        for idx in (
            'idx_bears_timestamp',
            'idx_bears_detected_id',
            'idx_bears_bot_country',
            'idx_bears_bot_continent',
            'idx_bears_bot_ip',
            'idx_bears_request_path',
            'idx_bears_listen_port',
            'idx_bears_classification',
        ):
            assert idx in ddl, f'{idx} missing from CREATE_INDEXES_PG_SQL'

    def test_init_db_issues_index_ddl(self, fake_psycopg2, monkeypatch):
        import manyfaced.common.config as cfg_mod

        monkeypatch.setattr(cfg_mod, 'settings', _fresh_settings())
        storage = storage_mod.PostgreSQLStorage()

        # Build a cursor whose execute records every statement it ran.
        executed = []
        cur = MagicMock()
        cur.execute.side_effect = lambda stmt, *a, **k: executed.append(stmt)
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        fake_psycopg2.connect.return_value = conn

        storage._init_db()

        # The timestamp index DDL must have been issued against the cursor.
        combined = '\n'.join(executed)
        assert 'idx_bears_timestamp' in combined
        assert 'ON honeypot_bears(timestamp)' in combined
        # The index DDL comes from the dedicated PG constant, not the SQLite one.
        assert sql_builder.CREATE_INDEXES_PG_SQL.strip() in combined

    def test_init_db_survives_index_create_failure(self, fake_psycopg2, monkeypatch):
        import manyfaced.common.config as cfg_mod

        monkeypatch.setattr(cfg_mod, 'settings', _fresh_settings())
        storage = storage_mod.PostgreSQLStorage()

        cur = MagicMock()
        # The classification-column ALTER block works, but the index CREATE
        # fails (e.g. permission/lock). Startup must NOT raise.
        cur.execute.side_effect = [
            None,  # CREATE TABLE
            None,  # listen_port information_schema probe
            None,  # (probe returns no row) -> ALTER listen_port
            None,  # classification information_schema probe
            None,  # ALTER bot_asn
            None,  # ALTER bot_org
            None,  # ALTER classification
            None,  # ALTER benign_source
            fake_psycopg2.Error('index create blocked'),  # CREATE INDEX ... fails
        ]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        fake_psycopg2.connect.return_value = conn

        # Must not raise despite the index create error.
        storage._init_db()
        assert conn.commit.called
