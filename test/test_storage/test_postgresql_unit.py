"""Unit tests for PostgreSQLStorage correctness work (issue #243).

These stay fully mocked (no real Postgres) and cover the behavior that does not
require a live server: singleton caching, TOML/config wiring, TLS/DSN plumbing,
reconnect-on-dead-connection, and the JSONL insert-failure fallback. The
``services: postgres`` job in ci.yml validates real protocol behavior.
"""

import contextlib
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

import manyfaced.common.config as cfg_mod
from manyfaced.db import storage as storage_mod
from manyfaced.db.storage import (
    PostgreSQLStorage,
    _resolve_backend,
    get_storage,
    reset_storage_singleton,
)


class _FakePsycopg2(types.ModuleType):
    """Stand-in psycopg2 with REAL exception classes (so ``except`` works) and a
    controllable ``connect`` (a MagicMock) for per-test behavior."""

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
    """Inject a fake psycopg2 into both sys.modules and the storage module."""
    fake = _FakePsycopg2()
    monkeypatch.setitem(sys.modules, 'psycopg2', fake)
    monkeypatch.setattr(storage_mod, 'psycopg2', fake)
    return fake


@pytest.fixture(autouse=True)
def _clear_singleton():
    reset_storage_singleton()
    yield
    reset_storage_singleton()


@contextlib.contextmanager
def _patch_settings(fake_settings):
    """Replace manyfaced.common.config.settings (the object storage lazily imports)."""
    saved = cfg_mod.settings
    try:
        cfg_mod.settings = fake_settings
        yield
    finally:
        cfg_mod.settings = saved


def _fresh_settings(**overrides):
    """A MagicMock settings with all DB_PG_* fields, overridable per test."""
    s = MagicMock()
    s.DB_BACKEND = ''
    s.DB_PG_HOST = '127.0.0.1'
    s.DB_PG_PORT = 5432
    s.DB_PG_DB = 'honeypot'
    s.DB_PG_USER = 'postgres'
    s.DB_PG_PASSWORD = 'postgres'
    s.DB_PG_SSLMODE = 'prefer'
    s.DB_PG_DSN = ''
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


class TestResolveBackend:
    def test_env_overrides_toml(self, fake_psycopg2):
        with _patch_settings(_fresh_settings(DB_BACKEND='postgresql')):
            with contextlib.nullcontext():
                os.environ.pop('HONEY_DB_BACKEND', None)
                assert _resolve_backend() == 'postgresql'

    def test_env_takes_precedence(self, fake_psycopg2, monkeypatch):
        with _patch_settings(_fresh_settings(DB_BACKEND='postgresql')):
            monkeypatch.setenv('HONEY_DB_BACKEND', 'sqlite')
            assert _resolve_backend() == 'sqlite'

    def test_default_is_sqlite(self, fake_psycopg2):
        import os as _os

        _os.environ.pop('HONEY_DB_BACKEND', None)
        with _patch_settings(_fresh_settings(DB_BACKEND='')):
            assert _resolve_backend() == 'sqlite'


class TestConfigWiring:
    def test_toml_pg_values_honored(self, fake_psycopg2, monkeypatch):
        s = _fresh_settings(
            DB_PG_HOST='toml.host',
            DB_PG_PORT=6432,
            DB_PG_DB='tomldb',
            DB_PG_USER='tomluser',
            DB_PG_PASSWORD='tomlpass',
            DB_PG_SSLMODE='require',
        )
        with _patch_settings(s):
            monkeypatch.delenv('HONEY_PG_HOST', raising=False)
            storage = PostgreSQLStorage()
        assert storage._host == 'toml.host'
        assert storage._port == 6432
        assert storage._database == 'tomldb'
        assert storage._user == 'tomluser'
        assert storage._password == 'tomlpass'
        assert storage._sslmode == 'require'
        # Explicit env overrides TOML.
        with _patch_settings(s):
            monkeypatch.setenv('HONEY_PG_HOST', 'env.host')
            storage2 = PostgreSQLStorage()
        assert storage2._host == 'env.host'

    def test_explicit_args_override_everything(self, fake_psycopg2, monkeypatch):
        s = _fresh_settings(DB_PG_HOST='toml.host')
        with _patch_settings(s):
            monkeypatch.setenv('HONEY_PG_HOST', 'env.host')
            storage = PostgreSQLStorage(host='explicit.host', port=9999)
        assert storage._host == 'explicit.host'
        assert storage._port == 9999


class TestDSN:
    def test_dsn_passed_to_connect(self, fake_psycopg2, monkeypatch):
        monkeypatch.setenv('HONEY_PG_DSN', 'postgres://u:p@h:5432/d')
        PostgreSQLStorage()
        args, kwargs = fake_psycopg2.connect.call_args
        assert kwargs.get('dsn') == 'postgres://u:p@h:5432/d'
        assert kwargs.get('sslmode') == 'prefer'
        assert 'host' not in kwargs

    def test_toml_dsn_used_when_no_env(self, fake_psycopg2, monkeypatch):
        s = _fresh_settings(DB_PG_DSN='postgres://toml:secret@db:5432/tomldb')
        with _patch_settings(s):
            monkeypatch.delenv('HONEY_PG_DSN', raising=False)
            PostgreSQLStorage()
        _, kwargs = fake_psycopg2.connect.call_args
        assert kwargs.get('dsn') == 'postgres://toml:secret@db:5432/tomldb'


class TestSingleton:
    def test_get_storage_caches_singleton(self, fake_psycopg2, monkeypatch):
        monkeypatch.setenv('HONEY_DB_BACKEND', 'postgresql')
        a = get_storage()
        b = get_storage()
        assert a is b

    def test_reset_singleton_forces_recreate(self, fake_psycopg2, monkeypatch):
        monkeypatch.setenv('HONEY_DB_BACKEND', 'postgresql')
        a = get_storage()
        reset_storage_singleton()
        b = get_storage()
        assert a is not b


class TestReconnect:
    def test_init_fails_lazy_then_insert_reconnects(self, fake_psycopg2, monkeypatch):
        # First connect (during __init__) yields a dead connection; the schema
        # probe on it raises, so init leaves _conn=None (lazy). The first insert
        # must trigger _ensure_connected(), which reconnects to a GOOD connection
        # and then succeeds.
        dead_conn = MagicMock()
        dead_conn.cursor.return_value.__enter__.return_value.execute.side_effect = (
            fake_psycopg2.OperationalError('dead')
        )
        good_conn = MagicMock()
        fake_psycopg2.connect.side_effect = [dead_conn, good_conn]
        monkeypatch.delenv('HONEY_DB_BACKEND', raising=False)
        storage = PostgreSQLStorage()
        assert storage._conn is None  # init failed lazily

        rec = {'ip': '1.2.3.4', 'timestamp': '2024-01-01 00:00:00'}
        storage.insert(rec)  # must not raise
        assert storage._conn is good_conn
        assert good_conn.cursor.called


class TestInsertFailureFallback:
    def test_insert_failure_dumps_jsonl(self, fake_psycopg2, monkeypatch, tmp_path):
        conn = MagicMock()
        fake_psycopg2.connect.return_value = conn
        conn.cursor.return_value.__enter__.return_value.execute.side_effect = (
            fake_psycopg2.OperationalError('boom')
        )
        monkeypatch.delenv('HONEY_DB_BACKEND', raising=False)
        storage = PostgreSQLStorage()
        # Force a dead connection so _ensure_connected cannot reconnect.
        storage._conn = None
        fake_psycopg2.connect.side_effect = fake_psycopg2.OperationalError('cannot reconnect')
        dump = tmp_path / 'dump.jsonl'
        # Config is frozen; capture the dump by redirecting dump_file to our file.
        import manyfaced.common.utils as utils_mod

        saved_dump = utils_mod.dump_file

        def _fake_dump(data):
            import json

            with open(dump, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(data) + '\n')

        monkeypatch.setattr(utils_mod, 'dump_file', _fake_dump)
        try:
            rec = {'ip': '9.9.9.9', 'timestamp': '2024-01-01 00:00:00'}
            storage.insert(rec)  # must not raise
        finally:
            monkeypatch.setattr(utils_mod, 'dump_file', saved_dump)
        assert dump.exists()
        assert 'postgres_insert_failure' in dump.read_text()


class TestAbortedTransactionRecovery:
    def test_infailedsqltransaction_recovers_and_stores(self, fake_psycopg2, monkeypatch, tmp_path):
        # Issue #243 regression: a failed query leaves the shared PG connection
        # in InFailedSqlTransaction. Every subsequent query then fails forever
        # (poisoning recording + the dashboard reader) unless we rollback and
        # reconnect. Simulate a generic psycopg2.Error (NOT OperationalError/
        # InterfaceError) on the first execute, then a GOOD connection on retry.
        bad_conn = MagicMock()
        bad_conn.cursor.return_value.__enter__.return_value.execute.side_effect = (
            fake_psycopg2.Error('InFailedSqlTransaction: current transaction is aborted')
        )
        good_conn = MagicMock()
        fake_psycopg2.connect.side_effect = [bad_conn, good_conn]
        monkeypatch.delenv('HONEY_DB_BACKEND', raising=False)
        storage = PostgreSQLStorage()
        # Make init succeed so the first insert uses bad_conn directly.
        storage._conn = bad_conn

        rec = {'ip': '1.2.3.4', 'timestamp': '2024-01-01 00:00:00', 'detected_id': 1}
        storage.insert(rec)  # must not raise, must recover + store

        # The bad connection was rolled back + closed, then a fresh good
        # connection performed the real insert (no JSONL dump fallback).
        assert bad_conn.rollback.called
        assert storage._conn is good_conn
        assert good_conn.cursor.called
        assert not dump_exists(tmp_path)

    def test_aborted_transaction_fallback_when_reconnect_fails(
        self, fake_psycopg2, monkeypatch, tmp_path
    ):
        # If rollback+reconnect still cannot establish a connection, the record
        # must be dumped to JSONL (never silently lost) rather than raising.
        bad_conn = MagicMock()
        bad_conn.cursor.return_value.__enter__.return_value.execute.side_effect = (
            fake_psycopg2.Error('InFailedSqlTransaction')
        )
        fake_psycopg2.connect.side_effect = [bad_conn, fake_psycopg2.Error('cannot reconnect')]
        monkeypatch.delenv('HONEY_DB_BACKEND', raising=False)
        storage = PostgreSQLStorage()
        storage._conn = bad_conn

        import manyfaced.common.utils as utils_mod

        saved_dump = utils_mod.dump_file
        dump = tmp_path / 'dump.jsonl'

        def _fake_dump(data):
            import json

            with open(dump, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(data) + '\n')

        monkeypatch.setattr(utils_mod, 'dump_file', _fake_dump)
        try:
            rec = {'ip': '9.9.9.9', 'timestamp': '2024-01-01 00:00:00'}
            storage.insert(rec)  # must not raise
        finally:
            monkeypatch.setattr(utils_mod, 'dump_file', saved_dump)
        assert dump.exists()
        assert 'postgres_insert_failure' in dump.read_text()


def dump_exists(path):
    return (path / 'dump.jsonl').exists()
