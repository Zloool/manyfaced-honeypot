"""Tests for manyfaced.db.storage (SQLiteStorage, PostgreSQLStorage, get_storage, helpers)."""

import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path
# ---------------------------------------------------------------------------
_project_root = __import__('os').path.abspath(
    __import__('os').path.join(__import__('os').path.dirname(__file__), '..')
)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from manyfaced.db.storage import (  # noqa: E402
    PostgreSQLStorage,
    SQLiteStorage,
    StorageBackend,
    _resolve_backend,
    _resolve_db_path,
    get_storage,
)


# ---------------------------------------------------------------------------
# _resolve_db_path tests
# ---------------------------------------------------------------------------


class TestResolveDbPath:
    """Tests for _resolve_db_path()."""

    def test_default_path_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch('manyfaced.common.config.settings', DB_PATH=None):
            result = _resolve_db_path()
        assert result == 'bots/honeypot.sqlite'

    def test_falls_back_to_toml_config_db_path(self):
        """When no env var is set, falls back to TOML config's database.path."""
        with patch.dict(os.environ, {}, clear=True), \
             patch('manyfaced.common.config.settings', DB_PATH='/custom/from/toml.db'):
            result = _resolve_db_path()
        assert result == '/custom/from/toml.db'

    def test_env_overrides_toml_config(self):
        """HONEY_DB_PATH env var takes precedence over TOML config."""
        with patch.dict(os.environ, {'HONEY_DB_PATH': '/env/override.db'}, clear=True), \
             patch('manyfaced.common.config.settings', DB_PATH='/toml/path.db'):
            result = _resolve_db_path()
        assert result == '/env/override.db'

    def test_custom_path_from_env(self):
        with patch.dict(os.environ, {'HONEY_DB_PATH': '/tmp/custom.db'}, clear=True):
            result = _resolve_db_path()
        assert result == '/tmp/custom.db'

    def test_env_path_with_subdirs(self):
        with patch.dict(os.environ, {'HONEY_DB_PATH': 'data/nested/honeypot.db'}, clear=True):
            result = _resolve_db_path()
        assert result == 'data/nested/honeypot.db'


# ---------------------------------------------------------------------------
# _resolve_backend tests
# ---------------------------------------------------------------------------


class TestResolveBackend:
    """Tests for _resolve_backend()."""

    def test_default_backend_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            result = _resolve_backend()
        assert result == 'sqlite'

    def test_custom_backend_from_env_lowercase(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'postgresql'}, clear=True):
            result = _resolve_backend()
        assert result == 'postgresql'

    def test_custom_backend_from_env_uppercase(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'PostgreSQL'}, clear=True):
            result = _resolve_backend()
        assert result == 'postgresql'

    def test_custom_backend_from_env_mixed_case(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'SQLITE'}, clear=True):
            result = _resolve_backend()
        assert result == 'sqlite'

    def test_env_backend_stored_lowercase(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'POSTGRES'}, clear=True):
            result = _resolve_backend()
        assert result == 'postgres'


# ---------------------------------------------------------------------------
# StorageBackend abstract base class tests
# ---------------------------------------------------------------------------


class TestStorageBackend:
    """Tests for the abstract StorageBackend class."""

    def test_storage_backend_is_abstract(self):
        """StorageBackend cannot be instantiated directly."""
        with pytest.raises(TypeError):
            StorageBackend()

    def test_storage_backend_has_abstract_methods(self):
        """StorageBackend defines abstract insert and close methods."""
        assert hasattr(StorageBackend, 'insert')
        assert hasattr(StorageBackend, 'close')

    def test_subclass_without_abstract_methods_cannot_be_instantiated(self):
        """A subclass that doesn't implement insert/close cannot be instantiated."""

        class IncompleteBackend(StorageBackend):
            pass

        with pytest.raises(TypeError):
            IncompleteBackend()

    def test_subclass_with_all_abstract_methods_can_be_instantiated(self):
        """A subclass implementing insert and close can be instantiated."""

        class CompleteBackend(StorageBackend):
            def insert(self, record: dict) -> None:
                pass

            def close(self) -> None:
                pass

        backend = CompleteBackend()
        assert isinstance(backend, StorageBackend)


# ---------------------------------------------------------------------------
# SQLiteStorage tests
# ---------------------------------------------------------------------------


class TestSQLiteStorageInit:
    """Tests for SQLiteStorage.__init__()."""

    def test_init_creates_parent_directory(self, tmp_path):
        """SQLiteStorage.__init__ should create parent directories for db_path."""
        db_path = str(tmp_path / 'sub' / 'dir' / 'test.db')
        storage = SQLiteStorage(db_path=db_path)
        assert os.path.exists(os.path.dirname(db_path))
        storage.close()

    def test_init_with_custom_db_path(self, tmp_path):
        """SQLiteStorage should accept a custom db_path."""
        db_path = str(tmp_path / 'custom.db')
        storage = SQLiteStorage(db_path=db_path)
        assert storage._db_path == db_path
        storage.close()

    def test_init_uses_default_path_when_no_db_path(self, tmp_path):
        """SQLiteStorage should use _resolve_db_path() when db_path is None."""
        with patch.dict(
            os.environ, {'HONEY_DB_PATH': str(tmp_path / 'default.sqlite')}, clear=True
        ):
            storage = SQLiteStorage()
        assert storage._db_path == str(tmp_path / 'default.sqlite')
        storage.close()

    def test_init_creates_connection(self, tmp_path):
        """SQLiteStorage should create a connection on init."""
        db_path = str(tmp_path / 'conn.db')
        storage = SQLiteStorage(db_path=db_path)
        assert storage._conn is not None
        storage.close()

    def test_init_creates_lock(self, tmp_path):
        """SQLiteStorage should create a threading Lock on init."""
        db_path = str(tmp_path / 'lock.db')
        storage = SQLiteStorage(db_path=db_path)
        assert storage._lock is not None
        storage.close()

    def test_init_creates_table(self, tmp_path):
        """SQLiteStorage._init_db should create the honeypot_bears table."""
        db_path = str(tmp_path / 'table.db')
        storage = SQLiteStorage(db_path=db_path)
        cursor = storage._conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='honeypot_bears'"
        )
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == 'honeypot_bears'
        storage.close()


class TestSQLiteStorageInsert:
    """Tests for SQLiteStorage.insert()."""

    def test_insert_with_full_record(self, tmp_path):
        """insert() should handle a full record with all fields."""
        db_path = str(tmp_path / 'full.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '192.168.1.1',
            'hostname': 'attacker.local',
            'timestamp': '2024-01-15 10:30:00',
            'parsed_request': {
                'path': '/admin',
                'command': 'GET',
                'request_version': 'HTTP/1.1',
                'user_agent': 'Mozilla/5.0',
            },
            'raw_request': 'GET /admin HTTP/1.1',
            'country': 'US',
            'continent': 'NA',
            'tracert': 'hop1,hop2',
            'dns_name': 'evil.com',
            'is_detected': 1,
            'hive_id': 42,
            'login': 'admin',
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT * FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert row[1] == '192.168.1.1'  # bot_ip
        assert row[2] == 'attacker.local'  # hostname
        assert row[3] == '2024-01-15 10:30:00'  # timestamp
        assert row[4] == '/admin'  # request_path
        assert row[5] == 'GET'  # request_command
        assert row[6] == 'HTTP/1.1'  # request_version
        assert row[7] == 'GET /admin HTTP/1.1'  # request_raw
        assert row[8] == 'Mozilla/5.0'  # bot_user_agent
        assert row[9] == 'US'  # bot_country
        assert row[10] == 'NA'  # bot_continent
        assert row[11] == 'hop1,hop2'  # bot_tracert
        assert row[12] == 'evil.com'  # bot_dns_name
        assert row[13] == 1  # detected_id
        assert row[14] == 42  # hive_id
        assert row[15] == 'admin'  # login
        storage.close()

    def test_insert_with_minimal_record(self, tmp_path):
        """insert() should handle a minimal record with only required keys."""
        db_path = str(tmp_path / 'minimal.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'raw_request': 'GET / HTTP/1.1',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT * FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert row[1] == '10.0.0.1'  # bot_ip
        assert row[2] == ''  # hostname defaults to ""
        assert row[4] == ''  # request_path defaults to ""
        storage.close()

    def test_insert_with_datetime_timestamp(self, tmp_path):
        """insert() should convert a datetime object to a timestamp string."""
        db_path = str(tmp_path / 'datetime.db')
        storage = SQLiteStorage(db_path=db_path)

        dt = datetime(2024, 6, 15, 14, 30, 0, 123456)
        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': dt,
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT timestamp FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        # Should be a string, not a datetime object
        assert isinstance(row[0], str)
        assert '2024-06-15 14:30:00' in row[0]
        storage.close()

    def test_insert_with_none_values(self, tmp_path):
        """insert() should handle None values gracefully."""
        db_path = str(tmp_path / 'none.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': None,
            'hostname': None,
            'timestamp': None,
            'parsed_request': None,
            'raw_request': None,
            'country': None,
            'continent': None,
            'tracert': None,
            'dns_name': None,
            'is_detected': None,
            'hive_id': None,
            'login': None,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT * FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        # None values should be converted to empty strings or NULL
        assert row[1] == ''  # bot_ip
        assert row[2] == ''  # hostname
        assert row[3] == ''  # timestamp
        storage.close()

    def test_insert_handles_missing_conn(self, tmp_path, caplog):
        """insert() should log an error and return when _conn is None."""
        db_path = str(tmp_path / 'missing_conn.db')
        storage = SQLiteStorage(db_path=db_path)
        # Simulate a missing connection
        storage._conn = None

        record = {'ip': '10.0.0.1'}
        storage.insert(record)  # Should not raise

        # Verify no row was inserted - connection was set to None,
        # so we can't query it. The important thing is that no exception was raised
        # The important thing is that no exception was raised
        storage.close()

    def test_insert_with_parsed_request_path_fallback(self, tmp_path):
        """insert() should fall back to record-level request_path if parsed_request is empty."""
        db_path = str(tmp_path / 'fallback.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},  # empty parsed_request
            'raw_request': 'GET /fallback HTTP/1.1',
            'request_path': '/fallback',  # fallback key
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT request_path FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == '/fallback'
        storage.close()

    def test_insert_with_empty_parsed_request_uses_record_keys(self, tmp_path):
        """When parsed_request is empty dict, should fall back to record-level keys."""
        db_path = str(tmp_path / 'empty_parsed.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET /path HTTP/1.1',
            'request_path': '/path',
            'request_command': 'GET',
            'request_version': 'HTTP/1.1',
            'ua': 'TestAgent',
            'is_detected': 1,
            'hive_id': 10,
            'HIVELOGIN': 'root',
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute(
            'SELECT request_path, request_command, bot_user_agent, hive_id, login FROM honeypot_bears'
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == '/path'  # request_path from record
        assert row[1] == 'GET'  # request_command from record
        assert row[2] == 'TestAgent'  # ua from record
        assert row[3] == 10  # hive_id from record
        assert row[4] == 'root'  # HIVELOGIN from record
        storage.close()

    def test_insert_with_is_detected_conversion(self, tmp_path):
        """insert() should convert is_detected to int."""
        db_path = str(tmp_path / 'detected.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 1,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT detected_id FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert isinstance(row[0], int)
        assert row[0] == 1
        storage.close()

    def test_insert_with_isDetected_fallback(self, tmp_path):
        """insert() should fall back to isDetected key if is_detected is None."""
        db_path = str(tmp_path / 'isdetected.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': None,
            'isDetected': 5,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT detected_id FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == 5
        storage.close()

    def test_insert_with_version_fallback(self, tmp_path):
        """insert() should try parsed request_version, version, then record_version."""
        db_path = str(tmp_path / 'version.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {'version': 'HTTP/2.0'},  # version in parsed, not request_version
            'raw_request': 'GET / HTTP/2.0',
            'request_version': 'HTTP/1.1',
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT request_version FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        # parsed.version should be tried after parsed.request_version (which is empty)
        # but parsed.request_version is not in parsed, so it tries parsed.version
        assert row[0] == 'HTTP/2.0'
        storage.close()


class TestSQLiteStorageClose:
    """Tests for SQLiteStorage.close()."""

    def test_close_closes_connection(self, tmp_path):
        """close() should close the SQLite connection."""
        db_path = str(tmp_path / 'close.db')
        storage = SQLiteStorage(db_path=db_path)
        assert storage._conn is not None
        storage.close()
        assert storage._conn is None

    def test_close_with_none_connection(self, tmp_path):
        """close() should not raise when _conn is None."""
        db_path = str(tmp_path / 'close_none.db')
        storage = SQLiteStorage(db_path=db_path)
        storage._conn = None
        # Should not raise
        storage.close()

    def test_close_twice(self, tmp_path):
        """close() should be safe to call multiple times."""
        db_path = str(tmp_path / 'close_twice.db')
        storage = SQLiteStorage(db_path=db_path)
        storage.close()
        storage.close()  # Should not raise


class TestSQLiteStorageContextManager:
    """Tests for SQLiteStorage.__enter__/__exit__."""

    def test_enter_returns_self(self, tmp_path):
        """__enter__ should return the storage instance."""
        db_path = str(tmp_path / 'enter.db')
        with SQLiteStorage(db_path=db_path) as storage:
            assert storage is not None
            assert storage._conn is not None

    def test_exit_closes_connection(self, tmp_path):
        """__exit__ should close the connection."""
        db_path = str(tmp_path / 'exit.db')
        storage = SQLiteStorage(db_path=db_path)
        assert storage._conn is not None
        with storage:
            pass
        assert storage._conn is None

    def test_context_manager_with_insert(self, tmp_path):
        """Context manager should work with insert operations."""
        db_path = str(tmp_path / 'ctx.db')
        with SQLiteStorage(db_path=db_path) as storage:
            record = {
                'ip': '10.0.0.1',
                'hostname': 'test',
                'timestamp': '2024-01-01 00:00:00',
                'parsed_request': {},
                'raw_request': 'GET / HTTP/1.1',
                'is_detected': 0,
            }
            storage.insert(record)
        # Connection should be closed after __exit__
        assert storage._conn is None


class TestSQLiteStorageMultipleInserts:
    """Tests for multiple insert() calls."""

    def test_multiple_inserts(self, tmp_path):
        """Multiple insert() calls should each create a row."""
        db_path = str(tmp_path / 'multi.db')
        storage = SQLiteStorage(db_path=db_path)

        for i in range(5):
            record = {
                'ip': f'10.0.0.{i}',
                'hostname': f'host{i}',
                'timestamp': f'2024-01-01 00:00:{i:02d}',
                'parsed_request': {},
                'raw_request': f'GET /{i} HTTP/1.1',
                'is_detected': i % 2,
            }
            storage.insert(record)

        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM honeypot_bears')
        count = cursor.fetchone()[0]
        assert count == 5
        storage.close()

    def test_multiple_inserts_different_records(self, tmp_path):
        """Multiple insert() calls with varying record completeness."""
        db_path = str(tmp_path / 'vary.db')
        storage = SQLiteStorage(db_path=db_path)

        # Full record
        storage.insert(
            {
                'ip': '10.0.0.1',
                'hostname': 'host1',
                'timestamp': '2024-01-01 00:00:01',
                'parsed_request': {'path': '/full'},
                'raw_request': 'GET /full HTTP/1.1',
                'is_detected': 1,
                'hive_id': 1,
                'login': 'admin',
            }
        )

        # Minimal record
        storage.insert(
            {
                'ip': '10.0.0.2',
                'raw_request': 'GET /min HTTP/1.1',
                'timestamp': '2024-01-01 00:00:02',
                'parsed_request': {},
                'is_detected': 0,
            }
        )

        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM honeypot_bears')
        count = cursor.fetchone()[0]
        assert count == 2
        storage.close()


# ---------------------------------------------------------------------------
# PostgreSQLStorage tests
# ---------------------------------------------------------------------------


# Fixture: provide a mocked psycopg2 module so PostgreSQLStorage can be instantiated
@pytest.fixture
def mock_psycopg2(monkeypatch):
    """Return a MagicMock for psycopg2 and inject it into sys.modules."""
    mock = MagicMock()
    monkeypatch.setitem(sys.modules, 'psycopg2', mock)
    return mock


class TestPostgreSQLStorageInit:
    """Tests for PostgreSQLStorage.__init__()."""

    def test_init_reads_env_vars(self, mock_psycopg2):
        """__init__ should read connection parameters from environment."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(
            os.environ,
            {
                'HONEY_PG_HOST': 'pg.example.com',
                'HONEY_PG_PORT': '5433',
                'HONEY_PG_DB': 'mydb',
                'HONEY_PG_USER': 'myuser',
                'HONEY_PG_PASSWORD': 'mypass',
            },
            clear=True,
        ):
            storage = PostgreSQLStorage()

        assert storage._host == 'pg.example.com'
        assert storage._port == 5433
        assert storage._database == 'mydb'
        assert storage._user == 'myuser'
        assert storage._password == 'mypass'

    def test_init_with_explicit_params(self, mock_psycopg2):
        """__init__ should accept explicit parameters over env vars."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {'HONEY_PG_HOST': 'env.host'}, clear=True):
            storage = PostgreSQLStorage(
                host='explicit.host', port=9999, database='db', user='u', password='p'
            )

        assert storage._host == 'explicit.host'
        assert storage._port == 9999
        assert storage._database == 'db'
        assert storage._user == 'u'
        assert storage._password == 'p'

    def test_init_default_env_values(self, mock_psycopg2):
        """__init__ should use default values when env vars are not set."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()

        assert storage._host == '127.0.0.1'
        assert storage._port == 5432
        assert storage._database == 'honeypot'
        assert storage._user == 'postgres'
        assert storage._password == 'postgres'

    def test_init_creates_lock(self, mock_psycopg2):
        """__init__ should create a threading Lock."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        assert storage._lock is not None


class TestPostgreSQLStorageInitDb:
    """Tests for PostgreSQLStorage._init_db()."""

    def test_init_db_raises_import_error_without_psycopg2(self):
        """_init_db should raise ImportError if psycopg2 is not available."""
        with patch.dict('sys.modules', {'psycopg2': None}):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(ImportError, match='psycopg2'):
                    PostgreSQLStorage()

    def test_init_db_raises_import_error_when_module_missing(self):
        """_init_db should raise ImportError when psycopg2 module is absent."""
        # Ensure psycopg2 is not in sys.modules
        with patch.dict('sys.modules', {k: v for k, v in sys.modules.items() if k != 'psycopg2'}):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(ImportError, match='psycopg2 is required'):
                    PostgreSQLStorage()

    def test_init_db_success_with_mocked_psycopg2(self):
        """_init_db should succeed when psycopg2.connect works."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        with patch(
            'sys.modules',
            {'psycopg2': MagicMock(connect=MagicMock(return_value=mock_conn))},
        ):
            with patch.dict(os.environ, {}, clear=True):
                storage = PostgreSQLStorage()

        mock_conn.cursor.assert_called()
        mock_conn.commit.assert_called()
        assert storage._conn is not None


class TestPostgreSQLStorageInsert:
    """Tests for PostgreSQLStorage.insert()."""

    def test_insert_with_mocked_connection(self, mock_psycopg2):
        """insert() should work with a mocked connection."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = mock_conn

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {'path': '/test', 'command': 'GET'},
            'raw_request': 'GET /test HTTP/1.1',
            'is_detected': 1,
            'hive_id': 42,
            'login': 'admin',
        }

        storage.insert(record)
        # execute was called twice: once for CREATE TABLE in _init_db, once for INSERT
        assert mock_cursor.execute.call_count >= 1
        # The last call should be the INSERT
        call_args = mock_cursor.execute.call_args_list[-1]
        assert 'INSERT INTO honeypot_bears' in call_args[0][0]
        mock_conn.commit.assert_called()

    def test_insert_handles_missing_conn(self, mock_psycopg2):
        """insert() should log an error and return when _conn is None."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = None

        record = {'ip': '10.0.0.1'}
        # Should not raise
        storage.insert(record)


class TestPostgreSQLStorageClose:
    """Tests for PostgreSQLStorage.close()."""

    def test_close_closes_connection(self, mock_psycopg2):
        """close() should close the PostgreSQL connection."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = mock_conn

        storage.close()
        mock_conn.close.assert_called_once()
        assert storage._conn is None

    def test_close_with_none_connection(self, mock_psycopg2):
        """close() should not raise when _conn is None."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = None

        # Should not raise
        storage.close()

    def test_close_twice(self, mock_psycopg2):
        """close() should be safe to call multiple times."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = mock_conn

        storage.close()
        storage.close()  # Should not raise


class TestPostgreSQLStorageContextManager:
    """Tests for PostgreSQLStorage.__enter__/__exit__."""

    def test_enter_returns_self(self, mock_psycopg2):
        """__enter__ should return the storage instance."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = mock_conn

        with storage as s:
            assert s is storage

    def test_exit_closes_connection(self, mock_psycopg2):
        """__exit__ should close the connection."""
        mock_conn = MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(os.environ, {}, clear=True):
            storage = PostgreSQLStorage()
        storage._conn = mock_conn

        with storage:
            pass

        assert storage._conn is None


# ---------------------------------------------------------------------------
# get_storage factory tests
# ---------------------------------------------------------------------------


class TestGetStorage:
    """Tests for get_storage() factory function."""

    def test_get_storage_returns_sqlite_by_default(self):
        """get_storage() should return SQLiteStorage when no backend is set."""
        with patch.dict(os.environ, {}, clear=True):
            storage = get_storage()
        assert isinstance(storage, SQLiteStorage)

    def test_get_storage_returns_sqlite_when_backend_is_sqlite(self):
        """get_storage() should return SQLiteStorage when HONEY_DB_BACKEND=sqlite."""
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'sqlite'}, clear=True):
            storage = get_storage()
        assert isinstance(storage, SQLiteStorage)

    def test_get_storage_returns_postgresql_when_backend_is_postgresql(self):
        """get_storage() should return PostgreSQLStorage when HONEY_DB_BACKEND=postgresql."""
        mock_pg = MagicMock(spec=PostgreSQLStorage)
        with patch('manyfaced.db.storage.PostgreSQLStorage', return_value=mock_pg):
            with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'postgresql'}, clear=True):
                storage = get_storage()
        assert storage is mock_pg

    def test_get_storage_returns_postgresql_case_insensitive(self):
        """get_storage() should accept case-insensitive backend names."""
        mock_pg = MagicMock(spec=PostgreSQLStorage)
        with patch('manyfaced.db.storage.PostgreSQLStorage', return_value=mock_pg):
            with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'PostgreSQL'}, clear=True):
                storage = get_storage()
        assert storage is mock_pg

    def test_get_storage_returns_sqlite_for_unknown_backend(self):
        """get_storage() should fall back to SQLiteStorage for unknown backends."""
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'mysql'}, clear=True):
            storage = get_storage()
        assert isinstance(storage, SQLiteStorage)


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests for storage insert methods."""

    def test_sqlite_insert_empty_parsed_request(self, tmp_path):
        """insert() should handle empty parsed_request dict gracefully."""
        db_path = str(tmp_path / 'edge1.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()
        storage.close()

    def test_sqlite_insert_missing_parsed_request_key(self, tmp_path):
        """insert() should handle record without parsed_request key."""
        db_path = str(tmp_path / 'edge2.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()
        storage.close()

    def test_sqlite_insert_fallback_to_record_level_keys(self, tmp_path):
        """insert() should fall back to record-level keys when parsed_request is empty."""
        db_path = str(tmp_path / 'edge3.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET /path HTTP/1.1',
            'request_path': '/path',
            'request_command': 'GET',
            'request_version': 'HTTP/1.1',
            'ua': 'TestAgent',
            'is_detected': 1,
            'hive_id': 10,
            'HIVELOGIN': 'root',
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute(
            'SELECT request_path, request_command, bot_user_agent, hive_id, login FROM honeypot_bears'
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == '/path'
        assert row[1] == 'GET'
        assert row[2] == 'TestAgent'
        assert row[3] == 10
        assert row[4] == 'root'
        storage.close()

    def test_sqlite_insert_string_timestamp(self, tmp_path):
        """insert() should handle string timestamps."""
        db_path = str(tmp_path / 'edge4.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00.123456',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 0,
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT timestamp FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == '2024-01-01 00:00:00.123456'
        storage.close()

    def test_sqlite_insert_with_all_record_keys(self, tmp_path):
        """insert() should handle a record with both parsed_request and record-level keys."""
        db_path = str(tmp_path / 'edge5.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'testhost',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {
                'path': '/from-parsed',
                'command': 'GET',
                'request_version': 'HTTP/1.1',
                'user_agent': 'ParsedAgent',
            },
            'raw_request': 'GET /raw HTTP/1.1',
            'country': 'US',
            'continent': 'NA',
            'tracert': 'hop1',
            'dns_name': 'dns.test',
            'is_detected': 1,
            'hive_id': 5,
            'login': 'admin',
        }

        storage.insert(record)
        storage._conn.commit()

        cursor = storage._conn.cursor()
        cursor.execute('SELECT * FROM honeypot_bears')
        row = cursor.fetchone()
        assert row is not None
        assert row[4] == '/from-parsed'  # request_path from parsed
        assert row[5] == 'GET'  # request_command from parsed
        assert row[8] == 'ParsedAgent'  # bot_user_agent from parsed
        assert row[9] == 'US'  # bot_country from record
        assert row[15] == 'admin'  # login from record
        storage.close()
