"""Tests for PostgreSQLStorage (init, init_db, insert, close, context manager)."""

import os
import sys
from unittest.mock import MagicMock, patch

# Imports handled by conftest.py sys.path setup
from manyfaced.db.storage import PostgreSQLStorage  # noqa: E402


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
                import pytest
                with pytest.raises(ImportError, match='psycopg2'):
                    PostgreSQLStorage()

    def test_init_db_raises_import_error_when_module_missing(self):
        """_init_db should raise ImportError when psycopg2 module is absent."""
        # Ensure psycopg2 is not in sys.modules
        with patch.dict('sys.modules', {k: v for k, v in sys.modules.items() if k != 'psycopg2'}):
            with patch.dict(os.environ, {}, clear=True):
                import pytest
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
