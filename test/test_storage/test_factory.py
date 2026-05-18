"""Tests for get_storage() factory and edge cases."""

import os
from unittest.mock import MagicMock, patch

# Imports handled by conftest.py sys.path setup
from manyfaced.db.storage import SQLiteStorage, PostgreSQLStorage, get_storage  # noqa: E402


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
        # HIVELOGIN is the sensor ID, NOT credentials — login should be empty
        assert row[4] == ''
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
