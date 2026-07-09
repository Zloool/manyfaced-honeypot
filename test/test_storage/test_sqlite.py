"""Tests for SQLiteStorage (init, insert, close, context manager, multiple inserts)."""

import os
import sqlite3
from datetime import datetime
from unittest.mock import patch

# Imports handled by conftest.py sys.path setup
from manyfaced.db.storage import SQLiteStorage, StorageBackend, _CREATE_TABLE_SQL  # noqa: E402


# ---------------------------------------------------------------------------
# StorageBackend abstract base class tests
# ---------------------------------------------------------------------------


class TestStorageBackend:
    """Tests for the abstract StorageBackend class."""

    def test_storage_backend_is_abstract(self):
        """StorageBackend cannot be instantiated directly."""
        import pytest

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

        import pytest

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

    def test_insert_handles_missing_conn(self, tmp_path):
        """insert() should log an error and return when _conn is None."""
        db_path = str(tmp_path / 'missing_conn.db')
        storage = SQLiteStorage(db_path=db_path)
        # Simulate a missing connection
        storage._conn = None

        record = {'ip': '10.0.0.1'}
        storage.insert(record)  # Should not raise

        # Verify no row was inserted - connection was set to None,
        # so we can't query it. The important thing is that no exception was raised
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
        # HIVELOGIN is the sensor ID, NOT credentials — login should be empty
        assert row[4] == ''
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


class TestInsertLockContention:
    """Coverage for the process-wide _WRITE_LOCK + 'database is locked' retry."""

    def _make_storage_with_mock_conn(self, db_path):
        from unittest.mock import MagicMock

        storage = SQLiteStorage(db_path=db_path)
        # Replace the real (read-only) connection with a mock so we can
        # script execute() failures without touching sqlite internals.
        storage._conn = MagicMock()
        storage._conn.execute.return_value = None
        return storage

    def test_insert_retries_on_database_locked(self, tmp_path):
        """A transient 'database is locked' is retried and the insert returns."""
        import sqlite3

        db_path = str(tmp_path / 'locked.db')
        storage = self._make_storage_with_mock_conn(db_path)

        calls = {'n': 0}

        def flaky(sql, params=None):
            calls['n'] += 1
            if calls['n'] == 1:
                raise sqlite3.OperationalError('database is locked')
            return None

        storage._conn.execute.side_effect = flaky
        storage.insert({'ip': '10.0.0.5'})  # must not raise
        storage.close()

        assert calls['n'] >= 2  # at least one failure + one success

    def test_insert_gives_up_after_persistent_lock(self, tmp_path):
        """Persistently locked DB is logged and the record is dumped (not lost)."""
        import sqlite3
        from unittest.mock import patch

        db_path = str(tmp_path / 'locked2.db')
        storage = self._make_storage_with_mock_conn(db_path)
        storage._conn.execute.side_effect = sqlite3.OperationalError('database is locked')

        with patch('manyfaced.common.utils.dump_file') as mock_dump:
            storage.insert({'ip': '10.0.0.6'})  # must not raise
        storage.close()

        # The record must survive via the JSONL dump fallback, not be dropped.
        mock_dump.assert_called_once()
        dumped = mock_dump.call_args.args[0]
        assert dumped['ip'] == '10.0.0.6'
        assert dumped['_dump_reason'] == 'sqlite_lock_contention'


class TestRetentionArchiveDelete:
    """Coverage for retention jobs using the module-wide _WRITE_LOCK (#179)
    and the archive-doesn't-lose-rows guarantee (#178)."""

    def _seed(self, storage, rows):
        """Insert rows directly into the storage connection (bypasses insert()).

        rows: list of (id, bot_ip, hostname, timestamp) tuples.
        """
        ph = ','.join(['?'] * 4)
        storage._conn.executemany(
            f'INSERT INTO honeypot_bears (id, bot_ip, hostname, timestamp) VALUES ({ph})', rows
        )
        storage._conn.commit()

    def test_archive_deletes_only_archived_rows(self, tmp_path):
        """archive_old_records deletes only rows that were copied to archive."""
        db = tmp_path / 'h.db'
        storage = SQLiteStorage(db_path=str(db))
        old_ts = '2000-01-01 00:00:00.000000'
        new_ts = '2099-01-01 00:00:00.000000'
        self._seed(
            storage,
            [
                (1, '10.0.0.1', 'h1', old_ts),
                (2, '10.0.0.2', 'h2', old_ts),
                (3, '10.0.0.3', 'h3', new_ts),
            ],
        )

        dest = str(tmp_path / 'archive.sqlite')
        result = storage.archive_old_records(days=1, dest_db=dest)
        storage.close()

        assert result == dest
        # Old rows gone from main, new row preserved.
        main = sqlite3.connect(str(db))
        remaining = {r[0] for r in main.execute('SELECT id FROM honeypot_bears')}
        main.close()
        assert remaining == {3}
        # Both old rows present in archive.
        arc = sqlite3.connect(dest)
        archived = {r[0] for r in arc.execute('SELECT id FROM honeypot_bears_archive')}
        arc.close()
        assert archived == {1, 2}

    def test_archive_idempotent_on_partial_retry(self, tmp_path):
        """A retry after a partial archive (row already in archive) must still
        delete the row from the main table, not strand it in both tables (#225).

        Scenario: row 1 was committed to the archive DB in a prior run whose
        main-table DELETE then failed. On retry, the archive INSERT for row 1
        hits a PK conflict; with INSERT OR IGNORE it is treated as archived and
        the row is deleted from main, leaving no duplicate.
        """
        db = tmp_path / 'h.db'
        storage = SQLiteStorage(db_path=str(db))
        old_ts = '2000-01-01 00:00:00.000000'
        new_ts = '2099-01-01 00:00:00.000000'
        self._seed(
            storage,
            [
                (1, '10.0.0.1', 'h1', old_ts),
                (2, '10.0.0.2', 'h2', old_ts),
                (3, '10.0.0.3', 'h3', new_ts),
            ],
        )

        dest = str(tmp_path / 'archive.sqlite')
        # Pre-seed the archive with row 1 already present (simulating the prior
        # partial run that committed the archive but failed the main delete).
        arc = sqlite3.connect(dest)
        arc.execute('PRAGMA journal_mode=WAL')
        arc.execute(_CREATE_TABLE_SQL.replace('honeypot_bears', 'honeypot_bears_archive'))
        arc.execute(
            'INSERT INTO honeypot_bears_archive (id, bot_ip, hostname, timestamp) '
            'VALUES (?, ?, ?, ?)',
            (1, '10.0.0.1', 'h1', old_ts),
        )
        arc.commit()
        arc.close()

        result = storage.archive_old_records(days=1, dest_db=dest)
        storage.close()

        assert result == dest
        # All old rows (1 and 2) removed from main; new row 3 preserved.
        main = sqlite3.connect(str(db))
        remaining = {r[0] for r in main.execute('SELECT id FROM honeypot_bears')}
        main.close()
        assert remaining == {3}
        # Archive contains exactly {1, 2} — no duplicate of row 1.
        arc = sqlite3.connect(dest)
        archived = {r[0] for r in arc.execute('SELECT id FROM honeypot_bears_archive')}
        arc.close()
        assert archived == {1, 2}

    def test_archive_keeps_rows_when_copy_fails(self, tmp_path):
        """If the archive copy fails, no rows are deleted (no data loss)."""
        db = tmp_path / 'h.db'
        storage = SQLiteStorage(db_path=str(db))
        old_ts = '2000-01-01 00:00:00.000000'
        self._seed(storage, [(1, '10.0.0.1', 'h1', old_ts), (2, '10.0.0.2', 'h2', old_ts)])

        # Break the archive DB so every row insert fails, but keep the main conn alive.
        real_connect = sqlite3.connect

        class _BrokenConn:
            def __init__(self, conn):
                self._conn = conn

            def __getattr__(self, name):
                return getattr(self._conn, name)

            def execute(self, *args, **kwargs):
                raise sqlite3.Error('disk full')

        def _connect(path, *args, **kwargs):
            conn = real_connect(path, *args, **kwargs)
            if 'archive' in str(path):
                return _BrokenConn(conn)
            return conn

        with patch('manyfaced.db.storage.sqlite3.connect', side_effect=_connect):
            result = storage.archive_old_records(days=1)
        storage.close()

        # Archive aborted; main table must be untouched.
        assert result is None
        main = sqlite3.connect(str(db))
        remaining = {r[0] for r in main.execute('SELECT id FROM honeypot_bears')}
        main.close()
        assert remaining == {1, 2}

    def test_delete_old_records_removes_old_rows(self, tmp_path):
        db = tmp_path / 'h.db'
        storage = SQLiteStorage(db_path=str(db))
        old_ts = '2000-01-01 00:00:00.000000'
        new_ts = '2099-01-01 00:00:00.000000'
        self._seed(storage, [(1, '10.0.0.1', 'h1', old_ts), (2, '10.0.0.2', 'h2', new_ts)])

        deleted = storage.delete_old_records(days=1)
        storage.close()

        assert deleted == 1
        main = sqlite3.connect(str(db))
        remaining = {r[0] for r in main.execute('SELECT id FROM honeypot_bears')}
        main.close()
        assert remaining == {2}


class TestListenPortColumn:
    """Tests for the issue #299 listen_port column (insert, default, migration, aggregate)."""

    def test_insert_round_trips_listen_port(self, tmp_path):
        """A record with a non-zero listen_port is stored and read back (issue #299)."""
        db_path = str(tmp_path / 'port_roundtrip.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.1',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 1,
            'listen_port': 8080,
        }
        storage.insert(record)
        storage._conn.commit()

        row = storage._conn.execute('SELECT listen_port FROM honeypot_bears').fetchone()
        assert row[0] == 8080

        # recent_records() should surface the new column.
        recs = storage.recent_records(limit=1)
        assert recs and recs[0]['listen_port'] == 8080
        storage.close()

    def test_insert_defaults_listen_port_to_zero(self, tmp_path):
        """A record without listen_port stores 0 (unknown), not NULL/error (issue #299)."""
        db_path = str(tmp_path / 'port_default.db')
        storage = SQLiteStorage(db_path=db_path)

        record = {
            'ip': '10.0.0.2',
            'hostname': 'test',
            'timestamp': '2024-01-01 00:00:00',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'is_detected': 0,
        }
        storage.insert(record)
        storage._conn.commit()

        row = storage._conn.execute('SELECT listen_port FROM honeypot_bears').fetchone()
        assert row[0] == 0
        storage.close()

    def test_migration_adds_column_to_pre_299_db(self, tmp_path):
        """A DB created WITHOUT listen_port gets the column added at startup (issue #299)."""
        db_path = str(tmp_path / 'legacy.db')
        # Build a pre-#299 schema manually (no listen_port column).
        legacy_conn = sqlite3.connect(db_path)
        legacy_conn.close()
        os.remove(db_path)
        legacy_conn = sqlite3.connect(db_path)
        legacy_conn.execute(
            """
            CREATE TABLE honeypot_bears (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                request_path TEXT,
                request_command TEXT,
                request_version TEXT,
                request_raw TEXT,
                bot_user_agent TEXT,
                bot_country TEXT,
                bot_continent TEXT,
                bot_tracert TEXT,
                bot_dns_name TEXT,
                detected_id INTEGER,
                hive_id INTEGER,
                login TEXT,
                bot_profile_data TEXT,
                UNIQUE(bot_ip, timestamp)
            )
            """
        )
        legacy_conn.commit()
        legacy_conn.close()

        # Opening with init_schema=True must migrate (add the column) BEFORE any
        # insert, otherwise inserts referencing listen_port would fail.
        storage = SQLiteStorage(db_path=db_path)  # noqa: F811
        cols = {r[1] for r in storage._conn.execute('PRAGMA table_info(honeypot_bears)').fetchall()}
        assert 'listen_port' in cols

        # And an insert referencing the new column must succeed post-migration.
        storage.insert(
            {
                'ip': '10.0.0.3',
                'hostname': 'test',
                'timestamp': '2024-01-01 00:00:00',
                'parsed_request': {},
                'raw_request': 'GET / HTTP/1.1',
                'is_detected': 0,
                'listen_port': 443,
            }
        )
        storage._conn.commit()
        row = storage._conn.execute('SELECT listen_port FROM honeypot_bears').fetchone()
        assert row[0] == 443
        storage.close()

    def test_migration_adds_classification_columns_to_pre_271_db(self, tmp_path):
        """A DB created WITHOUT the #271 columns gets them added at startup, and
        an insert carrying classification/bot_asn/bot_org/benign_source succeeds
        post-migration (issue #271)."""
        db_path = str(tmp_path / 'legacy271.db')
        legacy_conn = sqlite3.connect(db_path)
        legacy_conn.execute(
            """
            CREATE TABLE honeypot_bears (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                request_path TEXT,
                request_command TEXT,
                request_version TEXT,
                request_raw TEXT,
                bot_user_agent TEXT,
                bot_country TEXT,
                bot_continent TEXT,
                bot_tracert TEXT,
                bot_dns_name TEXT,
                detected_id INTEGER,
                hive_id INTEGER,
                login TEXT,
                bot_profile_data TEXT,
                listen_port INTEGER,
                UNIQUE(bot_ip, timestamp)
            )
            """
        )
        legacy_conn.commit()
        legacy_conn.close()

        storage = SQLiteStorage(db_path=db_path)
        cols = {r[1] for r in storage._conn.execute('PRAGMA table_info(honeypot_bears)').fetchall()}
        for new_col in ('bot_asn', 'bot_org', 'classification', 'benign_source'):
            assert new_col in cols, f'missing migrated column {new_col}'

        storage.insert(
            {
                'ip': '10.0.0.7',
                'hostname': 'test',
                'timestamp': '2024-01-01 00:00:00',
                'parsed_request': {},
                'raw_request': 'GET / HTTP/1.1',
                'is_detected': 0,
                'listen_port': 443,
                'bot_asn': 'AS13335',
                'bot_org': 'Cloudflare, Inc.',
                'classification': 'benign',
                'benign_source': 'cloudflare-cdn',
            }
        )
        storage._conn.commit()
        row = storage._conn.execute(
            'SELECT bot_asn, bot_org, classification, benign_source FROM honeypot_bears'
        ).fetchone()
        assert row == ('AS13335', 'Cloudflare, Inc.', 'benign', 'cloudflare-cdn')
        # The classification index must exist (idempotent CREATE INDEX).
        indexes = {
            r[0]
            for r in storage._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert 'idx_bears_classification' in indexes
        storage.close()

    def test_aggregate_stats_by_port(self, tmp_path):
        """aggregate_stats() returns a by_port breakdown grouped by listen_port (issue #299)."""
        db_path = str(tmp_path / 'by_port.db')
        storage = SQLiteStorage(db_path=db_path)

        rows = [
            ('10.0.0.1', '2024-01-01 00:00:01', 80),
            ('10.0.0.2', '2024-01-01 00:00:02', 80),
            ('10.0.0.3', '2024-01-01 00:00:03', 443),
            ('10.0.0.4', '2024-01-01 00:00:04', 0),  # unknown port excluded
        ]
        for ip, ts, port in rows:
            storage.insert(
                {
                    'ip': ip,
                    'hostname': 'h',
                    'timestamp': ts,
                    'parsed_request': {},
                    'raw_request': 'GET / HTTP/1.1',
                    'is_detected': 1,
                    'listen_port': port,
                }
            )
        storage._conn.commit()

        stats = storage.aggregate_stats(since='all')
        by_port = {int(r['key']): r['count'] for r in stats['by_port']}
        assert by_port.get(80) == 2
        assert by_port.get(443) == 1
        # listen_port = 0 (unknown) is excluded from the grouping.
        assert by_port.get(0) is None
        storage.close()

    def test_aggregate_stats_unique_ips(self, tmp_path):
        """aggregate_stats() reports COUNT(DISTINCT bot_ip) (issue #326 dashboard redesign)."""
        storage = SQLiteStorage(db_path=str(tmp_path / 'uniq.db'))
        for ip, ts in [
            ('10.0.0.1', '2024-01-01 00:00:01'),
            ('10.0.0.1', '2024-01-01 00:00:02'),
            ('10.0.0.2', '2024-01-01 00:00:03'),
        ]:
            storage.insert(
                {
                    'ip': ip,
                    'hostname': 'h',
                    'timestamp': ts,
                    'parsed_request': {},
                    'raw_request': 'GET / HTTP/1.1',
                    'is_detected': 1,
                }
            )
        storage._conn.commit()
        stats = storage.aggregate_stats()
        assert stats['total'] == 3
        assert stats['unique_ips'] == 2
        storage.close()

    def test_aggregate_stats_since_resolves_pre_computed_cutoff(self, tmp_path):
        """A caller-resolved absolute ISO cutoff (not a '24h'-style token) must still filter.

        Regression test: dashboard._parse_range() already resolves the window
        into an absolute cutoff before calling aggregate_stats(); passing that
        cutoff straight through must not be silently dropped.
        """
        storage = SQLiteStorage(db_path=str(tmp_path / 'cutoff.db'))
        storage.insert(
            {
                'ip': '10.0.0.1',
                'hostname': 'h',
                'timestamp': '2020-01-01 00:00:00.000',
                'parsed_request': {},
                'raw_request': 'old',
                'is_detected': 1,
            }
        )
        storage.insert(
            {
                'ip': '10.0.0.2',
                'hostname': 'h',
                'timestamp': '2030-01-01 00:00:00.000',
                'parsed_request': {},
                'raw_request': 'new',
                'is_detected': 1,
            }
        )
        storage._conn.commit()
        stats = storage.aggregate_stats(since='2025-01-01 00:00:00.000')
        assert stats['total'] == 1
        assert stats['by_ip'][0]['key'] == '10.0.0.2'
        storage.close()

    def test_volume_series_buckets_and_port_filter(self, tmp_path):
        """volume_series() groups by bucket and optionally scopes to one listen_port."""
        storage = SQLiteStorage(db_path=str(tmp_path / 'vol.db'))
        rows = [
            ('10.0.0.1', '2024-01-01 10:00:00.000', 80),
            ('10.0.0.2', '2024-01-01 10:20:00.000', 80),
            ('10.0.0.3', '2024-01-01 11:00:00.000', 443),
        ]
        for ip, ts, port in rows:
            storage.insert(
                {
                    'ip': ip,
                    'hostname': 'h',
                    'timestamp': ts,
                    'parsed_request': {},
                    'raw_request': 'x',
                    'is_detected': 1,
                    'listen_port': port,
                }
            )
        storage._conn.commit()

        hourly = {r['bucket']: r['count'] for r in storage.volume_series(bucket='hour')}
        assert hourly['2024-01-01 10:00'] == 2
        assert hourly['2024-01-01 11:00'] == 1

        port_80_only = {
            r['bucket']: r['count'] for r in storage.volume_series(bucket='hour', port=80)
        }
        assert port_80_only == {'2024-01-01 10:00': 2}

        five_min = {r['bucket']: r['count'] for r in storage.volume_series(bucket='minute5')}
        assert five_min['2024-01-01 10:00:00'] == 1
        assert five_min['2024-01-01 10:20:00'] == 1
        storage.close()

    def test_volume_series_no_connection_returns_empty(self, tmp_path):
        storage = SQLiteStorage(db_path=str(tmp_path / 'noconn.db'))
        storage._conn = None
        assert storage.volume_series() == []
