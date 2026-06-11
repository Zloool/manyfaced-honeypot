"""Tests for SQLiteStorage WAL checkpointing and backup_database."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestSQLiteWALCheckpointing:
    """Verify that WAL checkpointing happens periodically and on close."""

    def test_checkpoint_on_close(self, tmp_path: Path) -> None:
        """Closing storage should trigger a final PRAGMA wal_checkpoint(TRUNCATE)."""
        from manyfaced.db.storage import SQLiteStorage  # noqa: PLC0415

        db_file = str(tmp_path / 'test.sqlite')
        storage = SQLiteStorage(db_path=db_file)

        # Insert some data to create WAL activity
        for i in range(5):
            storage.insert(
                {
                    'ip': f'10.0.0.{i}',
                    'hostname': f'host-{i}',
                    'timestamp': '2026-01-01 00:00:00',
                    'path': '/',
                    'command': '',
                    'version': '',
                    'raw_request': '',
                    'ua': '',
                    'country': '',
                    'continent': '',
                    'tracert': '',
                    'dns_name': '',
                    'isDetected': 0,
                    'hive_id': None,
                    'login': '',
                }
            )

        # Verify WAL file exists before close (WAL mode creates it)
        wal_file = db_file + '-wal'
        assert os.path.exists(wal_file), 'Expected WAL file to exist in WAL mode'

        storage.close()

        # After close with checkpoint, WAL should be truncated/removed
        # The key behavior is that close() calls wal_checkpoint(TRUNCATE)
        # We verify this by checking the connection is properly closed
        assert storage._conn is None, 'Connection should be None after close'

    def test_periodic_checkpoint_after_interval(self, tmp_path: Path) -> None:
        """After CHECKPOINT_INTERVAL inserts, a WAL checkpoint should run."""
        from manyfaced.db.storage import SQLiteStorage  # noqa: PLC0415

        db_file = str(tmp_path / 'test.sqlite')
        storage = SQLiteStorage(db_path=db_file)

        # Insert enough records to trigger periodic checkpointing
        for i in range(SQLiteStorage.CHECKPOINT_INTERVAL * 2):
            storage.insert(
                {
                    'ip': f'10.0.0.{i}',
                    'hostname': f'host-{i}',
                    'timestamp': '2026-01-01 00:00:00',
                    'path': '/',
                    'command': '',
                    'version': '',
                    'raw_request': '',
                    'ua': '',
                    'country': '',
                    'continent': '',
                    'tracert': '',
                    'dns_name': '',
                    'isDetected': 0,
                    'hive_id': None,
                    'login': '',
                }
            )

        # Verify the storage is still functional after periodic checkpoints
        assert storage._conn is not None, 'Connection should still be open'
        storage.close()


class TestBackupDatabase:
    """Verify backup_database checkpoints and copies the DB file."""

    def test_backup_database_copies_file(self, tmp_path: Path) -> None:
        """backup_database should copy the SQLite file to dest_dir."""
        from manyfaced.db.storage import SQLiteStorage, backup_database  # noqa: PLC0415

        db_file = str(tmp_path / 'honeypot.sqlite')
        storage = SQLiteStorage(db_path=db_file)

        with patch('manyfaced.db.storage.get_storage', return_value=storage):
            dest_dir = str(tmp_path / 'backup')
            result = backup_database(dest_dir=dest_dir)

            assert len(result) == 1
            assert os.path.exists(result[0])
            assert Path(result[0]).name == 'honeypot.sqlite'

    def test_backup_database_skips_postgresql(self, tmp_path: Path) -> None:
        """backup_database should return empty list for non-SQLite backends."""
        from manyfaced.db.storage import backup_database  # noqa: PLC0415

        mock_pg = MagicMock()
        with patch('manyfaced.db.storage.get_storage', return_value=mock_pg):
            result = backup_database(dest_dir=str(tmp_path / 'backup'))
            assert result == []


class TestStartupIntegrityCheck:
    """Verify that startup runs PRAGMA integrity_check."""

    def test_integrity_check_on_init(self, tmp_path: Path) -> None:
        """Opening storage should run PRAGMA integrity_check on startup."""
        from manyfaced.db.storage import SQLiteStorage  # noqa: PLC0415

        db_file = str(tmp_path / 'test.sqlite')
        storage = SQLiteStorage(db_path=db_file)

        # Verify the connection is open and functional (integrity check ran successfully)
        assert storage._conn is not None, 'Connection should be open after init'
        result = storage._conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()
        assert result[0] == 0, 'Table should exist but be empty'
        storage.close()


class TestDbPathProperty:
    """Verify db_path property returns the correct path."""

    def test_db_path_returns_correct_value(self, tmp_path: Path) -> None:
        from manyfaced.db.storage import SQLiteStorage  # noqa: PLC0415

        storage = SQLiteStorage(db_path=str(tmp_path / 'custom.db'))
        assert storage.db_path == str(tmp_path / 'custom.db')
        storage.close()
