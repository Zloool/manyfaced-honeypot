"""Storage backend module for honeypot bear records.

Replaces the ClickHouse-based dbconnect.py with SQLite (default) or
PostgreSQL backends. Supports configuration via environment variables
and provides a factory function for runtime selection.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

try:
    import psycopg2  # type: ignore[import-untyped,unused-ignore]  # noqa: F401  # Optional dependency for PostgreSQL backend
except ImportError:
    pass  # psycopg2 not installed; PostgreSQL backend will raise ImportError at runtime

logger = logging.getLogger(__name__)

# Process-wide lock serializing all SQLite writes. get_storage() returns a
# fresh SQLiteStorage (and thus a fresh connection) on every call, so the
# per-instance lock cannot coordinate concurrent writer threads. A single
# module-level lock is what actually prevents 'database is locked' under
# the WAL backend when many report threads insert at once.
_WRITE_LOCK = Lock()

# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class StorageBackend(ABC):
    """Abstract base for storage backends."""

    @abstractmethod
    def insert(self, record: dict) -> None:
        """Insert a bear record.

        The record dict is expected to have, at minimum, these keys:

        * ip (str)
        * hostname (str)
        * timestamp (str, ``"%Y-%m-%d %H:%M:%S.%f"``)
        * path (str)
        * command (str)
        * version (str)
        * raw_request (str)
        * ua (str)
        * country (str)
        * continent (str)
        * tracert (str)
        * dns_name (str)
        * isDetected (int)
        * hive_id (any)
        * login (str)
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """Close any connections / resources held by the backend."""
        ...


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def _resolve_db_path() -> str:
    """Return the SQLite database path.

    Precedence (highest to lowest):
      1. HONEY_DB_PATH environment variable
      2. database.path from TOML config (settings.DB_PATH)
      3. Default 'bots/honeypot.sqlite' (relative to CWD)
    """
    env_path = os.environ.get('HONEY_DB_PATH')
    if env_path:
        return env_path

    # Fall back to TOML config setting
    try:
        from manyfaced.common.config import settings  # noqa: PLC0415

        toml_path = getattr(settings, 'DB_PATH', None)
        if toml_path:
            return toml_path
    except Exception:
        pass

    return 'bots/honeypot.sqlite'


def _resolve_backend() -> str:
    """Return the backend name from env or default to 'sqlite'."""
    return os.environ.get('HONEY_DB_BACKEND', 'sqlite').lower()


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------

from manyfaced.db.sql_builder import (  # noqa: E402, F401
    CREATE_TABLE_SQL as _CREATE_TABLE_SQL,
    INSERT_SQL as _INSERT_SQL,
)
from manyfaced.db.sql_builder import extract_record_fields as _extract_record_fields  # noqa: E402


class SQLiteStorage(StorageBackend):
    """SQLite storage backend using stdlib sqlite3.

    Features:
    - WAL mode with periodic checkpointing (every 100 inserts or on close)
    - Startup integrity check with warning on corruption
    - DB path exposed for backup/rotation scripts
    """

    CHECKPOINT_INTERVAL = 100  # Run PRAGMA wal_checkpoint(TRUNCATE) every N inserts

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _resolve_db_path()
        # Ensure parent directories exist
        parent = os.path.dirname(self._db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = Lock()
        self._insert_count = 0
        self._init_db()

    def _init_db(self) -> None:
        """Open the connection, create the table if it does not exist, and run integrity check."""
        try:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute(_CREATE_TABLE_SQL)
            self._conn.commit()

            # Run startup integrity check and warn if corruption is detected
            result = self._conn.execute('PRAGMA integrity_check').fetchone()
            if result and result[0] != 'ok':
                logger.warning('SQLite integrity check failed: %s — DB may be corrupted', result[0])

        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Failed to initialise SQLite database at %s', self._db_path)
            self._conn = None

    # -- public API ----------------------------------------------------------

    def insert(self, record: dict) -> None:  # noqa: C901
        """Insert a single bear record.

        Writes are serialized through the process-wide ``_WRITE_LOCK`` (not the
        per-instance lock, which cannot coordinate the separate connections
        created by get_storage()) and retried on ``database is locked`` so a
        busy WAL backend degrades to a short stall instead of dropping records
        or crashing the server child.
        """
        if self._conn is None:
            logger.error('SQLite storage is not initialised; skipping insert')
            return

        try:
            fields = _extract_record_fields(record)
        except (sqlite3.Error, ValueError, TypeError, KeyError) as e:
            logger.error('Error preparing record for insert: %s', e)
            return

        # Retry loop: SQLite WAL allows only one writer at a time. Under
        # concurrent load a write may transiently hit 'database is locked'.
        last_exc: Exception | None = None
        for attempt in range(5):
            try:
                with _WRITE_LOCK:
                    self._conn.execute(_INSERT_SQL, fields)
                    self._conn.commit()
                    self._insert_count += 1

                    # Periodic WAL checkpoint to prevent unbounded WAL growth
                    if self._insert_count % self.CHECKPOINT_INTERVAL == 0:
                        try:
                            self._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                        except (sqlite3.Error, sqlite3.OperationalError):
                            logger.debug('WAL checkpoint failed (non-critical)')
                return
            except sqlite3.OperationalError as e:
                if 'database is locked' in str(e).lower():
                    last_exc = e
                    time.sleep(0.05 * (attempt + 1))
                    continue
                logger.exception('Error inserting record into SQLite storage')
                return
            except (sqlite3.Error, sqlite3.DatabaseError):
                logger.exception('Error inserting record into SQLite storage')
                return

        if last_exc is not None:
            logger.error(
                'Giving up insert after lock contention (database is locked): %s',
                last_exc,
            )

    def close(self) -> None:
        """Close the SQLite connection with a final WAL checkpoint."""
        if self._conn is not None:
            try:
                # Final checkpoint before closing to ensure clean shutdown
                self._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                self._conn.close()
            except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
                logger.exception('Error closing SQLite connection')
            finally:
                self._conn = None

    @property
    def db_path(self) -> str:
        """Return the path to the SQLite database file."""
        return self._db_path

    def delete_old_records(self, days: int = 90) -> int:
        """Delete records older than *days* days from the honeypot_bears table.

        Args:
            days: Number of days to retain. Records with timestamp older than
                this many days will be deleted. Defaults to 90.

        Returns:
            Number of rows deleted.
        """
        if self._conn is None:
            logger.error('SQLite storage is not initialised; skipping delete')
            return 0

        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            with self._lock:
                cursor = self._conn.execute(
                    'SELECT COUNT(*) FROM honeypot_bears WHERE timestamp < ?',
                    (cutoff,),
                )
                count = cursor.fetchone()[0]

                if count > 0:
                    self._conn.execute(
                        'DELETE FROM honeypot_bears WHERE timestamp < ?',
                        (cutoff,),
                    )
                    self._conn.commit()
                    logger.info('Deleted %d records older than %d days', count, days)

                return count

        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error deleting old records from SQLite storage')
            return 0

    def archive_old_records(self, days: int = 90, dest_db: str | None = None) -> str | None:
        """Archive records older than *days* days to a separate database file.

        Creates an archive table (honeypot_bears_archive) in the destination DB
        and copies old records there before deleting them from the main table.

        Args:
            days: Number of days to retain. Records with timestamp older than
                this many days will be archived. Defaults to 90.
            dest_db: Path to the archive database file. If None, creates a file
                named 'honeypot_archive_YYYYMMDD.sqlite' in the same directory
                as the main database.

        Returns:
            Path to the created archive database, or None on failure.
        """
        if self._conn is None:
            logger.error('SQLite storage is not initialised; skipping archive')
            return None

        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            with self._lock:
                # Count records to archive
                cursor = self._conn.execute(
                    'SELECT COUNT(*) FROM honeypot_bears WHERE timestamp < ?',
                    (cutoff,),
                )
                count = cursor.fetchone()[0]

                if count == 0:
                    logger.info('No records older than %d days to archive', days)
                    return None

                # Determine destination path
                if dest_db is None:
                    date_str = datetime.now().strftime('%Y%m%d')
                    db_dir = os.path.dirname(self._db_path) or '.'
                    dest_db = os.path.join(db_dir, f'honeypot_archive_{date_str}.sqlite')

                # Create archive DB with same schema
                archive_conn = sqlite3.connect(dest_db)
                archive_conn.execute('PRAGMA journal_mode=WAL')
                archive_conn.execute(
                    _CREATE_TABLE_SQL.replace('honeypot_bears', 'honeypot_bears_archive')
                )
                archive_conn.commit()

                # Copy old records to archive
                rows = self._conn.execute(
                    'SELECT * FROM honeypot_bears WHERE timestamp < ?',
                    (cutoff,),
                ).fetchall()

                col_names = [
                    desc[0]
                    for desc in self._conn.execute(
                        'SELECT * FROM honeypot_bears LIMIT 0'
                    ).description
                ]
                placeholders = ','.join(['?' for _ in col_names])
                insert_sql = f'INSERT INTO honeypot_bears_archive VALUES ({placeholders})'

                with archive_conn:
                    for row in rows:
                        try:
                            archive_conn.execute(insert_sql, row)
                        except sqlite3.Error:
                            logger.debug('Failed to archive row %s', row)

                archive_conn.commit()
                archive_conn.close()

                # Delete archived records from main table
                self._conn.execute('DELETE FROM honeypot_bears WHERE timestamp < ?', (cutoff,))
                self._conn.commit()
                logger.info('Archived %d records to %s', count, dest_db)

                return dest_db

        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error archiving old records from SQLite storage')
            return None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> 'SQLiteStorage':
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------

from manyfaced.db.sql_builder import (  # noqa: E402, F401
    CREATE_TABLE_PG_SQL as _CREATE_TABLE_PG_SQL,
    INSERT_PG_SQL as _INSERT_PG_SQL,
)


class PostgreSQLStorage(StorageBackend):
    """PostgreSQL storage backend using psycopg2."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        self._host = host or os.environ.get('HONEY_PG_HOST', '127.0.0.1')
        self._port = port or int(os.environ.get('HONEY_PG_PORT', '5432'))
        self._database = database or os.environ.get('HONEY_PG_DB', 'honeypot')
        self._user = user or os.environ.get('HONEY_PG_USER', 'postgres')
        self._password = password or os.environ.get('HONEY_PG_PASSWORD', 'postgres')
        self._conn: Any = None
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Connect to PostgreSQL and create the table if it does not exist."""
        try:
            import psycopg2  # noqa: PLC0415  # pyright: ignore[reportMissingModuleSource]
        except ImportError:
            raise ImportError(
                'psycopg2 is required for PostgreSQL backend. '
                'Install it with: pip install psycopg2-binary'
            )
        try:
            self._conn = psycopg2.connect(
                host=self._host,
                port=self._port,
                database=self._database,
                user=self._user,
                password=self._password,
            )
            with self._conn.cursor() as cur:
                cur.execute(_CREATE_TABLE_PG_SQL)
            self._conn.commit()
        except psycopg2.Error:  # noqa: BLE001
            logger.exception('Failed to initialise PostgreSQL storage')
            self._conn = None

    # -- public API ----------------------------------------------------------

    def insert(self, record: dict) -> None:  # noqa: C901
        """Insert a single bear record."""
        if self._conn is None:
            logger.error('PostgreSQL storage is not initialised; skipping insert')
            return

        try:
            fields = _extract_record_fields(record)
            with self._lock:
                with self._conn.cursor() as cur:
                    cur.execute(_INSERT_PG_SQL, fields)
                self._conn.commit()
        except psycopg2.Error:  # noqa: BLE001
            logger.exception('Error inserting record into PostgreSQL storage')

    def close(self) -> None:
        """Close the PostgreSQL connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except psycopg2.Error:  # noqa: BLE001
                logger.exception('Error closing PostgreSQL connection')
            finally:
                self._conn = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> 'PostgreSQLStorage':
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def get_storage() -> StorageBackend:
    """Factory to get the storage backend based on HONEY_DB_BACKEND env var.

    Returns a :class:`SQLiteStorage` or :class:`PostgreSQLStorage` depending on
    the value of the ``HONEY_DB_BACKEND`` environment variable (case-insensitive).
    """
    backend = _resolve_backend()
    if backend == 'postgresql':
        return PostgreSQLStorage()
    # default to SQLite
    return SQLiteStorage()


def backup_database(dest_dir: str | None = None) -> list[str]:
    """Backup the SQLite database, copying both .sqlite and WAL files.

    IMPORTANT: When copying a SQLite database in WAL mode via scp/rsync, you MUST
    either (a) run PRAGMA wal_checkpoint(TRUNCATE) on the server first before
    copying just the .sqlite file, or (b) copy all three files (.sqlite,
    .sqlite-wal, .sqlite-shm). Copying only the main file without checkpointing
    causes "database disk image is malformed" errors.

    This function handles both: it checkpoints first, then copies the main DB file.

    Args:
        dest_dir: Directory to copy backup to. Defaults to 'deployment-analysis/latest'.

    Returns:
        List of copied file paths.
    """
    import shutil  # noqa: PLC0415

    storage = get_storage()
    if not isinstance(storage, SQLiteStorage):
        logger.warning('backup_database only supports SQLite backend')
        return []

    src_path = storage.db_path
    dest_dir = dest_dir or os.path.join(_PROJECT_ROOT, 'deployment-analysis', 'latest')
    os.makedirs(dest_dir, exist_ok=True)

    # Checkpoint first to ensure WAL is written back to main file
    try:
        if isinstance(storage, SQLiteStorage) and storage._conn is not None:
            storage._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    except (sqlite3.Error, sqlite3.OperationalError):
        logger.debug('Pre-backup checkpoint failed (non-critical)')

    # Copy the main database file
    basename = os.path.basename(src_path)
    dest_path = os.path.join(dest_dir, basename)
    shutil.copy2(src_path, dest_path)
    logger.info('Database backed up: %s → %s', src_path, dest_path)

    return [dest_path]


__all__ = [
    'StorageBackend',
    'SQLiteStorage',
    'PostgreSQLStorage',
    'get_storage',
    'backup_database',
]
