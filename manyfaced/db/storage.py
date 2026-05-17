"""Storage backend module for honeypot bear records.

Replaces the ClickHouse-based dbconnect.py with SQLite (default) or
PostgreSQL backends. Supports configuration via environment variables
and provides a factory function for runtime selection.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from abc import ABC, abstractmethod
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)

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
    """SQLite storage backend using stdlib sqlite3."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _resolve_db_path()
        # Ensure parent directories exist
        parent = os.path.dirname(self._db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Open the connection and create the table if it does not exist."""
        try:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute(_CREATE_TABLE_SQL)
            self._conn.commit()
        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Failed to initialise SQLite database at %s', self._db_path)
            self._conn = None

    # -- public API ----------------------------------------------------------

    def insert(self, record: dict) -> None:  # noqa: C901
        """Insert a single bear record."""
        if self._conn is None:
            logger.error('SQLite storage is not initialised; skipping insert')
            return

        try:
            fields = _extract_record_fields(record)
            with self._lock:
                self._conn.execute(_INSERT_SQL, fields)
                self._conn.commit()
        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Error inserting record into SQLite storage')

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
                logger.exception('Error closing SQLite connection')
            finally:
                self._conn = None

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
            import psycopg2  # noqa: PLC0415
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
        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
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
        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Error inserting record into PostgreSQL storage')

    def close(self) -> None:
        """Close the PostgreSQL connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
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


# ---------------------------------------------------------------------------
# Type aliases for clarity
# ---------------------------------------------------------------------------

SQLiteStorageType = SQLiteStorage
PostgreSQLStorageType = PostgreSQLStorage


__all__ = [
    'StorageBackend',
    'SQLiteStorage',
    'PostgreSQLStorage',
    'SQLiteStorageType',
    'PostgreSQLStorageType',
    'get_storage',
]
