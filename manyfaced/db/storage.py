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
from datetime import datetime
from threading import Lock
from typing import Any, Dict

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

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _resolve_db_path() -> str:
    """Return the SQLite database path from env or default."""
    return os.environ.get("HONEY_DB_PATH", "bots/honeypot.sqlite")


def _resolve_backend() -> str:
    """Return the backend name from env or default to 'sqlite'."""
    return os.environ.get("HONEY_DB_BACKEND", "sqlite").lower()


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS honeypot_bears (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_ip       TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    request_path TEXT,
    request_command TEXT,
    request_version TEXT,
    request_raw  TEXT,
    bot_user_agent TEXT,
    bot_country  TEXT,
    bot_continent TEXT,
    bot_tracert  TEXT,
    bot_dns_name TEXT,
    detected_id  INTEGER,
    hive_id      INTEGER,
    login        TEXT
)
"""

_INSERT_SQL = """\
INSERT INTO honeypot_bears
    (bot_ip, hostname, timestamp, request_path, request_command,
     request_version, request_raw, bot_user_agent, bot_country,
     bot_continent, bot_tracert, bot_dns_name, detected_id, hive_id, login)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


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
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(_CREATE_TABLE_SQL)
            self._conn.commit()
        except Exception:
            logger.exception("Failed to initialise SQLite database at %s", self._db_path)
            self._conn = None

    # -- public API ----------------------------------------------------------

    def insert(self, record: dict) -> None:  # noqa: C901
        """Insert a single bear record."""
        if self._conn is None:
            logger.error("SQLite storage is not initialised; skipping insert")
            return

        try:
            # Map the record dict to individual fields (extract safely)
            parsed = record.get("parsed_request") or {}

            bot_ip = record.get("ip") or ""
            hostname = record.get("hostname") or ""
            timestamp = record.get("timestamp") or ""
            request_path = parsed.get("path") or record.get("request_path") or ""
            request_command = parsed.get("command") or record.get("request_command") or ""
            request_version = parsed.get("request_version") or parsed.get("version") or record.get("request_version") or ""
            request_raw = record.get("raw_request") or ""
            bot_user_agent = parsed.get("user_agent") or record.get("ua") or ""
            bot_country = record.get("country") or ""
            bot_continent = record.get("continent") or ""
            bot_tracert = record.get("tracert") or ""
            bot_dns_name = record.get("dns_name") or ""
            detected_id = record.get("is_detected")
            if detected_id is None:
                detected_id = record.get("isDetected")
            hive_id = record.get("hive_id")
            login = record.get("login") or record.get("HIVELOGIN") or ""

            # Convert timestamps to text if needed
            if isinstance(timestamp, datetime):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
            timestamp = str(timestamp)

            with self._lock:
                self._conn.execute(
                    _INSERT_SQL,
                    (
                        bot_ip,
                        hostname,
                        timestamp,
                        request_path,
                        request_command,
                        request_version,
                        request_raw,
                        bot_user_agent,
                        bot_country,
                        bot_continent,
                        bot_tracert,
                        bot_dns_name,
                        int(detected_id) if detected_id is not None else None,
                        int(hive_id) if hive_id is not None else None,
                        login,
                    ),
                )
                self._conn.commit()

        except Exception:
            logger.exception("Error inserting record into SQLite storage")

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                logger.exception("Error closing SQLite connection")
            finally:
                self._conn = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "SQLiteStorage":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------

_CREATE_TABLE_PG_SQL = """\
CREATE TABLE IF NOT EXISTS honeypot_bears (
    id           SERIAL PRIMARY KEY,
    bot_ip       VARCHAR(45) NOT NULL,
    hostname     VARCHAR(255),
    timestamp    TEXT NOT NULL,
    request_path VARCHAR(4096),
    request_command VARCHAR(10),
    request_version TEXT,
    request_raw  TEXT,
    bot_user_agent TEXT,
    bot_country  VARCHAR(100),
    bot_continent VARCHAR(100),
    bot_tracert  TEXT,
    bot_dns_name VARCHAR(512),
    detected_id  INTEGER,
    hive_id      INTEGER,
    login        VARCHAR(255)
)
"""

_INSERT_PG_SQL = """\
INSERT INTO honeypot_bears
    (bot_ip, hostname, timestamp, request_path, request_command,
     request_version, request_raw, bot_user_agent, bot_country,
     bot_continent, bot_tracert, bot_dns_name, detected_id, hive_id, login)
VALUES
    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


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
        self._host = host or os.environ.get("HONEY_PG_HOST", "127.0.0.1")
        self._port = port or int(os.environ.get("HONEY_PG_PORT", "5432"))
        self._database = database or os.environ.get("HONEY_PG_DB", "honeypot")
        self._user = user or os.environ.get("HONEY_PG_USER", "postgres")
        self._password = password or os.environ.get("HONEY_PG_PASSWORD", "postgres")
        self._conn: Any = None
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Connect to PostgreSQL and create the table if it does not exist."""
        try:
            import psycopg2
        except ImportError:
            raise ImportError(
                "psycopg2 is required for PostgreSQL backend. "
                "Install it with: pip install psycopg2-binary"
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
        except Exception:
            logger.exception("Failed to initialise PostgreSQL storage")
            self._conn = None

    # -- public API ----------------------------------------------------------

    def insert(self, record: dict) -> None:  # noqa: C901
        """Insert a single bear record."""
        if self._conn is None:
            logger.error("PostgreSQL storage is not initialised; skipping insert")
            return

        try:
            parsed = record.get("parsed_request") or {}

            bot_ip = record.get("ip") or ""
            hostname = record.get("hostname") or ""
            timestamp = record.get("timestamp") or ""
            request_path = parsed.get("path") or record.get("request_path") or ""
            request_command = parsed.get("command") or record.get("request_command") or ""
            request_version = parsed.get("request_version") or parsed.get("version") or record.get("request_version") or ""
            request_raw = record.get("raw_request") or ""
            bot_user_agent = parsed.get("user_agent") or record.get("ua") or ""
            bot_country = record.get("country") or ""
            bot_continent = record.get("continent") or ""
            bot_tracert = record.get("tracert") or ""
            bot_dns_name = record.get("dns_name") or ""
            detected_id = record.get("is_detected")
            if detected_id is None:
                detected_id = record.get("isDetected")
            hive_id = record.get("hive_id")
            login = record.get("login") or record.get("HIVELOGIN") or ""

            if isinstance(timestamp, datetime):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
            timestamp = str(timestamp)

            with self._lock:
                with self._conn.cursor() as cur:
                    cur.execute(
                        _INSERT_PG_SQL,
                        (
                            bot_ip,
                            hostname,
                            timestamp,
                            request_path,
                            request_command,
                            request_version,
                            request_raw,
                            bot_user_agent,
                            bot_country,
                            bot_continent,
                            bot_tracert,
                            bot_dns_name,
                            int(detected_id) if detected_id is not None else None,
                            int(hive_id) if hive_id is not None else None,
                            login,
                        ),
                    )
                self._conn.commit()

        except Exception:
            logger.exception("Error inserting record into PostgreSQL storage")

    def close(self) -> None:
        """Close the PostgreSQL connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                logger.exception("Error closing PostgreSQL connection")
            finally:
                self._conn = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "PostgreSQLStorage":
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
    if backend == "postgresql":
        return PostgreSQLStorage()
    # default to SQLite
    return SQLiteStorage()


# ---------------------------------------------------------------------------
# Type aliases for clarity
# ---------------------------------------------------------------------------

# SQLiteStorage and PostgreSQLStorage are defined above directly.
# These aliases help with static type checkers when importing.
SQLiteStorageType = SQLiteStorage
PostgreSQLStorageType = PostgreSQLStorage


__all__ = [
    "StorageBackend",
    "SQLiteStorage",
    "PostgreSQLStorage",
    "SQLiteStorageType",
    "PostgreSQLStorageType",
    "get_storage",
]
