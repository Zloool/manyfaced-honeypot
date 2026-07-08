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

# ── detected_id → human-readable service name (issue #234 dashboard) ─────────
# Service handlers carry a `domain` (e.g. 'wordpress'); the special sentinel IDs
# in status.py describe non-HTTP / unknown protocols. Map both to friendly
# labels so the dashboard can group by "what was targeted".
from manyfaced.common import status as _status  # noqa: E402

_DETECTED_ID_NAMES: dict[int, str] = {
    _status.WORDPRESS_HTTP: 'wordpress',
    _status.PHPMYADMIN_HTTP: 'phpmyadmin',
    _status.JENKINS_HTTP: 'jenkins',
    _status.TOMCAT_HTTP: 'tomcat',
    _status.DRUPAL_HTTP: 'drupal',
    _status.CPANEL_HTTP: 'cpanel',
    _status.BITRIX_HTTP: 'bitrix',
    _status.WEBDAV_HTTP: 'webdav',
    _status.CONFIG_DISCLOSURE_HTTP: 'config_disclosure',
    _status.UNKNOWN_HTTP: 'unknown_http',
    _status.SSH_CLIENT: 'ssh',
    _status.UNKNOWN_NON_HTTP: 'unknown_non_http',
    _status.EMPTY_CONNECTION: 'empty_connection',
    _status.UNKNOWN_DNS: 'dns',
    _status.UNKNOWN_MONGODB: 'mongodb',
    _status.UNKNOWN_REDIS: 'redis',
    _status.UNKNOWN_TLS: 'tls',
    _status.UNKNOWN_SMB: 'smb',
    _status.UNKNOWN_TELNET: 'telnet',
    _status.UNKNOWN_RDP: 'rdp',
    _status.UNKNOWN_VNC: 'vnc',
}
# Service IDs (matched handlers) are "detected"; the sentinel range is not.
_DETECTED_SERVICE_MAX = _status.CONFIG_DISCLOSURE_HTTP


def detected_id_name(detected_id: int | None) -> str:
    """Map a detected_id to a friendly service/protocol label."""
    if detected_id is None:
        return 'unknown'
    return _DETECTED_ID_NAMES.get(int(detected_id), 'unknown')


def is_detected(detected_id: int | None) -> bool:
    """A row is 'detected' if it matched a known service handler."""
    if detected_id is None:
        return False
    return 1 <= int(detected_id) <= _DETECTED_SERVICE_MAX


def _scalar(conn, sql: str, params: tuple) -> int:
    """Run a COUNT/aggregate query and return the integer result (0 on None)."""
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _empty_stats() -> dict:
    """Return a well-shaped empty aggregate result."""
    return {
        'total': 0,
        'detected': 0,
        'undetected': 0,
        'by_service': [],
        'by_country': [],
        'by_continent': [],
        'by_ip': [],
        'by_path': [],
        'volume': [],
    }


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

    # -- read API (issue #234 dashboard) ------------------------------------
    # Not declared @abstractmethod: the existing abstract contract for storage
    # backends is insert/close only (see test_storage). Concrete subclasses
    # (SQLiteStorage, PostgreSQLStorage) override these; calling the base raises.

    def recent_records(self, limit: int = 50, since: str | None = None) -> list[dict]:
        """Return the most recent bear records (newest first).

        Args:
            limit: Max rows to return.
            since: Optional inclusive lower bound on ``timestamp`` (already
                formatted as the column's textual ``%Y-%m-%d %H:%M:%S.%f``).
        """
        raise NotImplementedError('recent_records not implemented by this backend')

    def aggregate_stats(self, since: str | None = None, bucket: str = 'hour') -> dict:
        """Return dashboard aggregates over the honeypot_bears table.

        Args:
            since: Optional inclusive lower bound on ``timestamp``.
            bucket: Time-bucketing granularity for the volume series —
                ``'hour'`` or ``'day'``.

        Returns:
            Dict with keys: total, detected, undetected, by_service,
            by_country, by_continent, by_ip, by_path, volume. Each ``by_*`` is
            a list of ``{'key': ..., 'count': ...}``; ``volume`` is a list of
            ``{'bucket': ..., 'count': ...}``.
        """
        raise NotImplementedError('aggregate_stats not implemented by this backend')


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def _resolve_data_dir() -> str:
    """Return a stable, deploy-independent directory for the SQLite DB.

    A relative ``HONEY_DB_PATH``/``database.path`` is rewritten to an absolute
    path here so it survives deploys. The target MUST NOT be the ephemeral
    release directory (``_PROJECT_ROOT``, which is ``pip install -e``'d under a
    release-specific staging dir and later ``rm -rf``'d by the cleanup step in
    deploy.yml) — otherwise a misconfigured relative path would silently have
    its DB deleted by routine maintenance (issue #224).

    Precedence:
      1. ``HONEY_DATA_DIR`` env var (explicit operator override).
      2. ``/opt/manyfaced/bots`` when it exists — the long-lived data dir used
         by the production deploy (the live DB lives there, not under a release).
      3. ``_PROJECT_ROOT`` only as a last-resort fallback for dev/non-deploy.
    """
    env_dir = os.environ.get('HONEY_DATA_DIR')
    if env_dir:
        return os.path.abspath(env_dir)
    deploy_data = '/opt/manyfaced/bots'
    if os.path.isdir(deploy_data):
        return deploy_data
    return _PROJECT_ROOT


def _raw_db_path() -> str:
    """Return the configured DB path WITHOUT the relative->absolute rewrite.

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


def _resolve_db_path() -> str:
    """Return the absolute SQLite database path, rewriting relative paths.

    A relative path is a footgun: the server's CWD (the ``current`` release
    symlink) is orphaned on every deploy, so writes would land in a fresh,
    empty file each deploy while operators inspect the long-lived DB — the
    "honeypot silently not recording" symptom (issue #188). Relative paths are
    therefore rewritten to absolute paths under the project root and a loud
    warning is emitted so the operator notices the misconfiguration.

    Use :func:`validate_db_path_absolute` to detect a relative *configuration*
    (before the rewrite) so a deploy/CI gate can fail fast.
    """
    resolved = _raw_db_path()
    if not os.path.isabs(resolved):
        # Rewrite relative -> absolute under a stable, deploy-independent data
        # dir so the DB at least survives deploys instead of being orphaned (or
        # deleted by release cleanup) under the CWD/release symlink (issue #224).
        abs_path = os.path.abspath(os.path.join(_resolve_data_dir(), resolved))
        logger.warning(
            'DB path %r is relative; under systemd the CWD (%s) is orphaned on '
            'every deploy and writes would be lost. Rewriting to absolute %r '
            '(issue #188). Set HONEY_DB_PATH (or database.path in config) to an '
            'absolute, long-lived path to silence this.',
            resolved,
            _PROJECT_ROOT,
            abs_path,
        )
        return abs_path

    return resolved


def validate_db_path_absolute() -> bool:
    """Return True if the *configured* (raw) DB path is absolute (deploy/CI guard).

    Unlike :func:`_resolve_db_path`, this does NOT apply the defensive
    relative->absolute rewrite, so it reports the actual configuration. A
    deploy/CI step should fail when this returns False to prevent recording
    from splitting onto an orphaned CWD-relative database (issue #188).
    """
    return os.path.isabs(_raw_db_path())


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
            from manyfaced.common.metrics import incr

            incr('db_insert_failure')
            # Don't silently lose the record: fall back to the JSONL dump file
            # (the same safety valve report_sender/server use) so the capture
            # survives a transient DB outage and can be replayed later.
            try:
                from manyfaced.common.utils import dump_file

                dump_file({'_dump_reason': 'sqlite_lock_contention', **record})
            except Exception:  # noqa: BLE001 — last-resort fallback must never raise
                logger.exception('Failed to dump record after lock contention')

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
            with _WRITE_LOCK:
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
            with _WRITE_LOCK:
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

                # Copy old records to archive, tracking which rows survived so a
                # partial archive never deletes rows that didn't make it.
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
                id_index = col_names.index('id')
                placeholders = ','.join(['?' for _ in col_names])
                insert_sql = f'INSERT INTO honeypot_bears_archive VALUES ({placeholders})'

                archived_ids: list[int] = []
                with archive_conn:
                    for row in rows:
                        try:
                            # INSERT OR IGNORE: if a prior partial run already
                            # committed this row into the archive, retrying must
                            # not raise a PK conflict and drop the row from
                            # archived_ids (which would strand it in BOTH tables
                            # forever, issue #225). An already-archived row is
                            # still safe to delete from the main table.
                            archive_conn.execute(
                                insert_sql.replace('INSERT INTO', 'INSERT OR IGNORE INTO'),
                                row,
                            )
                            archived_ids.append(row[id_index])
                        except sqlite3.Error:
                            # A genuinely novel row that fails to archive must
                            # NOT be deleted from the main table — log it loudly
                            # so the data is preserved until the archive can be
                            # retried.
                            logger.warning(
                                'Failed to archive row id=%s; leaving it in main DB', row[id_index]
                            )
                archive_conn.commit()
                archive_conn.close()

                if not archived_ids:
                    logger.error(
                        'Archive copy failed for all %d rows; aborting delete to avoid data loss',
                        count,
                    )
                    return None

                # Delete only the rows that were actually archived.
                placeholders_ids = ','.join(['?' for _ in archived_ids])
                # `placeholders_ids` is a fixed string of "?" markers (one per
                # archived id), never attacker-controlled; `archived_ids` are bound
                # as parameters. See issue #221.
                self._conn.execute(
                    f'DELETE FROM honeypot_bears WHERE id IN ({placeholders_ids})',  # nosec B608
                    archived_ids,
                )
                self._conn.commit()
                logger.info('Archived %d/%d records to %s', len(archived_ids), count, dest_db)

                return dest_db

        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error archiving old records from SQLite storage')
            return None

    # -- read API (issue #234 dashboard) ------------------------------------

    def recent_records(self, limit: int = 50, since: str | None = None) -> list[dict]:
        if self._conn is None:
            return []
        conn = self._conn
        sql = 'SELECT * FROM honeypot_bears'
        params: tuple = ()
        if since is not None:
            sql += ' WHERE timestamp >= ?'
            params = (since,)
        sql += ' ORDER BY timestamp DESC LIMIT ?'
        try:
            rows = conn.execute(sql, (*params, int(limit))).fetchall()
            cols = [d[0] for d in conn.execute('SELECT * FROM honeypot_bears LIMIT 0').description]
            return [dict(zip(cols, row)) for row in rows]
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error reading recent records from SQLite storage')
            return []

    def aggregate_stats(self, since: str | None = None, bucket: str = 'hour') -> dict:
        if self._conn is None:
            return _empty_stats()
        conn = self._conn
        if since is not None:
            where = ' WHERE timestamp >= ?'
            params: tuple = (since,)
            and_prefix = ' AND'
        else:
            where = ''
            params = ()
            and_prefix = ' WHERE'
        bucket_expr = (
            "strftime('%Y-%m-%d', timestamp)"
            if bucket == 'day'
            else "strftime('%Y-%m-%d %H:00', timestamp)"
        )
        try:
            total = _scalar(conn, f'SELECT COUNT(*) FROM honeypot_bears{where}', params)
            detected = _scalar(
                conn,
                f'SELECT COUNT(*) FROM honeypot_bears{where}{and_prefix} detected_id BETWEEN 1 AND ?',
                (*params, _DETECTED_SERVICE_MAX),
            )
            undetected = total - detected

            def _group(col: str, top: int = 15) -> list[dict]:
                q = (
                    f'SELECT {col}, COUNT(*) AS c FROM honeypot_bears{where}{and_prefix} '
                    f'{col} IS NOT NULL AND {col} != \'\' '
                    f'GROUP BY {col} ORDER BY c DESC LIMIT ?'
                )
                rows = conn.execute(q, (*params, top)).fetchall()
                return [{'key': r[0], 'count': r[1]} for r in rows]

            # Service grouping maps detected_id -> friendly name.
            svc_rows = conn.execute(
                f'SELECT detected_id, COUNT(*) AS c FROM honeypot_bears{where} '
                'GROUP BY detected_id ORDER BY c DESC',
                params,
            ).fetchall()
            by_service = [
                {'key': detected_id_name(r[0]), 'count': r[1]} for r in svc_rows
            ]

            vol_rows = conn.execute(
                f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '
                'GROUP BY b ORDER BY b',
                params,
            ).fetchall()
            volume = [{'bucket': r[0], 'count': r[1]} for r in vol_rows]

            return {
                'total': total,
                'detected': detected,
                'undetected': undetected,
                'by_service': by_service,
                'by_country': _group('bot_country'),
                'by_continent': _group('bot_continent'),
                'by_ip': _group('bot_ip'),
                'by_path': _group('request_path'),
                'volume': volume,
            }
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error aggregating stats from SQLite storage')
            return _empty_stats()

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

    # -- read API (issue #234 dashboard) ------------------------------------

    def recent_records(self, limit: int = 50, since: str | None = None) -> list[dict]:
        if self._conn is None:
            return []
        sql = 'SELECT * FROM honeypot_bears'
        params: list = []
        if since is not None:
            sql += ' WHERE timestamp >= %s'
            params.append(since)
        sql += ' ORDER BY timestamp DESC LIMIT %s'
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, (*params, int(limit)))
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        except psycopg2.Error:  # noqa: BLE001
            logger.exception('Error reading recent records from PostgreSQL storage')
            return []

    def aggregate_stats(self, since: str | None = None, bucket: str = 'hour') -> dict:
        if self._conn is None:
            return _empty_stats()
        if since is not None:
            where = ' WHERE timestamp >= %s'
            params: list = [since]
            and_prefix = ' AND'
        else:
            where = ''
            params = []
            and_prefix = ' WHERE'
        bucket_expr = (
            "to_char(timestamp::timestamp, 'YYYY-MM-DD')"
            if bucket == 'day'
            else "to_char(timestamp::timestamp, 'YYYY-MM-DD HH24:00')"
        )
        try:
            with self._conn.cursor() as cur:

                def _pg_scalar(q: str, p: list) -> int:
                    cur.execute(q, p)
                    row = cur.fetchone()
                    return int(row[0]) if row and row[0] is not None else 0

                total = _pg_scalar(
                    f'SELECT COUNT(*) FROM honeypot_bears{where}', params
                )
                detected = _pg_scalar(
                    f'SELECT COUNT(*) FROM honeypot_bears{where}{and_prefix} detected_id BETWEEN 1 AND %s',
                    [*params, _DETECTED_SERVICE_MAX],
                )
                undetected = total - detected

                def _group(col: str, top: int = 15) -> list[dict]:
                    q = (
                        f'SELECT {col}, COUNT(*) AS c FROM honeypot_bears{where}{and_prefix} '
                        f'{col} IS NOT NULL AND {col} != \'\' '
                        f'GROUP BY {col} ORDER BY c DESC LIMIT %s'
                    )
                    cur.execute(q, [*params, top])
                    return [{'key': r[0], 'count': r[1]} for r in cur.fetchall()]

                cur.execute(
                    f'SELECT detected_id, COUNT(*) AS c FROM honeypot_bears{where} '
                    'GROUP BY detected_id ORDER BY c DESC',
                    params,
                )
                by_service = [
                    {'key': detected_id_name(r[0]), 'count': r[1]} for r in cur.fetchall()
                ]

                cur.execute(
                    f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '
                    'GROUP BY b ORDER BY b',
                    params,
                )
                volume = [{'bucket': r[0], 'count': r[1]} for r in cur.fetchall()]

                return {
                    'total': total,
                    'detected': detected,
                    'undetected': undetected,
                    'by_service': by_service,
                    'by_country': _group('bot_country'),
                    'by_continent': _group('bot_continent'),
                    'by_ip': _group('bot_ip'),
                    'by_path': _group('request_path'),
                    'volume': volume,
                }
        except psycopg2.Error:  # noqa: BLE001
            logger.exception('Error aggregating stats from PostgreSQL storage')
            return _empty_stats()

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
    'validate_db_path_absolute',
]
