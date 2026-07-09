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
from collections import Counter
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

try:
    import psycopg2  # type: ignore[import-untyped,unused-ignore]  # noqa: F401  # Optional dependency for PostgreSQL backend
except ImportError:
    psycopg2 = None  # psycopg2 not installed; PostgreSQL backend raises ImportError at runtime

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
    _status.FINGERPRINT_PROBE: 'fingerprint_probe',
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


# Dashboard ``since`` values are human-friendly windows, not SQL. Convert them to
# a real ISO-8601 cutoff string so the ``idx_bears_timestamp`` index can bound the
# scan. Without this, ``timestamp >= '24h'`` is a malformed text comparison that
# defeats the index and forces a full-table scan (which hangs the dashboard under
# the live WAL writer on a multi-million-row DB). Returns None for 'all'/unknown.
_SINCE_DELTAS: dict[str, timedelta] = {
    '24h': timedelta(hours=24),
    '7d': timedelta(days=7),
    '30d': timedelta(days=30),
}


def _since_to_iso(since: str | None) -> str | None:
    if since in (None, 'all'):
        return None
    # The dashboard passes a concrete ISO-8601 cutoff (from _parse_range), not a
    # window token. Pass those through untouched so windowed aggregates actually
    # filter — otherwise `delta = _SINCE_DELTAS.get(iso_string)` is None and we
    # drop the WHERE clause, returning all-time totals for every range.
    if isinstance(since, str):
        for _fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
            try:
                datetime.strptime(since, _fmt)
                return since
            except ValueError:
                continue
    delta = _SINCE_DELTAS.get(since)
    if delta is not None:
        cutoff = datetime.now() - delta
        return cutoff.strftime('%Y-%m-%d %H:%M:%S')
    # Not a recognised shorthand token ('24h'/'7d'/'30d') AND not a valid
    # ISO-8601 cutoff (the dashboard's _parse_range resolves those, caught by
    # the strptime check above). Return None (no WHERE bound) rather than
    # injecting an arbitrary string into the SQL `WHERE timestamp >= <since>`
    # clause, which would be a malformed/unsafe query.
    return None


def _sqlite_bucket_expr(bucket: str) -> str:
    """SQL expression bucketing the TEXT ``timestamp`` column for SQLite.

    ``minute5`` rounds down to the nearest 5-minute mark via a Unix-epoch
    round-trip (SQLite has no native 5-minute strftime format); ``hour``/
    ``day`` format directly since those already align to calendar units.
    """
    if bucket == 'minute5':
        return (
            "strftime('%Y-%m-%d %H:%M:00', "
            "datetime((CAST(strftime('%s', timestamp) AS INTEGER) / 300) * 300, 'unixepoch'))"
        )
    if bucket == 'day':
        return "strftime('%Y-%m-%d', timestamp)"
    return "strftime('%Y-%m-%d %H:00', timestamp)"


def _pg_bucket_expr(bucket: str) -> str:
    """SQL expression bucketing the TEXT ``timestamp`` column for PostgreSQL.

    Mirrors :func:`_sqlite_bucket_expr`; the ``minute5`` case round-trips
    through ``AT TIME ZONE 'UTC'`` so it stays self-consistent with the naive
    (timezone-less) timestamps written by the collector, matching how
    ``hour``/``day`` format the naive value directly with no TZ conversion.
    """
    if bucket == 'minute5':
        return (
            'to_char(to_timestamp(floor(extract(epoch from timestamp::timestamp) / 300) * 300) '
            "AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:00')"
        )
    if bucket == 'day':
        return "to_char(timestamp::timestamp, 'YYYY-MM-DD')"
    return "to_char(timestamp::timestamp, 'YYYY-MM-DD HH24:00')"


def _empty_stats() -> dict:
    """Return a well-shaped empty aggregate result."""
    return {
        'total': 0,
        'detected': 0,
        'undetected': 0,
        'unique_ips': 0,
        'by_service': [],
        'by_country': [],
        'by_continent': [],
        'by_ip': [],
        'by_path': [],
        'by_port': [],
        'volume': [],
    }


# Dashboard volume-chart bucket granularities (issue #234 redesign): 5-minute
# buckets for the 1H range, hour/day for wider ranges (matches the ranges
# offered by the UI: 1H/24H/7D/30D).
_VOLUME_BUCKETS = ('minute5', 'hour', 'day')


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

    def recent_records(
        self, limit: int = 50, since: str | None = None, offset: int = 0
    ) -> list[dict]:
        """Return the most recent bear records (newest first).

        Args:
            limit: Max rows to return.
            since: Optional inclusive lower bound on ``timestamp`` (already
                formatted as the column's textual ``%Y-%m-%d %H:%M:%S.%f``).
            offset: Rows to skip from the newest end (pagination). Defaults to 0.
        """
        raise NotImplementedError('recent_records not implemented by this backend')

    def count_recent(self, since: str | None = None) -> int:
        """Count honeypot_bears rows within the optional ``since`` window.

        Used to drive capture-log pagination (issue #316) so older rows stay
        reachable. Concrete subclasses override this; the base raises.
        """
        raise NotImplementedError('count_recent not implemented by this backend')

    def aggregate_stats(self, since: str | None = None, bucket: str = 'hour') -> dict:
        """Return dashboard aggregates over the honeypot_bears table.

        Args:
            since: Optional inclusive lower bound on ``timestamp``.
            bucket: Time-bucketing granularity for the volume series —
                ``'hour'`` or ``'day'``.

        Returns:
            Dict with keys: total, detected, undetected, unique_ips,
            by_service, by_country, by_continent, by_ip, by_path, by_port,
            volume. Each ``by_*`` is a list of ``{'key': ..., 'count': ...}``;
            ``volume`` is a list of ``{'bucket': ..., 'count': ...}``.
        """
        raise NotImplementedError('aggregate_stats not implemented by this backend')

    def volume_series(
        self, since: str | None = None, bucket: str = 'hour', port: int | list[int] | None = None
    ) -> list[dict]:
        """Return a request-volume time series, optionally scoped to one port.

        Used by the volume chart, which is filtered independently of the
        (unfiltered) top-lists in :meth:`aggregate_stats`. ``bucket`` is one
        of ``'minute5'`` (1H range), ``'hour'`` (24H) or ``'day'`` (7D/30D).

        ``port`` may be a single port or a list of ports (e.g. an external port
        plus its iptables-redirect target) — see :func:`manyfaced.common.ports.
        internal_ports` (issue #330).
        """
        raise NotImplementedError('volume_series not implemented by this backend')


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
        # DB_PATH resolution can fail (bad config, unreadable env); fall back to
        # the default relative path rather than crashing import-time.
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
    """Return the backend name from env or TOML config, defaulting to 'sqlite'.

    Env ``HONEY_DB_BACKEND`` takes precedence (operator override); falls back to
    ``settings.DB_BACKEND`` (TOML ``[database] backend``) so setting
    ``backend = "postgresql"`` in config.toml actually switches backends. The
    import of ``settings`` is deferred to dodge import-time circularity, the
    same pattern ``_raw_db_path()`` already uses.
    """
    env_backend = os.environ.get('HONEY_DB_BACKEND')
    if env_backend:
        return env_backend.lower()
    try:
        from manyfaced.common.config import settings  # noqa: PLC0415

        toml_backend = getattr(settings, 'DB_BACKEND', None)
        if toml_backend:
            return str(toml_backend).lower()
    except Exception:
        # Config resolution can fail (bad config, unreadable env); fall back to
        # the default rather than crashing import-time.
        pass
    return 'sqlite'


def _pg_toml(attr: str, default: str) -> str:
    """Resolve a PostgreSQL config field from TOML config (``settings.DB_PG_*``).

    Used by :class:`PostgreSQLStorage` to consult ``settings.DB_PG_HOST`` /
    ``DB_PG_PORT`` / etc. when neither an explicit constructor arg nor an env var
    is supplied, so ``pg_*`` values in config.toml are honored (issue #243 #3).
    Deferred-import + broad-except so a missing/broken config falls back to the
    default instead of crashing import-time.
    """
    try:
        from manyfaced.common.config import settings  # noqa: PLC0415

        val = getattr(settings, attr, None)
        if val is not None and val != '':
            return str(val)
    except Exception:
        pass
    return default


# ── process-wide storage singleton (issue #243) ─────────────────────────────
# ``get_storage()`` previously constructed a fresh backend on EVERY call. SQLite
# tolerates this (cheap local connect + the module-level ``_WRITE_LOCK`` already
# serializes writes), but PostgreSQL does NOT — a fresh ``psycopg2.connect()``
# (TCP + auth handshake) per captured report overwhelms Postgres under bot load
# and leaks connections. Cache a single instance per process instead. One
# process only ever runs one backend (``_resolve_backend()`` is static for the
# process lifetime), so this is a single slot, not a dict.
_STORAGE_SINGLETON: 'StorageBackend | None' = None
_STORAGE_LOCK = Lock()


def reset_storage_singleton() -> None:
    """Drop the cached storage singleton (test-only hook).

    ``get_storage()`` caches one backend per process; tests that need to
    re-create the storage (e.g. across backend/env changes) call this to force
    re-creation on the next ``get_storage()``. Never used in production.
    """
    global _STORAGE_SINGLETON
    with _STORAGE_LOCK:
        old = _STORAGE_SINGLETON
        _STORAGE_SINGLETON = None
    if old is not None:
        try:
            old.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------

from manyfaced.db.sql_builder import (  # noqa: E402, F401
    CREATE_TABLE_SQL as _CREATE_TABLE_SQL,
    CREATE_INDEXES_SQL as _CREATE_INDEXES_SQL,
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

    def __init__(
        self,
        db_path: str | None = None,
        busy_timeout: int = 5000,
        integrity_check: bool = True,
        init_schema: bool = True,
    ) -> None:
        self._db_path = db_path or _resolve_db_path()
        # Ensure parent directories exist
        parent = os.path.dirname(self._db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = Lock()
        self._insert_count = 0
        self._init_db(
            busy_timeout=busy_timeout,
            integrity_check=integrity_check,
            init_schema=init_schema,
        )

    def _init_db(
        self,
        busy_timeout: int = 5000,
        integrity_check: bool = True,
        init_schema: bool = True,
    ) -> None:
        """Open the connection and (optionally) create the schema.

        ``busy_timeout`` makes concurrent reads (e.g. the dashboard) wait for a
        brief WAL write lock instead of immediately raising "database is locked"
        — important on a live honeypot where the writer is constantly inserting.

        ``init_schema`` gates DDL (CREATE TABLE + CREATE INDEXES). Read-only
        callers such as the dashboard MUST pass ``init_schema=False``: the schema
        already exists (the writer created it at startup), and running DDL on
        every connection open — including the per-request dashboard connection —
        stalls under WAL write contention and makes the dashboard hang.
        ``integrity_check`` is also skipped for read-only callers to avoid a
        full-table scan on every connection open.
        """
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute(f'PRAGMA busy_timeout={busy_timeout}')
            self._conn.execute('PRAGMA journal_mode=WAL')
            if init_schema:
                self._conn.execute(_CREATE_TABLE_SQL)
                # Issue #299: add the listen_port column to an existing DB that
                # predates this schema. CREATE TABLE IF NOT EXISTS won't add a
                # column to a pre-existing table, and inserts now reference it,
                # so the migration MUST run before the index script (which
                # indexes listen_port) and before the first insert, or they fail
                # with "no such column". Guarded by PRAGMA table_info so it is a
                # safe no-op on a fresh DB.
                self._add_listen_port_column()
                # Issue #271: add the benign-source classification columns to a
                # pre-#271 DB. As with listen_port, CREATE TABLE IF NOT EXISTS
                # won't alter an existing table, so we migrate explicitly and
                # guard with PRAGMA table_info so repeated writer startups are
                # cheap no-ops (and a redundant ALTER is swallowed if present).
                self._add_classification_columns()
                # Idempotent performance indexes for the dashboard aggregates.
                # Created once at writer startup, NOT on every read connection.
                self._conn.executescript(_CREATE_INDEXES_SQL)
                self._conn.commit()

            if integrity_check:
                # Run startup integrity check and warn if corruption is detected
                result = self._conn.execute('PRAGMA integrity_check').fetchone()
                if result and result[0] != 'ok':
                    logger.warning(
                        'SQLite integrity check failed: %s — DB may be corrupted', result[0]
                    )

        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Failed to initialise SQLite database at %s', self._db_path)
            self._conn = None

    # -- public API ----------------------------------------------------------

    def _add_listen_port_column(self) -> None:
        """Add the issue #299 ``listen_port`` column to a pre-#299 DB.

        SQLite cannot add a column inside CREATE TABLE IF NOT EXISTS once the
        table already exists, so we migrate explicitly. Guarded by
        PRAGMA table_info so repeated calls (every writer startup) are cheap
        no-ops, and the redundant ALTER is swallowed if the column is present.
        """
        try:
            cols = {
                r[1] for r in self._conn.execute('PRAGMA table_info(honeypot_bears)').fetchall()
            }
            if 'listen_port' in cols:
                return
            self._conn.execute('ALTER TABLE honeypot_bears ADD COLUMN listen_port INTEGER')
        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Failed to add listen_port column to honeypot_bears')

    def _add_classification_columns(self) -> None:
        """Add the issue #271 benign-source columns to a pre-#271 DB.

        Mirrors :meth:`_add_listen_port_column`: SQLite can't add columns via
        CREATE TABLE IF NOT EXISTS on an existing table, so we ALTER explicitly.
        Guarded by PRAGMA table_info so every writer startup is a cheap no-op,
        and a redundant ALTER is swallowed if a column is already present. The
        index on ``classification`` is created separately by
        ``CREATE_INDEXES_SQL`` (also idempotent), so we only add the columns
        here.
        """
        _CLASSIFICATION_COLUMNS = (
            'bot_asn TEXT',
            'bot_org TEXT',
            'classification TEXT',
            'benign_source TEXT',
        )
        try:
            existing = {
                r[1] for r in self._conn.execute('PRAGMA table_info(honeypot_bears)').fetchall()
            }
            for col_sql in _CLASSIFICATION_COLUMNS:
                name = col_sql.split()[0]
                if name in existing:
                    continue
                self._conn.execute(f'ALTER TABLE honeypot_bears ADD COLUMN {col_sql}')
        except (sqlite3.Error, sqlite3.OperationalError, sqlite3.DatabaseError):
            logger.exception('Failed to add classification columns to honeypot_bears')

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

    def recent_records(
        self, limit: int = 50, since: str | None = None, offset: int = 0
    ) -> list[dict]:
        if self._conn is None:
            return []
        conn = self._conn
        sql = 'SELECT * FROM honeypot_bears'
        params: tuple = ()
        if since is not None:
            sql += ' WHERE timestamp >= ?'
            params = (since,)
        sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        try:
            rows = conn.execute(sql, (*params, int(limit), int(offset))).fetchall()
            cols = [d[0] for d in conn.execute('SELECT * FROM honeypot_bears LIMIT 0').description]
            return [dict(zip(cols, row)) for row in rows]
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error reading recent records from SQLite storage')
            return []

    def count_recent(self, since: str | None = None) -> int:
        """Count honeypot_bears rows within the optional ``since`` window.

        Used to drive capture-log pagination (issue #316) so older rows inside
        the selected time range stay reachable beyond the rendered page size.
        """
        if self._conn is None:
            return 0
        conn = self._conn
        sql = 'SELECT COUNT(*) FROM honeypot_bears'
        params: tuple = ()
        if since is not None:
            sql += ' WHERE timestamp >= ?'
            params = (since,)
        try:
            return int(conn.execute(sql, params).fetchone()[0])
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error counting recent records from SQLite storage')
            return 0

    def aggregate_stats(self, since: str | None = None, bucket: str = 'hour') -> dict:
        if self._conn is None:
            return _empty_stats()
        conn = self._conn
        # Convert the human-friendly window ('24h'/'7d'/'30d'/'all') into a real
        # ISO cutoff so the timestamp index bounds the scan. A raw string like
        # '24h' compared against the TEXT timestamp column defeats the index and
        # forces a full-table scan that hangs under the live WAL writer.
        cutoff = _since_to_iso(since)
        if cutoff is not None:
            where = ' WHERE timestamp >= ?'
            params: tuple = (cutoff,)
            and_prefix = ' AND'
        else:
            where = ''
            params = ()
            and_prefix = ' WHERE'
        bucket_expr = _sqlite_bucket_expr(bucket)
        try:
            total = _scalar(conn, f'SELECT COUNT(*) FROM honeypot_bears{where}', params)
            detected = _scalar(
                conn,
                f'SELECT COUNT(*) FROM honeypot_bears{where}{and_prefix} detected_id BETWEEN 1 AND ?',
                (*params, _DETECTED_SERVICE_MAX),
            )
            undetected = total - detected
            unique_ips = _scalar(
                conn, f'SELECT COUNT(DISTINCT bot_ip) FROM honeypot_bears{where}', params
            )

            def _group(col: str, top: int = 15) -> list[dict]:
                q = (
                    f'SELECT {col}, COUNT(*) AS c FROM honeypot_bears{where}{and_prefix} '
                    f"{col} IS NOT NULL AND {col} != '' "
                    f'GROUP BY {col} ORDER BY c DESC LIMIT ?'
                )
                rows = conn.execute(q, (*params, top)).fetchall()
                return [{'key': r[0], 'count': r[1]} for r in rows]

            # by_port groups by the local honeypot port (issue #299). listen_port
            # is INTEGER and 0 is the "unknown" sentinel, so the generic _group's
            # `!= ''` filter (which only excludes TEXT empties) would let 0 slip
            # through; exclude it explicitly.
            def _group_port(top: int = 15) -> list[dict]:
                q = (
                    f'SELECT listen_port, COUNT(*) AS c FROM honeypot_bears{where}{and_prefix} '
                    'listen_port IS NOT NULL AND listen_port != 0 '
                    f'GROUP BY listen_port ORDER BY c DESC LIMIT ?'
                )
                rows = conn.execute(q, (*params, top)).fetchall()
                return [{'key': r[0], 'count': r[1]} for r in rows]

            # Service grouping maps detected_id -> friendly name. Because the
            # friendly name is many-to-one (every detected_id not in
            # _DETECTED_ID_NAMES collapses to 'unknown'), group by the *mapped*
            # label and sum, so e.g. multiple distinct unmapped ids merge into a
            # single 'unknown' row (issue #331).
            svc_rows = conn.execute(
                f'SELECT detected_id, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                'GROUP BY detected_id ORDER BY c DESC',
                params,
            ).fetchall()
            svc_counts: Counter[str] = Counter()
            for detected_id, c in svc_rows:
                svc_counts[detected_id_name(detected_id)] += c
            by_service = [{'key': k, 'count': c} for k, c in svc_counts.most_common()]

            vol_rows = conn.execute(
                f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                'GROUP BY b ORDER BY b',
                params,
            ).fetchall()
            volume = [{'bucket': r[0], 'count': r[1]} for r in vol_rows]

            return {
                'total': total,
                'detected': detected,
                'undetected': undetected,
                'unique_ips': unique_ips,
                'by_service': by_service,
                'by_country': _group('bot_country'),
                'by_continent': _group('bot_continent'),
                'by_ip': _group('bot_ip'),
                'by_path': _group('request_path'),
                'by_port': _group_port(),
                'by_classification': _group('classification'),
                'volume': volume,
            }
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error aggregating stats from SQLite storage')
            return _empty_stats()

    def volume_series(
        self, since: str | None = None, bucket: str = 'hour', port: int | list[int] | None = None
    ) -> list[dict]:
        if self._conn is None:
            return []
        cutoff = _since_to_iso(since)
        clauses: list[str] = []
        params: list = []
        if cutoff is not None:
            clauses.append('timestamp >= ?')
            params.append(cutoff)
        if port is not None:
            if isinstance(port, int):
                clauses.append('listen_port = ?')
                params.append(port)
            else:
                placeholders = ', '.join('?' for _ in port)
                clauses.append(f'listen_port IN ({placeholders})')
                params.extend(port)
        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        bucket_expr = _sqlite_bucket_expr(bucket)
        try:
            rows = self._conn.execute(
                f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                'GROUP BY b ORDER BY b',
                params,
            ).fetchall()
            return [{'bucket': r[0], 'count': r[1]} for r in rows]
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.exception('Error reading volume series from SQLite storage')
            return []

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
    CREATE_INDEXES_PG_SQL as _CREATE_INDEXES_PG_SQL,
    INSERT_PG_SQL as _INSERT_PG_SQL,
)


class PostgreSQLStorage(StorageBackend):
    """PostgreSQL storage backend using psycopg2.

    Connection lifecycle (issue #243): the backend is created ONCE per process
    via ``get_storage()`` (a cached singleton), so ``_conn`` is a long-lived
    connection reused across every insert. A dropped connection is transparently
    re-established by :meth:`_ensure_connected` before each operation, and the
    process-wide ``_STORAGE_LOCK`` (not the per-instance lock) serializes the
    writer process's inserts against the single shared connection.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        user: str | None = None,
        password: str | None = None,
        sslmode: str | None = None,
        dsn: str | None = None,
    ) -> None:
        # Explicit constructor args (used by tests) stay the top override; then
        # env vars; then TOML config (settings.DB_PG_*) — the previous code only
        # honored env/defaults, so ``pg_*`` in config.toml was ignored (issue #243).
        self._host = host or os.environ.get('HONEY_PG_HOST') or _pg_toml('DB_PG_HOST', '127.0.0.1')
        self._port = port or int(os.environ.get('HONEY_PG_PORT') or _pg_toml('DB_PG_PORT', '5432'))
        self._database = (
            database or os.environ.get('HONEY_PG_DB') or _pg_toml('DB_PG_DB', 'honeypot')
        )
        self._user = user or os.environ.get('HONEY_PG_USER') or _pg_toml('DB_PG_USER', 'postgres')
        self._password = (
            password
            or os.environ.get('HONEY_PG_PASSWORD')
            or _pg_toml('DB_PG_PASSWORD', 'postgres')
        )
        # TLS / managed-Postgres support (issue #243 #9).
        self._sslmode = (
            sslmode or os.environ.get('HONEY_PG_SSLMODE') or _pg_toml('DB_PG_SSLMODE', 'prefer')
        )
        self._dsn = dsn or os.environ.get('HONEY_PG_DSN') or _pg_toml('DB_PG_DSN', '')
        self._conn: Any = None
        # Per-instance lock is now genuinely useful: with a cached singleton, all
        # report threads share this one instance's connection and serialize here.
        self._lock = Lock()
        try:
            self._init_db()
        except ImportError:
            # psycopg2 not installed — the caller must have selected postgresql
            # by mistake; raise clearly rather than swallowing into a silent None.
            raise
        except Exception:  # noqa: BLE001 — psycopg2 may be None here
            # Transient startup failure (Postgres not up yet) is tolerated: the
            # first insert() triggers a lazy reconnect via _ensure_connected().
            logger.warning('PostgreSQL storage not yet connected; will retry on first write')

    def _init_db(self) -> None:
        """Connect to PostgreSQL and create the table if it does not exist."""
        if psycopg2 is None:
            raise ImportError(
                'psycopg2 is required for PostgreSQL backend. '
                'Install it with: pip install psycopg2-binary'
            )
        try:
            if self._dsn:
                # Managed/cloud Postgres is often handed as a single DSN URI.
                # Pass sslmode alongside the DSN so a required TLS connection
                # (e.g. HONEY_PG_SSLMODE=require) still applies.
                self._conn = psycopg2.connect(dsn=self._dsn, sslmode=self._sslmode)
            else:
                self._conn = psycopg2.connect(
                    host=self._host,
                    port=self._port,
                    database=self._database,
                    user=self._user,
                    password=self._password,
                    sslmode=self._sslmode,
                )
            with self._conn.cursor() as cur:
                cur.execute(_CREATE_TABLE_PG_SQL)
                # Issue #299: add the listen_port column to a pre-#299 DB.
                # Online/safe for Postgres; guarded by information_schema so it
                # is a cheap no-op on a fresh DB.
                cur.execute(
                    'SELECT 1 FROM information_schema.columns '
                    "WHERE table_name = 'honeypot_bears' AND column_name = 'listen_port'"
                )
                if cur.fetchone() is None:
                    cur.execute('ALTER TABLE honeypot_bears ADD COLUMN listen_port INTEGER')
                # Issue #271: add the benign-source classification columns to a
                # pre-#271 DB. Online/safe for Postgres; guarded by
                # information_schema so it is a cheap no-op on a fresh DB.
                cur.execute(
                    'SELECT 1 FROM information_schema.columns '
                    "WHERE table_name = 'honeypot_bears' AND column_name = 'classification'"
                )
                if cur.fetchone() is None:
                    cur.execute('ALTER TABLE honeypot_bears ADD COLUMN bot_asn VARCHAR(32)')
                    cur.execute('ALTER TABLE honeypot_bears ADD COLUMN bot_org VARCHAR(255)')
                    cur.execute('ALTER TABLE honeypot_bears ADD COLUMN classification VARCHAR(16)')
                    cur.execute('ALTER TABLE honeypot_bears ADD COLUMN benign_source VARCHAR(64)')
                # Issue #347: create the dashboard aggregate indexes (timestamp
                # btree most importantly). Each is CREATE INDEX IF NOT EXISTS so
                # a missing/skipped index cannot break startup and re-runs are
                # cheap no-ops on an already-indexed DB.
                try:
                    cur.execute(_CREATE_INDEXES_PG_SQL)
                except psycopg2.Error:  # noqa: BLE001
                    logger.exception('Failed to create PostgreSQL dashboard indexes')
            self._conn.commit()
        except psycopg2.Error:  # noqa: BLE001
            logger.exception('Failed to initialise PostgreSQL storage')
            self._conn = None
            raise  # propagated so _ensure_connected / singleton can retry once

    def _ensure_connected(self) -> bool:
        """Ensure ``self._conn`` is live; reconnect once on a dead connection.

        Returns True if a usable connection is available, False otherwise. A
        transient Postgres outage (timeout, killed backend, TLS drop) should not
        permanently break recording — we reconnect once per call and retry the
        operation in the caller, instead of failing every insert forever.
        """
        if self._conn is not None:
            try:
                with self._conn.cursor() as cur:
                    cur.execute('SELECT 1')
                return True
            except (psycopg2.OperationalError, psycopg2.InterfaceError):  # noqa: BLE001
                logger.warning('PostgreSQL connection lost; attempting reconnect')
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001 — best-effort
                    pass
                self._conn = None
        try:
            self._init_db()
        except psycopg2.Error:  # noqa: BLE001
            logger.exception('PostgreSQL reconnect failed')
            self._conn = None
            return False
        return self._conn is not None

    def _reset_conn(self) -> None:
        """Roll back any aborted transaction and drop the connection.

        A failed query leaves the PostgreSQL session in
        ``InFailedSqlTransaction`` — every subsequent query on this *shared*
        connection then fails until a ``ROLLBACK``. Because the honeypot and
        the dashboard reader use one ``PostgreSQLStorage`` instance, a single
        bad write/read would otherwise poison recording and the dashboard
        reader forever (issue #243). Roll back (clearing the aborted txn) and
        close the connection so the next operation opens a fresh, clean one.
        """
        conn = self._conn
        self._conn = None
        if conn is None:
            return
        try:
            conn.rollback()
        except psycopg2.Error:  # noqa: BLE001 — best-effort
            pass
        try:
            conn.close()
        except psycopg2.Error:  # noqa: BLE001 — best-effort
            pass

    # -- public API ----------------------------------------------------------

    def insert(self, record: dict) -> None:  # noqa: C901
        """Insert a single bear record.

        On a dropped connection, reconnect once and retry (issue #243 #2); if the
        insert still fails, fall back to the JSONL dump file (the same safety
        valve SQLite uses) so a transient Postgres outage never silently loses a
        capture.
        """
        if self._conn is None and not self._ensure_connected():
            logger.error('PostgreSQL storage is not initialised; dumping record to fallback')
            self._dump_insert_failure(record)
            return

        try:
            fields = _extract_record_fields(record)
            with self._lock:
                with self._conn.cursor() as cur:
                    cur.execute(_INSERT_PG_SQL, fields)
                self._conn.commit()
        except psycopg2.Error:  # noqa: BLE001 — dead conn OR aborted txn
            # A dropped connection or an aborted transaction
            # (InFailedSqlTransaction) poisons this shared connection. Reset
            # it (rollback + close) and reconnect once before retrying, so a
            # single failure can't permanently break recording (issue #243).
            logger.warning('PostgreSQL insert error; rolling back and reconnecting once')
            self._reset_conn()
            if not self._ensure_connected():
                self._dump_insert_failure(record)
                return
            try:
                with self._lock:
                    with self._conn.cursor() as cur:
                        cur.execute(_INSERT_PG_SQL, fields)
                    self._conn.commit()
            except psycopg2.Error:  # noqa: BLE001
                logger.exception('Error inserting record into PostgreSQL storage')
                self._dump_insert_failure(record)

    def _dump_insert_failure(self, record: dict) -> None:
        """Last-resort fallback: dump the record to JSONL so it is not lost.

        Mirrors ``SQLiteStorage.insert``'s lock-contention path. Wrapped so the
        fallback itself can never raise (issue #243 #8).
        """
        from manyfaced.common.metrics import incr

        incr('db_insert_failure')
        try:
            from manyfaced.common.utils import dump_file

            dump_file({'_dump_reason': 'postgres_insert_failure', **record})
        except Exception:  # noqa: BLE001 — last-resort fallback must never raise
            logger.exception('Failed to dump record after PostgreSQL insert failure')

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

    def recent_records(
        self, limit: int = 50, since: str | None = None, offset: int = 0
    ) -> list[dict]:
        if self._conn is None and not self._ensure_connected():
            return []
        sql = 'SELECT * FROM honeypot_bears'
        params: list = []
        if since is not None:
            sql += ' WHERE timestamp >= %s'
            params.append(since)
        sql += ' ORDER BY timestamp DESC LIMIT %s OFFSET %s'
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, (*params, int(limit), int(offset)))
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        except psycopg2.Error:  # noqa: BLE001 — dead conn OR aborted txn
            # Reset (rollback + close) the shared connection and retry once,
            # so a transient failure can't poison later reads/writes.
            logger.warning('PostgreSQL recent_records error; rolling back and reconnecting once')
            self._reset_conn()
            if not self._ensure_connected():
                return []
            try:
                with self._conn.cursor() as cur:
                    cur.execute(sql, (*params, int(limit), int(offset)))
                    cols = [d[0] for d in cur.description]
                    return [dict(zip(cols, row)) for row in cur.fetchall()]
            except psycopg2.Error:  # noqa: BLE001
                logger.exception('Error reading recent records from PostgreSQL storage')
                return []

    def count_recent(self, since: str | None = None) -> int:
        """Count honeypot_bears rows within the optional ``since`` window.

        Used to drive capture-log pagination (issue #316). Mirrors
        :meth:`SQLiteStorage.count_recent`.
        """
        if self._conn is None and not self._ensure_connected():
            return 0
        sql = 'SELECT COUNT(*) FROM honeypot_bears'
        params: list = []
        if since is not None:
            sql += ' WHERE timestamp >= %s'
            params.append(since)
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, params)
                return int(cur.fetchone()[0])
        except psycopg2.Error:  # noqa: BLE001
            self._reset_conn()
            if not self._ensure_connected():
                return 0
            try:
                with self._conn.cursor() as cur:
                    cur.execute(sql, params)
                    return int(cur.fetchone()[0])
            except psycopg2.Error:  # noqa: BLE001
                logger.exception('Error counting recent records from PostgreSQL storage')
                return 0

    def aggregate_stats(self, since: str | None = None, bucket: str = 'hour') -> dict:
        if self._conn is None:
            return _empty_stats()
        # Mirror the SQLite backend: convert the human-friendly window
        # ('24h'/'7d'/'30d'/'all') into an ISO cutoff. 'all' (and None) map to
        # None so no WHERE clause is emitted — a raw 'all' string compared
        # against the timestamp column matches nothing.
        cutoff = _since_to_iso(since)
        if cutoff is not None:
            where = ' WHERE timestamp >= %s'
            params: list = [cutoff]
            and_prefix = ' AND'
        else:
            where = ''
            params = []
            and_prefix = ' WHERE'
        bucket_expr = _pg_bucket_expr(bucket)

        def _run(cur) -> dict:
            def _pg_scalar(q: str, p: list) -> int:
                cur.execute(q, p)
                row = cur.fetchone()
                return int(row[0]) if row and row[0] is not None else 0

            total = _pg_scalar(f'SELECT COUNT(*) FROM honeypot_bears{where}', params)
            detected = _pg_scalar(
                f'SELECT COUNT(*) FROM honeypot_bears{where}{and_prefix} detected_id BETWEEN 1 AND %s',
                [*params, _DETECTED_SERVICE_MAX],
            )
            undetected = total - detected
            unique_ips = _pg_scalar(
                f'SELECT COUNT(DISTINCT bot_ip) FROM honeypot_bears{where}', params
            )

            def _group(col: str, top: int = 15) -> list[dict]:
                q = (
                    f'SELECT {col}, COUNT(*) AS c FROM honeypot_bears{where}{and_prefix} '
                    f"{col} IS NOT NULL AND {col} != '' "
                    f'GROUP BY {col} ORDER BY c DESC LIMIT %s'
                )
                cur.execute(q, [*params, top])
                return [{'key': r[0], 'count': r[1]} for r in cur.fetchall()]

            # by_port groups by local honeypot port (issue #299). listen_port
            # is INTEGER and 0 is the "unknown" sentinel; the generic _group's
            # `!= ''` only excludes TEXT empties, so exclude 0 explicitly.
            def _group_port(top: int = 15) -> list[dict]:
                q = (
                    f'SELECT listen_port, COUNT(*) AS c FROM honeypot_bears{where}{and_prefix} '
                    'listen_port IS NOT NULL AND listen_port <> 0 '
                    f'GROUP BY listen_port ORDER BY c DESC LIMIT %s'
                )
                cur.execute(q, [*params, top])
                return [{'key': r[0], 'count': r[1]} for r in cur.fetchall()]

            # Service grouping maps detected_id -> friendly name. The friendly
            # name is many-to-one, so group by the *mapped* label and sum
            # (issue #331).
            cur.execute(
                f'SELECT detected_id, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                'GROUP BY detected_id ORDER BY c DESC',
                params,
            )
            svc_counts: Counter[str] = Counter()
            for detected_id, c in cur.fetchall():
                svc_counts[detected_id_name(detected_id)] += c
            by_service = [{'key': k, 'count': c} for k, c in svc_counts.most_common()]

            cur.execute(
                f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                'GROUP BY b ORDER BY b',
                params,
            )
            volume = [{'bucket': r[0], 'count': r[1]} for r in cur.fetchall()]

            return {
                'total': total,
                'detected': detected,
                'undetected': undetected,
                'unique_ips': unique_ips,
                'by_service': by_service,
                'by_country': _group('bot_country'),
                'by_continent': _group('bot_continent'),
                'by_ip': _group('bot_ip'),
                'by_path': _group('request_path'),
                'by_port': _group_port(),
                'by_classification': _group('classification'),
                'volume': volume,
            }

        try:
            with self._conn.cursor() as cur:
                return _run(cur)
        except psycopg2.Error:  # noqa: BLE001 — dead conn OR aborted txn
            # Reset (rollback + close) the shared connection and retry once,
            # so a transient failure can't poison later reads/writes.
            logger.warning('PostgreSQL aggregate_stats error; rolling back and reconnecting once')
            self._reset_conn()
            if not self._ensure_connected():
                return _empty_stats()
            try:
                with self._conn.cursor() as cur:
                    return _run(cur)
            except psycopg2.Error:  # noqa: BLE001
                logger.exception('Error aggregating stats from PostgreSQL storage')
                return _empty_stats()

    def volume_series(
        self, since: str | None = None, bucket: str = 'hour', port: int | list[int] | None = None
    ) -> list[dict]:
        if self._conn is None:
            return []
        clauses: list[str] = []
        params: list = []
        if since is not None:
            clauses.append('timestamp >= %s')
            params.append(since)
        if port is not None:
            if isinstance(port, int):
                clauses.append('listen_port = %s')
                params.append(port)
            else:
                placeholders = ', '.join('%s' for _ in port)
                clauses.append(f'listen_port IN ({placeholders})')
                params.extend(port)
        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        bucket_expr = _pg_bucket_expr(bucket)
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                    'GROUP BY b ORDER BY b',
                    params,
                )
                return [{'bucket': r[0], 'count': r[1]} for r in cur.fetchall()]
        except psycopg2.Error:  # noqa: BLE001 — dead conn OR aborted txn
            # Reset (rollback + close) the shared connection and retry once,
            # so a transient failure can't poison later reads/writes.
            logger.warning('PostgreSQL volume_series error; rolling back and reconnecting once')
            self._reset_conn()
            if not self._ensure_connected():
                return []
            try:
                with self._conn.cursor() as cur:
                    cur.execute(
                        f'SELECT {bucket_expr} AS b, COUNT(*) AS c FROM honeypot_bears{where} '  # nosec B608
                        'GROUP BY b ORDER BY b',
                        params,
                    )
                    return [{'bucket': r[0], 'count': r[1]} for r in cur.fetchall()]
            except psycopg2.Error:  # noqa: BLE001
                logger.exception('Error reading volume series from PostgreSQL storage')
                return []

    # -- data lifecycle (issue #243 #4) --------------------------------------

    def delete_old_records(self, days: int = 90) -> int:
        """Delete records older than *days* days from the honeypot_bears table.

        Args:
            days: Number of days to retain. Records with timestamp older than
                this many days will be deleted. Defaults to 90.

        Returns:
            Number of rows deleted.
        """
        if self._conn is None and not self._ensure_connected():
            logger.error('PostgreSQL storage is not initialised; skipping delete')
            return 0
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            with self._lock:
                with self._conn.cursor() as cur:
                    cur.execute(
                        'SELECT COUNT(*) FROM honeypot_bears WHERE timestamp < %s',
                        (cutoff,),
                    )
                    count = cur.fetchone()[0]
                    if count > 0:
                        cur.execute(
                            'DELETE FROM honeypot_bears WHERE timestamp < %s',
                            (cutoff,),
                        )
                        self._conn.commit()
                        logger.info('Deleted %d records older than %d days', count, days)
                    return int(count)
        except (psycopg2.OperationalError, psycopg2.InterfaceError):  # noqa: BLE001
            self._reset_conn()
            logger.exception('Error deleting old records from PostgreSQL storage')
            return 0
        except psycopg2.Error:  # noqa: BLE001
            self._reset_conn()
            logger.exception('Error deleting old records from PostgreSQL storage')
            return 0

    def archive_old_records(self, days: int = 90, dest_db: str | None = None) -> str | None:
        """Archive records older than *days* days to a gzipped dump file.

        PostgreSQL has no in-process "second database" like SQLite's file copy,
        so instead of standing up a second PG database we stream the matching
        rows out via ``COPY ... TO STDOUT`` into a local gzip file, then delete
        them. This preserves the "one file per archive" shape the SQLite version
        produces and keeps the archive portable (re-loadable via ``COPY ... FROM
        STDIN`` or ``pg_restore``-style tooling).

        Args:
            days: Number of days to retain. Records with timestamp older than
                this many days will be archived. Defaults to 90.
            dest_db: Path to the archive file. If None, creates a file named
                'honeypot_archive_YYYYMMDD.sqlite' in the same directory as the
                running module's data dir — but with a ``.dump.gz`` extension to
                signal it is a Postgres COPY dump, not a SQLite file.

        Returns:
            Path to the archive file, or None if nothing was archived / on error.
        """
        if self._conn is None and not self._ensure_connected():
            logger.error('PostgreSQL storage is not initialised; skipping archive')
            return None
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            # Stream the matching rows into a gzip file via COPY TO STDOUT.
            import gzip  # noqa: PLC0415

            dest_db = dest_db or os.path.join(
                _resolve_data_dir(),
                f'honeypot_archive_{datetime.now().strftime("%Y%m%d")}.dump.gz',
            )
            with self._lock:
                with self._conn.cursor() as cur:
                    cur.execute(
                        'SELECT COUNT(*) FROM honeypot_bears WHERE timestamp < %s',
                        (cutoff,),
                    )
                    count = cur.fetchone()[0]
                    if count == 0:
                        logger.info('No records older than %d days to archive', days)
                        return None
                    # COPY ... TO STDOUT streams the rows as TSV; wrap the cursor
                    # in a gzip file so the archive is compressed on the fly.
                    with gzip.open(dest_db, 'wt', encoding='utf-8') as gzf:
                        cur.copy_expert(
                            'COPY (SELECT * FROM honeypot_bears WHERE timestamp < %s) TO STDOUT',
                            gzf,
                            (cutoff,),
                        )
                    # Now delete the archived rows.
                    cur.execute('DELETE FROM honeypot_bears WHERE timestamp < %s', (cutoff,))
                    self._conn.commit()
                    logger.info(
                        'Archived %d records older than %d days to %s', count, days, dest_db
                    )
            return dest_db
        except (psycopg2.OperationalError, psycopg2.InterfaceError):  # noqa: BLE001
            self._reset_conn()
            logger.exception('Error archiving old records from PostgreSQL storage')
            return None
        except psycopg2.Error:  # noqa: BLE001
            self._reset_conn()
            logger.exception('Error archiving old records from PostgreSQL storage')
            return None
        except OSError:  # noqa: BLE001 — file/IO errors (disk full, bad path)
            logger.exception('Error writing PostgreSQL archive file')
            return None

    def __del__(self) -> None:
        # Guard against interpreter-shutdown GC: globals ``close()`` depends on
        # (e.g. psycopg2, the logger) may already be torn down. getattr guards
        # against a half-constructed instance too (issue #243 #11).
        conn = getattr(self, '_conn', None)
        if conn is not None:
            self.close()

    def __enter__(self) -> 'PostgreSQLStorage':
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def get_storage(
    integrity_check: bool = True,
    busy_timeout: int = 5000,
    init_schema: bool = True,
) -> StorageBackend:
    """Factory to get the storage backend based on ``HONEY_DB_BACKEND``.

    Returns a cached, process-wide :class:`SQLiteStorage` or
    :class:`PostgreSQLStorage` instance. The instance is created once per process
    and reused — ``get_storage()`` is called on every captured report, and a
    fresh connection-per-call would overwhelm PostgreSQL under bot load (issue
    #243 #2). Double-checked locking via ``_STORAGE_LOCK`` keeps construction
    race-free.

    Backend selection honors both ``HONEY_DB_BACKEND`` and TOML
    ``[database] backend`` (see :func:`_resolve_backend`).

    ``integrity_check`` / ``busy_timeout`` / ``init_schema`` are forwarded to
    :class:`SQLiteStorage` so read-only callers (the dashboard) can skip the
    startup full-table scan / DDL and tolerate brief WAL write-lock contention
    without erroring or stalling.
    """
    global _STORAGE_SINGLETON
    if _STORAGE_SINGLETON is not None:
        return _STORAGE_SINGLETON

    with _STORAGE_LOCK:
        if _STORAGE_SINGLETON is not None:
            return _STORAGE_SINGLETON
        backend = _resolve_backend()
        if backend == 'postgresql':
            storage: StorageBackend = PostgreSQLStorage()
        else:
            # default to SQLite
            storage = SQLiteStorage(
                integrity_check=integrity_check,
                busy_timeout=busy_timeout,
                init_schema=init_schema,
            )
        _STORAGE_SINGLETON = storage
        return _STORAGE_SINGLETON


def backup_database(dest_dir: str | None = None) -> list[str]:
    """Back up the configured storage backend.

    SQLite: checkpoint WAL then copy the ``.sqlite`` file (existing behaviour).
    PostgreSQL (issue #243 #5): shell out to ``pg_dump -Fc`` (custom format,
    compressible, restore-via-``pg_restore``) writing ``.dump`` files, with
    rotation. The password is passed via the ``PGPASSWORD`` env var — never
    interpolated into the command string (command-injection / process-list
    credential leak).

    Args:
        dest_dir: Directory to copy backup to. Defaults to
            'deployment-analysis/latest'.

    Returns:
        List of copied/created backup file paths.
    """
    import shutil  # noqa: PLC0415

    storage = get_storage()
    dest_dir = dest_dir or os.path.join(_PROJECT_ROOT, 'deployment-analysis', 'latest')
    os.makedirs(dest_dir, exist_ok=True)

    if isinstance(storage, SQLiteStorage):
        src_path = storage.db_path
        # Checkpoint first to ensure WAL is written back to main file
        try:
            if storage._conn is not None:
                storage._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        except (sqlite3.Error, sqlite3.OperationalError):
            logger.debug('Pre-backup checkpoint failed (non-critical)')

        basename = os.path.basename(src_path)
        dest_path = os.path.join(dest_dir, basename)
        shutil.copy2(src_path, dest_path)
        logger.info('Database backed up: %s → %s', src_path, dest_path)
        return [dest_path]

    if isinstance(storage, PostgreSQLStorage):
        return _backup_postgresql(storage, dest_dir)

    logger.warning(
        'backup_database: unknown backend %r; nothing to back up', type(storage).__name__
    )
    return []


def _backup_postgresql(storage: 'PostgreSQLStorage', dest_dir: str) -> list[str]:
    """Back up a PostgreSQL backend via ``pg_dump -Fc`` (issue #243 #5)."""
    import subprocess  # noqa: PLC0415

    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    dest_path = os.path.join(dest_dir, f'honeypot-{timestamp}.dump')
    # Build an explicit arg list (shell=False) and pass the password via env so
    # it never appears in the command string or the process list.
    cmd = ['pg_dump', '-Fc', '-f', dest_path]
    env = dict(os.environ)
    if storage._dsn:
        # pg_dump honors the libpq connection string via --dbname.
        cmd += ['--dbname', storage._dsn]
        if storage._sslmode:
            cmd += ['--sslmode', storage._sslmode]
    else:
        cmd += [
            '--host',
            storage._host,
            '--port',
            str(storage._port),
            '--username',
            storage._user,
            '--dbname',
            storage._database,
        ]
        if storage._sslmode:
            cmd += ['--sslmode', storage._sslmode]
        env['PGPASSWORD'] = storage._password

    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)  # noqa: S603
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        logger.exception('pg_dump failed for PostgreSQL backup')
        return []
    logger.info('PostgreSQL database backed up: %s', dest_path)
    return [dest_path]


__all__ = [
    'StorageBackend',
    'SQLiteStorage',
    'PostgreSQLStorage',
    'get_storage',
    'backup_database',
    'validate_db_path_absolute',
]
