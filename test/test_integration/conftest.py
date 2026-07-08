"""Shared fixtures and helpers for integration tests."""

import json
import logging
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

logger = logging.getLogger(__name__)

# --- Test key shared between encryptor and ServerHandler ---
TEST_KEY = 'beehive123'
BEE_IDENTIFIER = 'testbee'


@pytest.fixture(autouse=True)
def _clean_env_and_db():
    """Ensure clean DB and settings for every test (backend-aware, issue #243).

    For SQLite it deletes the DB file. For PostgreSQL it TRUNCATEs the table —
    but ONLY when a real Postgres is actually reachable (the real-PG CI job); in
    sqlite-only environments a leaked HONEY_DB_BACKEND or absent psycopg2 must
    not turn teardown into a hard failure, so connection errors are swallowed
    with a warning and treated as "nothing to clean".
    """
    from manyfaced.db.storage import (
        _resolve_backend,
        _resolve_db_path,
        reset_storage_singleton,
    )

    # get_storage() caches a process-wide singleton; a postgresql instance
    # cached by another test package (test_storage) must not leak into this
    # package's tests (issue #243: the [postgres] extra is now installed, so PG
    # storage actually constructs and gets cached).
    reset_storage_singleton()

    backend = _resolve_backend()
    if backend == 'postgresql':
        try:
            import psycopg2
        except ImportError:
            yield
            return
        try:
            dsn = os.environ.get('HONEY_PG_DSN')
            kwargs = {'sslmode': os.environ.get('HONEY_PG_SSLMODE', 'prefer')}
            if dsn:
                conn = psycopg2.connect(dsn=dsn, **kwargs)
            else:
                conn = psycopg2.connect(
                    host=os.environ.get('HONEY_PG_HOST', '127.0.0.1'),
                    port=int(os.environ.get('HONEY_PG_PORT', '5432')),
                    database=os.environ.get('HONEY_PG_DB', 'honeypot'),
                    user=os.environ.get('HONEY_PG_USER', 'postgres'),
                    password=os.environ.get('HONEY_PG_PASSWORD', 'postgres'),
                    **kwargs,
                )
            with conn.cursor() as cur:
                cur.execute('DELETE FROM honeypot_bears')
            conn.commit()
            conn.close()
        except Exception:  # noqa: BLE001 — no Postgres here; nothing to clean
            logger.warning('PostgreSQL cleanup skipped (no reachable server)')
        yield
    else:
        db_path = _resolve_db_path()
        # Best-effort cleanup. On Windows the SQLite file may be held by a
        # connection/thread from a prior test; ignore locked-file errors (Linux
        # CI has no such locking).
        try:
            if Path(db_path).exists():
                Path(db_path).unlink(missing_ok=True)
        except OSError as exc:  # noqa: BLE001
            logger.warning('Could not remove test DB %s: %s', db_path, exc)
        yield
        # Best-effort cleanup. On Windows the SQLite file may still be held by a
        # connection/thread at teardown; ignore the locked-file error rather than
        # fail the run. Linux CI has no such locking issue.
        try:
            if Path(db_path).exists():
                Path(db_path).unlink(missing_ok=True)
        except OSError as exc:  # noqa: BLE001
            logger.warning('Could not remove test DB %s: %s', db_path, exc)


@pytest.fixture(autouse=True)
def _patch_bears_dict():
    """Ensure AUTHORIZED_BEES has our test bee.

    Mutates the dict in-place because server.py holds a reference to
    the original dict object (from 'from ... import settings' at load time).
    """
    mod = sys.modules['manyfaced.common.config']
    cfg = mod.settings

    # Mutate the original dict in-place (not a copy!)
    cfg.AUTHORIZED_BEES[BEE_IDENTIFIER] = TEST_KEY
    try:
        yield cfg
    finally:
        # Clean up just the test entry
        cfg.AUTHORIZED_BEES.pop(BEE_IDENTIFIER, None)


def make_encrypted_message(identifier: str, data: dict, key: str) -> str:
    """Encrypt *data* as JSON, AES-GCM with *key*, return 'identifier:b64(nonce|ct|tag)'."""
    from manyfaced.common.myenc import AESCipher

    aes = AESCipher(key)
    raw = json.dumps(data).encode('utf-8')
    encrypted = aes.encrypt(raw)  # returns str (base64-encoded)
    return f'{identifier}:{encrypted}'


def _verify_record(db_path, ip=None, path=None, detected=None, field=None, value=None):
    """Verify a record exists in the DB."""
    import sqlite3

    conn = sqlite3.connect(db_path)
    if field is not None:
        row = conn.execute(f'SELECT {field} FROM honeypot_bears').fetchone()
        conn.close()
        assert row is not None
        assert row[0] == value
    else:
        rows = conn.execute(
            'SELECT bot_ip, request_path, detected_id FROM honeypot_bears'
        ).fetchall()
        conn.close()
        assert len(rows) == 1
        row = rows[0]
        if ip is not None:
            assert row[0] == ip
        if path is not None:
            assert row[1] == path
        if detected is not None:
            assert row[2] == detected
