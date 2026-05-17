"""Shared fixtures and helpers for integration tests."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# --- Test key shared between encryptor and ServerHandler ---
TEST_KEY = 'beehive123'
BEE_IDENTIFIER = 'testbee'


@pytest.fixture(autouse=True)
def _clean_env_and_db():
    """Ensure clean DB and settings for every test."""
    from manyfaced.db.storage import _resolve_db_path

    db_path = _resolve_db_path()
    if Path(db_path).exists():
        Path(db_path).unlink(missing_ok=True)
    yield
    if Path(db_path).exists():
        Path(db_path).unlink(missing_ok=True)


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
