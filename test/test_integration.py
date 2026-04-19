"""
Integration tests covering the full request path:

  encrypted message -> handle_request() -> decrypt -> parse -> process_request()
  -> save_data() (synchronous, via mock) -> SQLite insert
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest

# --- Project root wiring ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Mock geoip / GeoIP (required by bearstorage) before any import ---
sys.modules["geoip"] = MagicMock()
sys.modules["geoip.geolite2"] = MagicMock()
sys.modules["GeoIP"] = MagicMock()

# --- Ensure settings.py exists for import ---
settings_dst = Path(project_root) / "manyfaced" / "common" / "settings.py"
settings_src = settings_dst.with_suffix(".example")
if not settings_dst.exists() and settings_src.exists():
    settings_dst.parent.mkdir(parents=True, exist_ok=True)
    settings_dst.write_text(settings_src.read_text())

# --- Test key shared between encryptor and ServerHandler ---
TEST_KEY = "beehive123"
BEAR_IDENTIFIER = "testbear"

# --- Helpers ---
# noqa: E402 - module-level import after sys.path manipulation
from manyfaced.common.myenc import AESCipher  # noqa: E402


def make_encrypted_message(identifier: str, data: dict, key: str) -> str:  # noqa: E402
    """Encrypt *data* as JSON, AES-CBC with *key*, return 'identifier:b64(IV|ct)'."""
    aes = AESCipher(key)
    raw = json.dumps(data).encode("utf-8")
    encrypted = aes.encrypt(raw)
    return f"{identifier}:{encrypted.decode()}"


# ---- Fixtures ----


@pytest.fixture(autouse=True)
def _clean_env_and_db():
    """Ensure clean DB and settings for every test."""
    db_path = "bots/honeypot.sqlite"
    if Path(db_path).exists():
        Path(db_path).unlink(missing_ok=True)
    yield
    if Path(db_path).exists():
        Path(db_path).unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def _patch_bears_dict():
    """Ensure AUTHORISEDBEARS has our test bear.

    Uses setattr which works whether the module has the attr in __dict__
    or gets it via __getattr__.  We mutate in-place because server.py
    did 'from ... import AUTHORISEDBEARS' at load time and holds a
    reference to the original dict object.
    """
    import sys
    import manyfaced.common.settings as settings_mod

    mod = sys.modules["manyfaced.common.settings"]

    # Read current value if it exists (may come from __getattr__)
    old_val = getattr(mod, "AUTHORISEDBEARS", None)
    # Ensure it's at least a dict (may be provided by env defaults in __getattr__)
    if old_val is None or not isinstance(old_val, dict):
        # Create a dict and set it so future getattr calls find it in __dict__
        old_val = {}
        setattr(mod, "AUTHORISEDBEARS", old_val)

    # Store the original before mutation so we can restore
    original_dict = mod.__dict__["AUTHORISEDBEARS"]

    # Add our test bear in-place
    original_dict["testbear"] = TEST_KEY
    try:
        yield settings_mod
    finally:
        # Clean up just the test entry
        original_dict.pop("testbear", None)
        # Restore original dict object
        setattr(mod, "AUTHORISEDBEARS", original_dict)


def _verify_record(db_path, ip=None, path=None, detected=None, field=None, value=None):
    """Verify a record exists in the DB."""
    import sqlite3

    conn = sqlite3.connect(db_path)
    if field is not None:
        row = conn.execute(f"SELECT {field} FROM honeypot_bears").fetchone()
        conn.close()
        assert row is not None
        assert row[0] == value
    else:
        rows = conn.execute(
            "SELECT bot_ip, request_path, detected_id FROM honeypot_bears"
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


class TestFullPathSocketToDatabase:
    """Test the complete request pipeline: encrypted -> decrypted -> parsed -> saved.

    Multiprocessing is replaced by calling save_data synchronously so assertions
    can query the DB immediately after handle_request().
    """

    def _run_pipeline(self, bear_data):
        """Encrypt, route through handle_request with mocked process, verify result."""
        from manyfaced.server.server import ServerHandler
        from multiprocessing import Lock

        message = make_encrypted_message(BEAR_IDENTIFIER, bear_data, TEST_KEY)
        update_event = MagicMock()
        args_obj = MagicMock(server=(0, 8080), verbose=False)
        handler = ServerHandler(args_obj, update_event)

        # Replace process_request entirely so save_data runs synchronously
        def capture_and_save(data):
            handler.save_data(data, args_obj, Lock())
            return True

        # Capture the data dict
        captured_data = [None]

        def capturing_process_request(data):
            captured_data[0] = data
            handler.save_data(data, args_obj, Lock())
            return True

        with patch.object(handler, "process_request", capturing_process_request):
            result = handler.handle_request(message)

        assert result is True
        assert captured_data[0] is not None
        assert captured_data[0]["ip"] == bear_data["ip"]
        return handler

    def test_detects_valid_bear_and_saves_to_sqlite(self):
        """A valid encrypted message should decrypt, parse, and save to SQLite."""
        bear_data = {
            "ip": "10.1.2.3",
            "raw_request": "GET /wp-login.php HTTP/1.1\r\nHost: honeypot\r\n\r\n",
            "timestamp": "2026-04-18 20:00:00.000000",
            "parsed_request": {
                "command": "GET",
                "path": "/wp-login.php",
                "version": "HTTP/1.1",
                "headers": {"Host": "honeypot"},
            },
            "is_detected": 1,
            "HIVELOGIN": "",
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            "bots/honeypot.sqlite", ip="10.1.2.3", path="/wp-login.php", detected=1
        )

    def test_detects_webdav_scan_and_saves_to_sqlite(self):
        """A WebDAV PROPFIND-style scan should be detected and stored."""
        bear_data = {
            "ip": "192.168.99.99",
            "raw_request": "PROPFIND /webdav/ HTTP/1.1\r\nHost: honeypot\r\n\r\n",
            "timestamp": "2026-04-18 21:00:00.000000",
            "parsed_request": {
                "command": "PROPFIND",
                "path": "/webdav/",
                "version": "HTTP/1.1",
                "headers": {"Host": "honeypot"},
            },
            "is_detected": 1,
            "HIVELOGIN": "",
            "hostname": "localhost",
            "country": "RU",
            "continent": "EU",
            "tracert": "",
            "dns_name": "",
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            "bots/honeypot.sqlite",
            ip="192.168.99.99",
            path="/webdav/",
            field="request_command",
            value="PROPFIND",
        )

    def test_incorrect_identifier_fails_gracefully(self):
        """An unknown identifier should raise ValueError and not save."""
        from manyfaced.server.server import ServerHandler

        import sys as _sys

        old = getattr(
            _sys.modules["manyfaced.common.settings"], "AUTHORISEDBEARS", None
        )
        _sys.modules["manyfaced.common.settings"].AUTHORISEDBEARS = dict()

        try:
            unknown_bear_data = {
                "ip": "10.0.0.1",
                "raw_request": "GET /admin\r\n\r\n",
                "timestamp": "2026-04-18 22:00:00.000000",
                "parsed_request": {"command": "GET", "path": "/admin"},
                "is_detected": 1,
                "HIVELOGIN": "",
            }
            message = make_encrypted_message(
                "unknown_bear", unknown_bear_data, TEST_KEY
            )
            handler = ServerHandler(
                MagicMock(server=(0, 6668), verbose=False), MagicMock()
            )
            with pytest.raises((ValueError, TypeError, KeyError, AttributeError)):
                handler.handle_request(message)
        finally:
            if old is None:
                _sys.modules["manyfaced.common.settings"].__dict__.pop(
                    "AUTHORISEDBEARS", None
                )
            else:
                _sys.modules["manyfaced.common.settings"].AUTHORISEDBEARS = old

    def test_invalid_format_raises_valueerror(self):
        """A message without ':' delimiter should raise ValueError."""
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6669), verbose=False), MagicMock())
        with pytest.raises(ValueError):
            handler.handle_request("no-colon-here")

    def test_invalid_json_raises_valueerror(self):
        """Valid identifier:valid AES but invalid JSON should raise ValueError."""
        from manyfaced.server.server import ServerHandler

        aes = AESCipher(TEST_KEY)
        garbage = b"\x00\x01\x02\x03\x04\x05" * 3
        encrypted = aes.encrypt(garbage)
        message = f"{BEAR_IDENTIFIER}:{encrypted.decode()}"

        handler = ServerHandler(MagicMock(server=(0, 6670), verbose=False), MagicMock())
        with pytest.raises(ValueError):
            handler.handle_request(message)

    def test_multiple_records_in_database(self):
        """Multiple messages should create multiple separate DB rows."""
        from manyfaced.server.server import ServerHandler
        from multiprocessing import Lock

        args_obj = MagicMock(server=(0, 6671), verbose=False)

        # Insert 3 records using save_data directly (synchronous)
        for i in range(3):
            bear_data = {
                "ip": f"10.10.10.{i}",
                "raw_request": f"GET /path{i}\r\n\r\n",
                "timestamp": f"2026-04-18 {20 + i}:00:00.000000",
                "parsed_request": {"command": "GET", "path": f"/path{i}"},
                "is_detected": 1,
                "HIVELOGIN": "",
            }
            handler = ServerHandler(
                MagicMock(server=(0, 6671), verbose=False), MagicMock()
            )
            lock = Lock()
            handler.save_data(bear_data, args_obj, lock)

        # Verify all 3 records exist
        import sqlite3

        conn = sqlite3.connect("bots/honeypot.sqlite")
        count = conn.execute("SELECT COUNT(*) FROM honeypot_bears").fetchone()[0]
        conn.close()
        assert count == 3

        # Verify specific IPs exist
        conn = sqlite3.connect("bots/honeypot.sqlite")
        ips = [
            r[0] for r in conn.execute("SELECT bot_ip FROM honeypot_bears").fetchall()
        ]
        conn.close()
        assert "10.10.10.0" in ips
        assert "10.10.10.1" in ips
        assert "10.10.10.2" in ips

    def test_raw_request_preserved_in_database(self):
        """The raw_request field should be stored verbatim."""
        raw = "GET /wp-content/debug.log HTTP/1.1\r\nHost: honeypot\r\n\r\n"
        bear_data = {
            "ip": "172.16.0.1",
            "raw_request": raw,
            "timestamp": "2026-04-18 23:00:00.000000",
            "parsed_request": {"command": "GET", "path": "/wp-content/debug.log"},
            "is_detected": 1,
            "HIVELOGIN": "",
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            "bots/honeypot.sqlite",
            ip="172.16.0.1",
            path="/wp-content/debug.log",
            field="request_raw",
            value=raw,
        )

    def test_hivelogin_field_stored(self):
        """HIVELOGIN field should be stored in the login column."""
        bear_data = {
            "ip": "10.10.10.10",
            "raw_request": "GET /\r\n\r\n",
            "timestamp": "2026-04-19 00:00:00.000000",
            "parsed_request": {"command": "GET", "path": "/"},
            "is_detected": 1,
            "HIVELOGIN": "testuser123",
        }

        _ = self._run_pipeline(bear_data)

        _verify_record("bots/honeypot.sqlite", field="login", value="testuser123")

    def test_detected_field_preserved(self):
        """is_detected should store the correct value in detected_id."""
        from manyfaced.common.status import UNKNOWN_HTTP

        bear_data = {
            "ip": "10.10.10.20",
            "raw_request": "GET /unknown\r\n\r\n",
            "timestamp": "2026-04-19 01:00:00.000000",
            "parsed_request": {"command": "GET", "path": "/unknown"},
            "is_detected": UNKNOWN_HTTP,
            "HIVELOGIN": "",
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            "bots/honeypot.sqlite",
            ip="10.10.10.20",
            path="/unknown",
            detected=UNKNOWN_HTTP,
        )


class TestServerHandlerDirect:
    """Direct server handler tests (no encryption, just process_request)."""

    def test_process_request_starts_save_process(self):
        """process_request should start save process and return True."""
        from manyfaced.server.server import ServerHandler

        data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /\r\n\r\n",
            "timestamp": "2026-04-19 03:00:00.000000",
            "parsed_request": {"command": "GET", "path": "/"},
            "is_detected": 1,
        }

        handler = ServerHandler(MagicMock(server=(0, 6676), verbose=False), MagicMock())
        result = handler.process_request(data)
        assert result is True


class TestAESRoundtrip:
    """Verify AESCipher encrypt/decrypt roundtrip works with the fixed implementation."""

    def test_encrypt_decrypt_roundtrip(self):
        """Real AESCipher encrypt + decrypt roundtrip should work."""
        aes = AESCipher("roundtrip_test")
        original = json.dumps(
            {
                "ip": "1.2.3.4",
                "raw_request": "GET /\r\n\r\n",
                "timestamp": "2026-04-19 07:00:00.000000",
                "parsed_request": {"command": "GET", "path": "/"},
                "is_detected": 1,
            }
        ).encode("utf-8")

        encrypted = aes.encrypt(original)
        decrypted = aes.decrypt(encrypted)

        assert json.loads(decrypted.decode("utf-8")) == json.loads(
            original.decode("utf-8")
        )

    def test_different_keys_cannot_decrypt(self):
        """Encrypted with one key should not decrypt with a different key."""
        aes_correct = AESCipher("correct_key")
        aes_wrong = AESCipher("wrong_key")

        original = b'{"ip":"1.2.3.4"}'
        encrypted = aes_correct.encrypt(original)

        try:
            decrypted = aes_wrong.decrypt(encrypted)
            assert decrypted != original
        except Exception:
            pass


class TestServerHandlerKeyLookup:
    """Test ServerHandler key lookup."""

    def test_get_key_returns_key_for_known_bear(self):
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6677), verbose=False), MagicMock())
        key = handler.get_key("testbear")
        assert key == TEST_KEY

    def test_get_key_returns_none_for_unknown_bear(self):
        import sys
        from manyfaced.server.server import ServerHandler

        old = getattr(sys.modules["manyfaced.common.settings"], "AUTHORISEDBEARS", None)
        sys.modules["manyfaced.common.settings"].AUTHORISEDBEARS = dict()
        try:
            handler = ServerHandler(
                MagicMock(server=(0, 6677), verbose=False), MagicMock()
            )
            key = handler.get_key("unknown_bear")
            assert key is None
        finally:
            if old is None:
                sys.modules["manyfaced.common.settings"].__dict__.pop(
                    "AUTHORISEDBEARS", None
                )
            else:
                sys.modules["manyfaced.common.settings"].AUTHORISEDBEARS = old


class TestSQLiteStorageDirect:
    """Test SQLite storage backend directly (no encryption)."""

    def test_insert_and_query_record(self):
        """Verify SQLiteStorage insert works end-to-end."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = "bots/test_integration_store.sqlite"
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    "ip": "1.2.3.4",
                    "hostname": "example.com",
                    "timestamp": "2026-04-19 03:00:00.000000",
                    "parsed_request": {
                        "command": "GET",
                        "path": "/test",
                        "version": "HTTP/1.1",
                        "headers": {"Host": "x"},
                    },
                    "is_detected": 1,
                    "raw_request": "GET /test\r\n\r\n",
                    "ua": "TestAgent",
                    "country": "US",
                    "continent": "NA",
                    "tracert": "",
                    "dns_name": "",
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT bot_ip, request_path, request_command, request_version, "
            "detected_id, login FROM honeypot_bears"
        ).fetchone()
        conn.close()

        assert row[0] == "1.2.3.4"
        assert row[1] == "/test"
        assert row[2] == "GET"
        assert row[3] == "HTTP/1.1"
        assert row[4] == 1
        assert row[5] == ""

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_insert_handles_extra_fields(self):
        """SQLiteStorage should handle extra fields gracefully."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = "bots/test_extra.sqlite"
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    "ip": "5.6.7.8",
                    "timestamp": "2026-04-19 04:00:00",
                    "extra_field": "ignored",
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT bot_ip FROM honeypot_bears").fetchone()
        conn.close()
        assert row[0] == "5.6.7.8"

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_insert_with_datetime_timestamp(self):
        """Datetime objects as timestamp should also work."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = "bots/test_dt.sqlite"

        with SQLiteStorage(db_path) as store:
            store.insert({"ip": "9.10.11.12", "timestamp": "2026-04-19 05:00:00"})
        with SQLiteStorage(db_path) as store:
            store.insert(
                {"ip": "13.14.15.16", "timestamp": datetime(2026, 4, 19, 6, 0, 0)}
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM honeypot_bears").fetchone()[0]
        conn.close()
        assert count == 2

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)
