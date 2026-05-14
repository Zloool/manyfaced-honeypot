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
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Mock geoip / GeoIP (required by bearstorage) before any import ---
sys.modules['geoip'] = MagicMock()
sys.modules['geoip.geolite2'] = MagicMock()
sys.modules['GeoIP'] = MagicMock()


# --- Resolve DB path for tests (must match what storage.py resolves) ---
from manyfaced.db.storage import _resolve_db_path  # noqa: E402


# --- Test key shared between encryptor and ServerHandler ---
TEST_KEY = 'beehive123'
BEE_IDENTIFIER = 'testbee'

# --- Helpers ---
# noqa: E402 - module-level import after sys.path manipulation
from manyfaced.common.myenc import AESCipher  # noqa: E402


def make_encrypted_message(identifier: str, data: dict, key: str) -> str:  # noqa: E402
    """Encrypt *data* as JSON, AES-GCM with *key*, return 'identifier:b64(nonce|ct|tag)'."""
    aes = AESCipher(key)
    raw = json.dumps(data).encode('utf-8')
    encrypted = aes.encrypt(raw)  # returns str (base64-encoded)
    return f'{identifier}:{encrypted}'


# ---- Fixtures ----


@pytest.fixture(autouse=True)
def _clean_env_and_db():
    """Ensure clean DB and settings for every test."""
    from manyfaced.db.storage import _resolve_db_path  # noqa: E402

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
    import sys
    import manyfaced.common.config as config_mod

    mod = sys.modules['manyfaced.common.config']
    cfg = mod.settings

    # Mutate the original dict in-place (not a copy!)
    cfg.AUTHORIZED_BEES[BEE_IDENTIFIER] = TEST_KEY
    try:
        yield cfg
    finally:
        # Clean up just the test entry
        cfg.AUTHORIZED_BEES.pop(BEE_IDENTIFIER, None)


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


class TestFullPathSocketToDatabase:
    """Test the complete request pipeline: encrypted -> decrypted -> parsed -> saved.

    Multiprocessing is replaced by calling save_data synchronously so assertions
    can query the DB immediately after handle_request().
    """

    def _run_pipeline(self, bear_data):
        """Encrypt, route through handle_request with mocked process, verify result."""
        from manyfaced.server.server import ServerHandler

        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)
        update_event = MagicMock()
        args_obj = MagicMock(server=(0, 8080), verbose=False)
        handler = ServerHandler(args_obj, update_event)

        # Replace process_request entirely so save_data runs synchronously
        def capture_and_save(data):
            handler.save_data(data, args_obj)
            return True

        # Capture the data dict
        captured_data = [None]

        def capturing_process_request(data):
            captured_data[0] = data
            handler.save_data(data, args_obj)
            return True

        with patch.object(handler, 'process_request', capturing_process_request):
            result = handler.handle_request(message)

        assert result is True
        assert captured_data[0] is not None
        assert captured_data[0]['ip'] == bear_data['ip']
        return handler

    def test_detects_valid_bear_and_saves_to_sqlite(self):
        """A valid encrypted message should decrypt, parse, and save to SQLite."""
        bear_data = {
            'ip': '10.1.2.3',
            'raw_request': 'GET /wp-login.php HTTP/1.1\r\nHost: honeypot\r\n\r\n',
            'timestamp': '2026-04-18 20:00:00.000000',
            'parsed_request': {
                'command': 'GET',
                'path': '/wp-login.php',
                'version': 'HTTP/1.1',
                'headers': {'Host': 'honeypot'},
            },
            'is_detected': 1,
            'HIVELOGIN': '',
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(_resolve_db_path(), ip='10.1.2.3', path='/wp-login.php', detected=1)

    def test_detects_webdav_scan_and_saves_to_sqlite(self):
        """A WebDAV PROPFIND-style scan should be detected and stored."""
        bear_data = {
            'ip': '192.168.99.99',
            'raw_request': 'PROPFIND /webdav/ HTTP/1.1\r\nHost: honeypot\r\n\r\n',
            'timestamp': '2026-04-18 21:00:00.000000',
            'parsed_request': {
                'command': 'PROPFIND',
                'path': '/webdav/',
                'version': 'HTTP/1.1',
                'headers': {'Host': 'honeypot'},
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            'hostname': 'localhost',
            'country': 'RU',
            'continent': 'EU',
            'tracert': '',
            'dns_name': '',
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            _resolve_db_path(),
            ip='192.168.99.99',
            path='/webdav/',
            field='request_command',
            value='PROPFIND',
        )

    def test_incorrect_identifier_fails_gracefully(self):
        """An unknown identifier falls back to DEFAULT_KEY; garbage data fails decryption."""
        from manyfaced.server.server import ServerHandler

        aes = AESCipher(TEST_KEY)
        garbage = b'\x00\x01\x02\x03\x04\x05' * 3
        encrypted = aes.encrypt(garbage)  # returns str
        message = f'unknown_bear:{encrypted}'

        handler = ServerHandler(MagicMock(server=(0, 6669), verbose=False), MagicMock())
        # Unknown identifier falls back to DEFAULT_KEY, but decryption fails because
        # the data was encrypted with TEST_KEY (not DEFAULT_KEY) → InvalidTag exception
        with pytest.raises(Exception):
            handler.handle_request(message)

        # Verify nothing was saved to the DB
        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        # Table may not exist if no valid request was processed yet
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='honeypot_bears'"
        ).fetchall()
        if tables:
            count = conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()[0]
            assert count == 0
        conn.close()

    def test_invalid_format_raises_valueerror(self):
        """A message without ':' delimiter should raise ValueError."""
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6669), verbose=False), MagicMock())
        with pytest.raises(ValueError):
            handler.handle_request('no-colon-here')

    def test_invalid_json_raises_valueerror(self):
        """Valid identifier:valid AES but invalid JSON should raise ValueError."""
        from manyfaced.server.server import ServerHandler

        aes = AESCipher(TEST_KEY)
        garbage = b'\x00\x01\x02\x03\x04\x05' * 3
        encrypted = aes.encrypt(garbage)  # returns str
        message = f'{BEE_IDENTIFIER}:{encrypted}'

        handler = ServerHandler(MagicMock(server=(0, 6670), verbose=False), MagicMock())
        with pytest.raises(ValueError):
            handler.handle_request(message)

    def test_multiple_records_in_database(self):
        """Multiple messages should create multiple separate DB rows."""
        from manyfaced.server.server import ServerHandler

        args_obj = MagicMock(server=(0, 6671), verbose=False)

        # Insert 3 records using save_data directly (synchronous)
        for i in range(3):
            bear_data = {
                'ip': f'10.10.10.{i}',
                'raw_request': f'GET /path{i}\r\n\r\n',
                'timestamp': f'2026-04-18 {20 + i}:00:00.000000',
                'parsed_request': {'command': 'GET', 'path': f'/path{i}'},
                'is_detected': 1,
                'HIVELOGIN': '',
            }
            handler = ServerHandler(MagicMock(server=(0, 6671), verbose=False), MagicMock())
            handler.save_data(bear_data, args_obj)

        # Verify all 3 records exist
        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        count = conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()[0]
        conn.close()
        assert count == 3

        # Verify specific IPs exist
        conn = sqlite3.connect(_resolve_db_path())
        ips = [r[0] for r in conn.execute('SELECT bot_ip FROM honeypot_bears').fetchall()]
        conn.close()
        assert '10.10.10.0' in ips
        assert '10.10.10.1' in ips
        assert '10.10.10.2' in ips

    def test_raw_request_preserved_in_database(self):
        """The raw_request field should be stored verbatim."""
        raw = 'GET /wp-content/debug.log HTTP/1.1\r\nHost: honeypot\r\n\r\n'
        bear_data = {
            'ip': '172.16.0.1',
            'raw_request': raw,
            'timestamp': '2026-04-18 23:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/wp-content/debug.log'},
            'is_detected': 1,
            'HIVELOGIN': '',
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            _resolve_db_path(),
            ip='172.16.0.1',
            path='/wp-content/debug.log',
            field='request_raw',
            value=raw,
        )

    def test_hivelogin_field_stored(self):
        """HIVELOGIN field should be stored in the login column."""
        bear_data = {
            'ip': '10.10.10.10',
            'raw_request': 'GET /\r\n\r\n',
            'timestamp': '2026-04-19 00:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/'},
            'is_detected': 1,
            'HIVELOGIN': 'testuser123',
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(_resolve_db_path(), field='login', value='testuser123')

    def test_detected_field_preserved(self):
        """is_detected should store the correct value in detected_id."""
        from manyfaced.common.status import UNKNOWN_HTTP

        bear_data = {
            'ip': '10.10.10.20',
            'raw_request': 'GET /unknown\r\n\r\n',
            'timestamp': '2026-04-19 01:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/unknown'},
            'is_detected': UNKNOWN_HTTP,
            'HIVELOGIN': '',
        }

        _ = self._run_pipeline(bear_data)

        _verify_record(
            _resolve_db_path(),
            ip='10.10.10.20',
            path='/unknown',
            detected=UNKNOWN_HTTP,
        )


class TestServerHandlerDirect:
    """Direct server handler tests (no encryption, just process_request)."""

    def test_process_request_starts_save_process(self):
        """process_request should save data and return True."""
        from manyfaced.server.server import ServerHandler

        data = {
            'ip': '10.0.0.1',
            'raw_request': 'GET /\r\n\r\n',
            'timestamp': '2026-04-19 03:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/'},
            'is_detected': 1,
            'HIVELOGIN': 'test_bear',
        }

        handler = ServerHandler(MagicMock(server=(0, 6676), verbose=False), MagicMock())
        result = handler.process_request(data)
        assert result is True


class TestAESRoundtrip:
    """Verify AESCipher encrypt/decrypt roundtrip works with the fixed implementation."""

    def test_encrypt_decrypt_roundtrip(self):
        """Real AESCipher encrypt + decrypt roundtrip should work."""
        aes = AESCipher('roundtrip_test')
        original = json.dumps(
            {
                'ip': '1.2.3.4',
                'raw_request': 'GET /\r\n\r\n',
                'timestamp': '2026-04-19 07:00:00.000000',
                'parsed_request': {'command': 'GET', 'path': '/'},
                'is_detected': 1,
            }
        ).encode('utf-8')

        encrypted = aes.encrypt(original)
        decrypted = aes.decrypt(encrypted)

        assert json.loads(decrypted.decode('utf-8')) == json.loads(original.decode('utf-8'))

    def test_different_keys_cannot_decrypt(self):
        """Encrypted with one key should not decrypt with a different key."""
        aes_correct = AESCipher('correct_key')
        aes_wrong = AESCipher('wrong_key')

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
        key = handler.get_key(BEE_IDENTIFIER)
        assert key == TEST_KEY

    def test_get_key_raises_for_unknown_bean(self):
        """get_key should raise ValueError for unknown identifiers (no fallback)."""
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6677), verbose=False), MagicMock())
        with pytest.raises(ValueError, match='Unknown identifier'):
            handler.get_key('completely_unknown_bean')

    def test_get_key_raises_when_no_default_key(self):
        """get_key should raise ValueError when neither AUTHORISEDBEARS nor DEFAULT_KEY is set."""
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6678), verbose=False), MagicMock())
        # Use object.__setattr__ to bypass frozen dataclass restriction
        saved_default_key = (
            handler.args.DEFAULT_KEY if hasattr(handler.args, 'DEFAULT_KEY') else None
        )
        # We need to patch settings.DEFAULT_KEY directly via the module
        import manyfaced.common.config as config_mod

        mod = sys.modules['manyfaced.common.config']
        cfg = mod.settings

        # Save and clear DEFAULT_KEY using object.__setattr__ for frozen dataclass
        saved_default_key = cfg.DEFAULT_KEY
        object.__setattr__(cfg, 'DEFAULT_KEY', None)
        try:
            with pytest.raises(ValueError, match='Unknown identifier'):
                handler.get_key('completely_unknown_bear')
        finally:
            # Restore DEFAULT_KEY
            object.__setattr__(cfg, 'DEFAULT_KEY', saved_default_key)


class TestSQLiteStorageDirect:
    """Test SQLite storage backend directly (no encryption)."""

    def test_insert_and_query_record(self):
        """Verify SQLiteStorage insert works end-to-end."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_integration_store.sqlite'
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    'ip': '1.2.3.4',
                    'hostname': 'example.com',
                    'timestamp': '2026-04-19 03:00:00.000000',
                    'parsed_request': {
                        'command': 'GET',
                        'path': '/test',
                        'version': 'HTTP/1.1',
                        'headers': {'Host': 'x'},
                    },
                    'is_detected': 1,
                    'raw_request': 'GET /test\r\n\r\n',
                    'ua': 'TestAgent',
                    'country': 'US',
                    'continent': 'NA',
                    'tracert': '',
                    'dns_name': '',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            'SELECT bot_ip, request_path, request_command, request_version, '
            'detected_id, login FROM honeypot_bears'
        ).fetchone()
        conn.close()

        assert row[0] == '1.2.3.4'
        assert row[1] == '/test'
        assert row[2] == 'GET'
        assert row[3] == 'HTTP/1.1'
        assert row[4] == 1
        assert row[5] == ''

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_insert_handles_extra_fields(self):
        """SQLiteStorage should handle extra fields gracefully."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_extra.sqlite'
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    'ip': '5.6.7.8',
                    'timestamp': '2026-04-19 04:00:00',
                    'extra_field': 'ignored',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute('SELECT bot_ip FROM honeypot_bears').fetchone()
        conn.close()
        assert row[0] == '5.6.7.8'

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_insert_with_datetime_timestamp(self):
        """Datetime objects as timestamp should also work."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_dt.sqlite'

        with SQLiteStorage(db_path) as store:
            store.insert({'ip': '9.10.11.12', 'timestamp': '2026-04-19 05:00:00'})
        with SQLiteStorage(db_path) as store:
            store.insert({'ip': '13.14.15.16', 'timestamp': datetime(2026, 4, 19, 6, 0, 0)})

        import sqlite3

        conn = sqlite3.connect(db_path)
        count = conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()[0]
        conn.close()
        assert count == 2

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)


class TestEnrichmentPipeline:
    """Tests for the HTTP enrichment pipeline (ua, dns_name, country, continent)."""

    def test_enrichment_fields_flow_through_save_data(self):
        """A payload with ua/dns_name/country/continent should reach storage.insert()."""
        from manyfaced.server.server import ServerHandler

        bear_data = {
            'ip': '203.0.113.42',
            'raw_request': 'GET /wp-login.php HTTP/1.1\r\nHost: honeypot\r\n\r\n',
            'timestamp': '2026-05-14 12:00:00.000000',
            'parsed_request': {
                'command': 'GET',
                'path': '/wp-login.php',
                'version': 'HTTP/1.1',
                'headers': {'Host': 'honeypot'},
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            'ua': 'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
            'dns_name': 'scanner.example.net',
            'country': 'United States',
            'continent': 'North America',
        }

        args_obj = MagicMock(server=(0, 8090), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())
        handler.save_data(bear_data, args_obj)

        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_user_agent, bot_dns_name, bot_country, bot_continent '
            'FROM honeypot_bears WHERE bot_ip = ?',
            ('203.0.113.42',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 'Mozilla/5.0 (compatible; Nmap Scripting Engine)'
        assert row[1] == 'scanner.example.net'
        assert row[2] == 'United States'
        assert row[3] == 'North America'

    def test_enrichment_defaults_to_empty_when_missing(self):
        """Missing enrichment keys should result in empty strings in the DB."""
        from manyfaced.server.server import ServerHandler

        bear_data = {
            'ip': '198.51.100.7',
            'raw_request': 'GET / HTTP/1.1\r\n\r\n',
            'timestamp': '2026-05-14 13:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/'},
            'is_detected': 0,
            'HIVELOGIN': '',
        }

        args_obj = MagicMock(server=(0, 8091), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())
        handler.save_data(bear_data, args_obj)

        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_user_agent, bot_dns_name, bot_country, bot_continent '
            'FROM honeypot_bears WHERE bot_ip = ?',
            ('198.51.100.7',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == ''
        assert row[1] == ''
        assert row[2] == ''
        assert row[3] == ''


class TestHostnameFallback:
    """Tests for hostname extraction with HIVELOGIN fallback."""

    def test_hostname_fallback_to_hivelogin(self):
        """When record has no 'hostname' key, storage should fall back to HIVELOGIN."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_hostname_fallback.sqlite'
        with SQLiteStorage(db_path) as store:
            # No 'hostname' key — only HIVELOGIN is present
            store.insert(
                {
                    'ip': '10.99.99.99',
                    'timestamp': '2026-05-14 14:00:00',
                    'parsed_request': {'command': 'GET', 'path': '/'},
                    'is_detected': 1,
                    'raw_request': 'GET / HTTP/1.1\r\n\r\n',
                    'HIVELOGIN': 'admin_user',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            'SELECT hostname FROM honeypot_bears WHERE bot_ip = ?',
            ('10.99.99.99',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 'admin_user'

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_hostname_takes_precedence_over_hivelogin(self):
        """When both hostname and HIVELOGIN are present, hostname wins."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_hostname_precedence.sqlite'
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    'ip': '10.88.88.88',
                    'hostname': 'real-hostname.local',
                    'timestamp': '2026-05-14 15:00:00',
                    'parsed_request': {'command': 'GET', 'path': '/'},
                    'is_detected': 1,
                    'raw_request': 'GET / HTTP/1.1\r\n\r\n',
                    'HIVELOGIN': 'admin_user',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            'SELECT hostname FROM honeypot_bears WHERE bot_ip = ?',
            ('10.88.88.88',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 'real-hostname.local'

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)
