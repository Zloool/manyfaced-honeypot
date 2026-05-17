"""Test the complete request pipeline: encrypted -> decrypted -> parsed -> saved."""

from unittest.mock import MagicMock, patch

import pytest

from .conftest import TEST_KEY, BEE_IDENTIFIER, make_encrypted_message, _verify_record


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
        from manyfaced.db.storage import _resolve_db_path

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
        from manyfaced.db.storage import _resolve_db_path

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
        from manyfaced.common.myenc import AESCipher
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

        from manyfaced.db.storage import _resolve_db_path

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
        from manyfaced.common.myenc import AESCipher
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

        from manyfaced.db.storage import _resolve_db_path

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
        from manyfaced.db.storage import _resolve_db_path

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
        from manyfaced.db.storage import _resolve_db_path

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
        from manyfaced.db.storage import _resolve_db_path

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
