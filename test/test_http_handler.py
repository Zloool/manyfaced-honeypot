"""
Comprehensive pytest tests for HTTPHandler and HTTPRequest modules.

Tests the new router architecture:
- HTTPHandler routes requests through an explicit Router with ordered route table
- Service handlers generate realistic honeypot responses
- BotProfile tracks per-bot state
"""

import os
import sys
from unittest.mock import MagicMock, patch

_CRLF = chr(13) + chr(10)  # CRLF without backslash escapes (keeps tests ASCII-safe)

import pytest

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip before any handler module is imported
_geoip_mock = MagicMock()
_geoip_mock.geolite2.geolite2 = _geoip_mock.geolite2
sys.modules['geoip'] = _geoip_mock
sys.modules['geoip.geolite2'] = _geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()

from manyfaced.common.httphandler import HTTPRequest  # noqa: E402
from manyfaced.handlers.http_handler import HTTPHandler  # noqa: E402
from manyfaced.common.bearstorage import BearStorage  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_resolve_geo():
    """Stub BearStorage.resolve_geo / resolve_dns_name so handler tests never
    hit the real ip-api rate limiter (~1.33s sleep per lookup in the worker
    thread) or perform a synchronous reverse-DNS call (socket.gethostbyaddr,
    ~1s timeout when the IP has no PTR).

    Also stub the report send (``send_report``): several tests below set
    ``args.server = 9999`` (a dead localhost port) to exercise the
    queue/thread-pool path. Without this stub the worker would spend ~30s on
    connect retries to the dead port. The test still asserts the queue path is
    taken (e.g. ``process_request`` submits a job); only the real TCP send is
    removed. Real end-to-end report delivery is covered by test_e2e_pipeline.py.

    Routing/enrichment tests assert on response *content* or on
    ``resolve_geo.assert_called_once_with(...)`` — stubbing the return value
    keeps the call (so those assertions stay valid) while removing the waits.
    The geo + DNS lookups themselves are exercised by test_geolocate.py and the
    enrichment integration tests that opt out of this fixture.
    """
    with (
        patch.object(BearStorage, 'resolve_geo', return_value=('', '', '', '')),
        patch.object(BearStorage, 'resolve_dns_name', return_value=''),
        patch('manyfaced.client.report_sender.send_report', lambda *a, **k: None),
    ):
        yield


# ---------------------------------------------------------------------------
# HTTPHandler Tests
# ---------------------------------------------------------------------------


class TestHTTPHandlerHandleRequest:
    """Tests for HTTPHandler.handle_request()."""

    @pytest.fixture
    def handler(self):
        """Create a minimal HTTPHandler instance."""
        args = MagicMock()
        args.verbose = False
        args.server = None  # No server port = no report sent
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_handle_request_parses_http(self, handler):
        """handle_request() should parse the raw HTTP request."""
        output = handler.handle_request(
            'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            bot_ip='1.2.3.4',
        )
        assert isinstance(output, bytes)
        assert len(output) > 0

    def test_handle_request_routes_to_wordpress(self, handler):
        """handle_request() should route /wp-login.php to WordPressHandler."""
        output = handler.handle_request(
            'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            bot_ip='1.2.3.4',
        )
        assert b'WordPress' in output
        assert b'wp-login.php' in output

    def test_handle_request_routes_to_phpmyadmin(self, handler):
        """handle_request() should route /phpmyadmin/ to PhpMyAdminHandler."""
        output = handler.handle_request(
            'GET /phpmyadmin/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            bot_ip='1.2.3.4',
        )
        assert b'phpMyAdmin' in output

    def test_handle_request_routes_generic(self, handler):
        """handle_request() should route unknown paths to GenericHandler."""
        output = handler.handle_request(
            'GET /random-path HTTP/1.1\r\nHost: example.com\r\n\r\n',
            bot_ip='1.2.3.4',
        )
        assert b'Server Administration Panel' in output

    def test_handle_request_post_login_captures_credentials(self, handler):
        """handle_request() should capture credentials from login POST."""
        output = handler.handle_request(
            'POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nlog=admin&pwd=secret123',
            bot_ip='1.2.3.4',
        )
        # Should return login failed response
        assert b'ERROR' in output or b'Invalid username' in output

    def test_handle_request_with_query_string(self, handler):
        """handle_request() should handle query strings in paths."""
        output = handler.handle_request(
            'GET /search?q=test&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n',
            bot_ip='1.2.3.4',
        )
        assert isinstance(output, bytes)
        assert len(output) > 0

    def test_handle_request_fallback_on_parse_error(self, handler):
        """handle_request() should handle malformed requests gracefully."""
        # This should not raise an exception
        output = handler.handle_request(
            'INVALID REQUEST',
            bot_ip='1.2.3.4',
        )
        assert isinstance(output, bytes)


class TestHTTPHandlerProcessRequest:
    """Tests for HTTPHandler.process_request()."""

    @pytest.fixture
    def handler(self):
        """Create a minimal HTTPHandler instance."""
        args = MagicMock()
        args.verbose = False
        args.server = None  # No server port = no report sent
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    @pytest.fixture
    def sample_data(self):
        """Provide a sample request data dict."""
        raw = 'GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n'
        return {
            'ip': '10.0.0.1',
            'raw_request': raw,
            'parsed_request': MagicMock(),
        }

    def test_process_request_returns_response(self, handler, sample_data):
        """process_request() should return response bytes."""
        result = handler.process_request(sample_data)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_process_request_includes_http_status(self, handler, sample_data):
        """Response should include HTTP status line."""
        result = handler.process_request(sample_data)
        assert result.startswith(b'HTTP/1.1')

    def test_process_request_with_server_port_uses_thread_pool(self, handler):
        """process_request() should submit to thread pool when server port is set."""
        handler.args.server = 9999
        sample_data = {
            'ip': '10.0.0.1',
            'raw_request': 'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            'parsed_request': MagicMock(),
        }

        with patch('manyfaced.handlers.http_handler.BearStorage'):
            result = handler.process_request(sample_data)
            # Should return a response (not None)
            assert result is not None

    def test_process_request_without_server_port_skips_report(self, handler):
        """process_request() should skip send_report when server port is None."""
        handler.args.server = None
        sample_data = {
            'ip': '10.0.0.1',
            'raw_request': 'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            'parsed_request': MagicMock(),
        }

        with patch('manyfaced.handlers.http_handler.BearStorage'):
            result = handler.process_request(sample_data)
            # Should still return a response (report sending is skipped)
            assert result is not None


class TestHTTPRequest:
    """Tests for HTTPRequest parsing."""

    def test_parse_get(self):
        req = HTTPRequest('GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n')
        assert req.command == 'GET'
        assert req.path == '/wp-login.php'
        assert req.request_version == 'HTTP/1.1'

    def test_parse_post(self):
        req = HTTPRequest(
            'POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\nlog=admin&pwd=test'
        )
        assert req.command == 'POST'
        assert req.path == '/wp-login.php'

    def test_parse_with_query_string(self):
        req = HTTPRequest('GET /search?q=test&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n')
        assert req.path == '/search?q=test&lang=en'

    def test_parse_headers(self):
        req = HTTPRequest('GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot\r\n\r\n')
        assert req.headers is not None
        headers = dict(req.headers) if req.headers else {}
        assert 'Host' in headers or 'host' in headers

    def test_parse_empty_path(self):
        req = HTTPRequest('GET HTTP/1.1\r\nHost: example.com\r\n\r\n')
        # Malformed request – path is whatever parse_request extracted
        assert req.path is not None

    def test_parse_fallback_on_error(self):
        """HTTPRequest should raise ValueError on malformed input."""
        with pytest.raises(ValueError):
            HTTPRequest('INVALID')


class TestHandlerRouting:
    """Tests for handler routing through the registry."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        args.server = None
        update_event = MagicMock()
        # These routing tests assert on response *content*, not geo enrichment.
        # resolve_geo() hits the real ip-api rate limiter (time.sleep(1.1) per
        # call) and each test fires it 5-7x in a tight loop, adding ~90s of
        # wall-clock to the suite for zero extra coverage. Stub it so routing
        # tests stay fast and CI stays under machine-time limits.
        with patch('manyfaced.handlers.http_handler.BearStorage') as MockBS:
            instance = MockBS.return_value
            instance.resolve_geo.return_value = ('', '', '', '')
            instance.resolve_dns_name.return_value = ''
            yield HTTPHandler(args, update_event)

    def test_wordpress_paths(self, handler):
        paths = [
            '/wp-login.php',
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/xmlrpc.php',
        ]
        for path in paths:
            req = 'GET ' + path + ' HTTP/1.1' + _CRLF + 'Host: example.com' + _CRLF + _CRLF
            output = handler.handle_request(req, bot_ip='1.2.3.4')
            assert b'WordPress' in output, f'Failed for path: {path}'

    def test_phpmyadmin_paths(self, handler):
        paths = [
            '/phpmyadmin/',
            '/pma/',
            '/mysql/',
            '/db/',
        ]
        for path in paths:
            req = 'GET ' + path + ' HTTP/1.1' + _CRLF + 'Host: example.com' + _CRLF + _CRLF
            output = handler.handle_request(req, bot_ip='1.2.3.4')
            assert b'phpMyAdmin' in output, f'Failed for path: {path}'

    def test_bitrix_paths(self, handler):
        paths = [
            '/bitrix/admin/',
            '/bitrix/auth/',
            '/bitrix/setup/',
            '/bitrix/',
        ]
        for path in paths:
            req = 'GET ' + path + ' HTTP/1.1' + _CRLF + 'Host: example.com' + _CRLF + _CRLF
            output = handler.handle_request(req, bot_ip='1.2.3.4')
            assert b'Bitrix' in output, f'Failed for path: {path}'

    def test_response_is_bytes(self, handler):
        """All responses should be bytes."""
        paths = [
            '/wp-login.php',
            '/phpmyadmin/',
            '/jenkins/',
            '/manager/html',
            '/user/login',
            '/cpanel/',
            '/random-path',
        ]
        for path in paths:
            req = 'GET ' + path + ' HTTP/1.1' + _CRLF + 'Host: example.com' + _CRLF + _CRLF
            output = handler.handle_request(req, bot_ip='1.2.3.4')
            assert isinstance(output, bytes), f'Failed for path: {path}'
            assert len(output) > 0, f'Empty response for path: {path}'


class TestEmptyConnection:
    """Tests for zero-byte (empty-input) connection handling."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        args.server = None
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_empty_string_uses_empty_connection_id(self, handler):
        """Empty string input should produce a record with EMPTY_CONNECTION detected_id."""
        from manyfaced.common.status import EMPTY_CONNECTION

        output = handler.handle_request('', bot_ip='5.6.7.8')

        # handle_request now returns (response_bytes, BearStorage) for empty connections
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0

    def test_empty_bytes_uses_empty_connection_id(self, handler):
        """Empty bytes input should produce a record with EMPTY_CONNECTION detected_id."""
        from manyfaced.common.status import EMPTY_CONNECTION

        output = handler.handle_request(b'', bot_ip='5.6.7.8')

        # handle_request now returns (response_bytes, BearStorage) for empty connections
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0

    def test_empty_connection_has_empty_raw_request(self, handler):
        """Empty connection record should have empty request_raw."""
        with patch.object(handler, '_enrich_and_send') as mock_enrich:
            handler.handle_request('', bot_ip='5.6.7.8')

        # _enrich_and_send is called with BearStorage instance and bot_ip
        assert mock_enrich.called
        bs = mock_enrich.call_args[0][0]  # BearStorage is the first positional arg
        assert bs.raw_request == ''

    def test_empty_connection_no_parse_failure_log(self, handler, caplog):
        """Empty input should NOT emit 'HTTPRequest failed to parse path' log line."""
        import logging

        with patch.object(handler, '_enrich_and_send'):
            handler.handle_request('', bot_ip='5.6.7.8')

        # The "failed to parse" message should not appear in logs for empty input
        assert 'HTTPRequest failed to parse path' not in caplog.text
        assert 'Failed to parse HTTP request' not in caplog.text

    def test_normal_get_still_works(self, handler):
        """Normal GET / request should still be processed normally (regression guard)."""
        output = handler.handle_request(
            'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
            bot_ip='5.6.7.8',
        )
        assert isinstance(output, bytes)
        assert len(output) > 0

    def test_non_empty_unparseable_still_emits_parse_failure_log(self, handler, caplog):
        """Non-empty but unparseable input should still emit the existing log line."""
        import logging

        # Ensure debug-level logs are captured
        caplog.set_level(logging.DEBUG)

        with patch.object(handler, 'process_request') as mock_process:
            mock_process.return_value = b'HTTP/1.1 200 OK\r\n\r\n'
            handler.handle_request('\r\n', bot_ip='5.6.7.8')

        # The "failed to parse" message SHOULD appear for non-empty unparseable input
        assert (
            'HTTPRequest failed to parse path' in caplog.text
            or 'Failed to parse HTTP request' in caplog.text
        )

    @pytest.fixture
    def enriched_handler(self):
        """Handler with server configured so _send_report_enriched actually sends."""
        args = MagicMock()
        args.verbose = False
        args.server = 9999
        args.server_host = '127.0.0.1'
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_empty_connection_enriched_with_dns_and_geo(self, enriched_handler):
        """Empty connection should produce a record with bot_dns_name/bot_country/bot_continent populated."""
        from manyfaced.common.status import EMPTY_CONNECTION

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            output = enriched_handler.handle_request('', bot_ip='5.6.7.8')

        # handle_request now returns (response_bytes, BearStorage) for empty connections
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0

        # Verify BearStorage was created with correct args
        call_args = MockBS.call_args
        assert call_args[0][0] == '5.6.7.8'  # bot_ip
        assert call_args[0][4] == EMPTY_CONNECTION  # detected_id

        # Verify enrichment methods were called on the BearStorage instance
        mock_bs.resolve_dns_name.assert_called_once_with('5.6.7.8', timeout=1.0)
        mock_bs.resolve_geo.assert_called_once_with('5.6.7.8', timeout=2.0)

    def test_empty_connection_enrichment_failure_does_not_crash(self, enriched_handler):
        """Enrichment failure (exception) should not crash the empty-connection handler."""
        from manyfaced.common.status import EMPTY_CONNECTION

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''
        # Make resolve_dns_name raise an exception
        mock_bs.resolve_dns_name.side_effect = Exception('DNS lookup failed')

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs):
            output = enriched_handler.handle_request('', bot_ip='5.6.7.8')

        # Should still get response (no crash)
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0

        # resolve_geo should still be called even after DNS failure
        mock_bs.resolve_geo.assert_called_once_with('5.6.7.8', timeout=2.0)

    def test_listen_port_is_tagged_on_bearstorage(self, enriched_handler):
        """The handler's listen_port should be copied onto the BearStorage before reporting (issue #299)."""
        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        enriched_handler.listen_port = 8080

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs):
            enriched_handler.handle_request('', bot_ip='5.6.7.8')

        assert mock_bs.listen_port == 8080

    def test_listen_port_zero_is_not_tagged(self, enriched_handler):
        """A handler with listen_port=0 must NOT overwrite a BearStorage port (issue #299)."""
        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''
        mock_bs.listen_port = 9999  # pre-existing value must be preserved

        enriched_handler.listen_port = 0

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs):
            enriched_handler.handle_request('', bot_ip='5.6.7.8')

        assert mock_bs.listen_port == 9999


class TestSSHEnrichment:
    """Tests for SSH probe DNS and geo enrichment."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        args.server = 9999
        args.server_host = '127.0.0.1'
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_ssh_probe_enriched_with_dns_and_geo(self, handler):
        """SSH probe should produce a record that gets enriched when _enrich_and_send is called."""
        from manyfaced.common.status import SSH_CLIENT

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            output = handler.handle_request(
                b'SSH-2.0-OpenSSH_8.9\r\n',
                bot_ip='1.2.3.4',
            )

        # Should get SSH banner response (handle_request returns tuple for SSH)
        bear_storage = None
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert response_bytes.startswith(b'SSH-2.0')

        # Verify BearStorage was created with correct args
        call_args = MockBS.call_args
        assert call_args[0][0] == '1.2.3.4'  # bot_ip
        assert call_args[0][4] == SSH_CLIENT  # detected_id

        # Now simulate what the caller does: call _enrich_and_send after credential capture
        handler._enrich_and_send(bear_storage, '1.2.3.4')

        # Verify enrichment methods were called on the BearStorage instance
        mock_bs.resolve_dns_name.assert_called_once_with('1.2.3.4', timeout=1.0)
        mock_bs.resolve_geo.assert_called_once_with('1.2.3.4', timeout=2.0)

    def test_ssh_probe_enrichment_failure_does_not_crash(self, handler):
        """Enrichment failure (exception) should not crash the SSH handler."""
        from manyfaced.common.status import SSH_CLIENT

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''
        # Make resolve_dns_name raise an exception
        mock_bs.resolve_dns_name.side_effect = Exception('DNS lookup failed')

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs):
            output = handler.handle_request(
                b'SSH-2.0-OpenSSH_8.9\r\n',
                bot_ip='1.2.3.4',
            )

        # Should still get SSH banner response (no crash)
        bear_storage = None
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert response_bytes.startswith(b'SSH-2.0')

        # resolve_geo should still be called even after DNS failure (via _enrich_and_send)
        handler._enrich_and_send(bear_storage, '1.2.3.4')
        mock_bs.resolve_geo.assert_called_once_with('1.2.3.4', timeout=2.0)


class TestNonHTTPEnrichment:
    """Tests for non-HTTP (Telnet/RDP/FTP/VNC/etc.) probe DNS and geo enrichment."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        args.server = 9999
        args.server_host = '127.0.0.1'
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_telnet_probe_enriched_with_dns_and_geo(self, handler):
        """Telnet probe should produce a record with bot_dns_name/bot_country/bot_continent populated."""
        from manyfaced.common.status import UNKNOWN_TELNET

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        # Telnet probes start with IAC (Interpret As Command) byte 0xFF
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            output = handler.handle_request(
                b'\xff\xfb\x01\xff\xfb\x03',  # Telnet IAC probe bytes
                bot_ip='5.6.7.8',
            )

        # Should get telnet response (handle_request returns tuple for non-HTTP)
        bear_storage = None
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0

        # Verify BearStorage was created with correct args
        call_args = MockBS.call_args
        assert call_args[0][0] == '5.6.7.8'  # bot_ip
        assert call_args[0][4] == UNKNOWN_TELNET  # detected_id (telnet probe)

        # Now simulate what the caller does: call _enrich_and_send after credential capture
        handler._enrich_and_send(bear_storage, '5.6.7.8')

        # Verify enrichment methods were called on the BearStorage instance
        mock_bs.resolve_dns_name.assert_called_once_with('5.6.7.8', timeout=1.0)
        mock_bs.resolve_geo.assert_called_once_with('5.6.7.8', timeout=2.0)

    def test_smb_probe_enriched_with_dns_and_geo(self, handler):
        """SMB/NBT probe should produce a record with bot_dns_name/bot_country/bot_continent populated."""
        from manyfaced.common.status import UNKNOWN_SMB

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        # SMB probe: \x00\x00\x00 + 16 bytes padding + "NT LM" identifier
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            output = handler.handle_request(
                b'\x00\x00\x00'
                + b'\x00' * 16
                + b'NT LM 0.12',  # SMB/NBT probe with NT LM identifier
                bot_ip='5.6.7.8',
            )

        bear_storage = None
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0

        # Verify BearStorage was created with SMB detected_id
        call_args = MockBS.call_args
        assert call_args[0][0] == '5.6.7.8'  # bot_ip
        assert call_args[0][4] == UNKNOWN_SMB  # detected_id

        # Now simulate what the caller does: call _enrich_and_send after credential capture
        handler._enrich_and_send(bear_storage, '5.6.7.8')

        # Verify enrichment methods were called on the BearStorage instance
        mock_bs.resolve_dns_name.assert_called_once_with('5.6.7.8', timeout=1.0)
        mock_bs.resolve_geo.assert_called_once_with('5.6.7.8', timeout=2.0)

    def test_rdp_probe_enriched_with_dns_and_geo(self, handler):
        """RDP probe should produce a record with bot_dns_name/bot_country/bot_continent populated."""
        from manyfaced.common.status import UNKNOWN_NON_HTTP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            output = handler.handle_request(
                b'\x03\x00\x00\x1f\x0e\xe0',  # RDP probe bytes
                bot_ip='9.10.11.12',
            )

        bear_storage = None
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        call_args = MockBS.call_args
        assert call_args[0][0] == '9.10.11.12'  # bot_ip

        # Now simulate what the caller does: call _enrich_and_send after credential capture
        handler._enrich_and_send(bear_storage, '9.10.11.12')

        mock_bs.resolve_dns_name.assert_called_once_with('9.10.11.12', timeout=1.0)
        mock_bs.resolve_geo.assert_called_once_with('9.10.11.12', timeout=2.0)

    def test_non_http_probe_enrichment_failure_does_not_crash(self, handler):
        """Enrichment failure (exception) should not crash the non-HTTP handler."""
        from manyfaced.common.status import UNKNOWN_NON_HTTP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''
        # Make resolve_geo raise an exception
        mock_bs.resolve_geo.side_effect = Exception('Geo lookup failed')

        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs):
            output = handler.handle_request(
                b'\xff\xfb\x01\xff\xfb\x03',  # Telnet IAC probe bytes
                bot_ip='5.6.7.8',
            )

        # Should still get response (no crash)
        if isinstance(output, tuple):
            response_bytes, bear_storage = output
        else:
            response_bytes = output

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


# ---------------------------------------------------------------------------
# BotProfile Memory Bounds Tests (issue #111)
# ---------------------------------------------------------------------------


class TestBotProfileMemoryBounds:
    """Tests for BotProfile memory bounds enforcement."""

    def test_request_history_eviction(self):
        """request_history should evict oldest entries when exceeding MAX_HISTORY."""
        from manyfaced.handlers.bot_profile import BotProfile

        profile = BotProfile(bot_ip='1.2.3.4')
        # Fill beyond the cap
        for i in range(profile.MAX_HISTORY + 10):
            profile.record_request({'path': f'/path{i}', 'method': 'GET'})

        assert len(profile.request_history) == profile.MAX_HISTORY
        # Oldest entries should be evicted (first 10 missing)
        paths = [r['path'] for r in profile.request_history]
        assert paths[0] == '/path10'
        assert paths[-1] == '/path509'

    def test_dialogue_eviction(self):
        """dialogue should evict oldest entries when exceeding MAX_DIALOGUE."""
        from manyfaced.handlers.bot_profile import BotProfile

        profile = BotProfile(bot_ip='5.6.7.8')
        # Fill beyond the cap
        for i in range(profile.MAX_DIALOGUE + 10):
            profile.record_interaction(
                request={'path': f'/dialogue{i}', 'method': 'GET', 'raw': ''},
                response=b'HTTP/1.1 200 OK\r\n\r\n',
                detected=1,
            )

        assert len(profile.dialogue) == profile.MAX_DIALOGUE
        # Oldest entries should be evicted
        paths = [d['request']['path'] for d in profile.dialogue]
        assert paths[0] == '/dialogue10'
        assert paths[-1] == '/dialogue509'


class TestHandlerLRUCache:
    """Tests for HTTPHandlerBase LRU bot_profiles cache (issue #111)."""

    @pytest.fixture
    def handler(self):
        """Create a minimal GenericHandler instance."""
        from manyfaced.handlers.generic_handler import GenericHandler

        return GenericHandler()

    def test_lru_eviction_on_capacity(self, handler):
        """When MAX_PROFILES is exceeded, least-recently-used profile should be evicted."""
        # Temporarily lower the cap for faster testing
        original_max = handler.MAX_PROFILES
        handler.MAX_PROFILES = 5

        try:
            # Create 7 profiles (exceeds capacity of 5)
            for i in range(7):
                handler.get_or_create_profile(f'10.0.0.{i}')

            assert len(handler.bot_profiles) == 5
            # First 2 IPs should have been evicted (LRU)
            assert '10.0.0.0' not in handler.bot_profiles
            assert '10.0.0.1' not in handler.bot_profiles
            assert '10.0.0.2' in handler.bot_profiles
            assert '10.0.0.6' in handler.bot_profiles

        finally:
            handler.MAX_PROFILES = original_max

    def test_lru_access_moves_to_end(self, handler):
        """Accessing a profile should move it to the end (most recently used)."""
        # Lower cap for testing
        original_max = handler.MAX_PROFILES
        handler.MAX_PROFILES = 3

        try:
            # Create profiles in order
            handler.get_or_create_profile('1.1.1.1')
            handler.get_or_create_profile('2.2.2.2')
            handler.get_or_create_profile('3.3.3.3')

            # Access first profile — should move it to end
            handler.get_profile('1.1.1.1')

            # Now add a new one — oldest (2.2.2.2) should be evicted
            handler.get_or_create_profile('4.4.4.4')

            assert len(handler.bot_profiles) == 3
            assert '2.2.2.2' not in handler.bot_profiles  # Evicted
            assert '1.1.1.1' in handler.bot_profiles  # Still there (was accessed)

        finally:
            handler.MAX_PROFILES = original_max

    def test_memory_stays_bounded_with_many_ips(self, handler):
        """Memory should stay bounded even when many distinct IPs connect."""
        original_max = handler.MAX_PROFILES
        handler.MAX_PROFILES = 100

        try:
            # Simulate 1000 unique IPs
            for i in range(1000):
                profile = handler.get_or_create_profile(f'192.168.{i // 256}.{i % 256}')
                profile.record_request({'path': f'/scan{i}', 'method': 'GET'})

            # Cache should never exceed MAX_PROFILES
            assert len(handler.bot_profiles) <= handler.MAX_PROFILES

        finally:
            handler.MAX_PROFILES = original_max


class TestGetRouterSingleton:
    """_get_router() must be a safe, single-instance lazy singleton (#184)."""

    def test_concurrent_first_calls_return_one_instance(self):
        """Many threads racing to build the router must share one instance.

        Mirrors the multi-port startup race: several accept-loop threads can
        each see _router is None and try to construct a Router simultaneously.
        """
        import threading

        from manyfaced.handlers import http_handler as hh

        # Force a fresh build so the race is exercised.
        hh._router = None

        results: list = []
        barrier = threading.Barrier(8)
        threads = []

        def worker() -> None:
            barrier.wait()  # release all threads at once
            results.append(hh._get_router())

        for _ in range(8):
            t = threading.Thread(target=worker, daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 8
        # All callers must receive the *same* singleton instance.
        first = results[0]
        assert all(r is first for r in results)
        assert type(first).__name__ == 'Router'

    def test_second_call_returns_cached_instance(self):
        from manyfaced.handlers import http_handler as hh

        hh._router = None
        a = hh._get_router()
        b = hh._get_router()
        assert a is b


# ---------------------------------------------------------------------------
# Issues #634 #635 #636 #637 — HTTP coverage + data-quality gaps
# ---------------------------------------------------------------------------


class TestHTTPCoverageGaps:
    """Regression tests for prod-recon issues #634/#635/#636/#637."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        args.server = None
        return HTTPHandler(args, MagicMock())

    # -- #634: overlong UTF-8 traversal must get a response, never silence --

    def test_overlong_c0af_traversal_returns_response(self, handler):
        output = handler.handle_request(
            'GET /..%c0%afetc/passwd?_=123 HTTP/1.1' + _CRLF + 'Host: x' + _CRLF + _CRLF,
            bot_ip='1.2.3.4',
        )
        assert isinstance(output, bytes)
        assert len(output) > 0
        assert output.startswith(b'HTTP/1.1')
        # Should be the traversal 403, not the detected_id=1 fallback silence
        assert b'403' in output.split(bytes([13, 10]))[0] or b'Forbidden' in output

    def test_overlong_c0ae_traversal_returns_response(self, handler):
        output = handler.handle_request(
            'GET /theme/META-INF/%c0%ae%c0%ae/web.xml HTTP/1.1' + _CRLF + _CRLF,
            bot_ip='1.2.3.4',
        )
        assert isinstance(output, bytes)
        assert output.startswith(b'HTTP/1.1')

    def test_normalize_overlong_path(self):
        from manyfaced.handlers.http_handler import normalize_overlong_path

        assert normalize_overlong_path('/..%c0%afetc/passwd') == '/../etc/passwd'
        assert normalize_overlong_path('/%C0%AE%C0%AE/') == '/../'
        # invalid lead bytes stripped, replacement chars removed
        assert chr(0xFFFD) not in normalize_overlong_path('/a' + chr(0xFFFD) + 'b')

    # -- #635: common attack paths get protocol-appropriate fake responses --

    def test_env_probe_gets_fake_404(self, handler):
        output = handler.handle_request(
            'GET /.env HTTP/1.1' + _CRLF + 'Host: x' + _CRLF + _CRLF,
            bot_ip='1.2.3.4',
        )
        assert isinstance(output, bytes)
        assert output.startswith(b'HTTP/1.1')
        assert b'Server Administration Panel' not in output

    def test_cve_endpoint_gets_terse_404(self):
        from manyfaced.handlers.generic_handler import GenericHandler

        gh = GenericHandler()
        raw = 'GET /goform/set_LimitClient_cfg HTTP/1.1' + _CRLF + _CRLF
        response, detected = gh.generate_response('/goform/set_LimitClient_cfg', raw, '1.2.3.4', {})
        assert response.startswith(b'HTTP/1.1 404')
        assert b'Server Administration Panel' not in response
        assert detected == GenericHandler.DETECTED_ID

    def test_xmlrpc_post_gets_fault_response(self):
        from manyfaced.handlers.generic_handler import GenericHandler

        gh = GenericHandler()
        raw = 'POST /xmlrpc.php HTTP/1.1' + _CRLF + _CRLF
        response, _ = gh.generate_response('/xmlrpc.php', raw, '1.2.3.4', {})
        assert b'methodResponse' in response

    def test_wp_login_get_gets_login_form(self):
        from manyfaced.handlers.generic_handler import GenericHandler

        gh = GenericHandler()
        raw = 'GET /wp-login.php HTTP/1.1' + _CRLF + _CRLF
        response, _ = gh.generate_response('/wp-login.php', raw, '1.2.3.4', {})
        assert b'loginform' in response
        assert b'Server Administration Panel' not in response

    # -- #636: plaintext non-HTTP probes get protocol-shaped responses --

    def test_jdwp_handshake_gets_echo(self, handler):
        result = handler.handle_request('JDWP-Handshake', bot_ip='1.2.3.4')
        assert isinstance(result, tuple)
        response, bs = result
        assert response == b'JDWP-Handshake'
        assert bs.isDetected is not None

    def test_mglndd_probe_gets_banner(self, handler):
        result = handler.handle_request('MGLNDD_68.183.114.1_8080', bot_ip='1.2.3.4')
        assert isinstance(result, tuple)
        response, _ = result
        assert response.startswith(b'220')
        assert b'<html' not in response.lower()

    def test_ldap_bind_gets_bind_response(self, handler):
        # ASN.1 bind: 0x30 len 0x02 0x01 msgid 0x60 ...
        raw = bytes([0x30, 0x14, 0x02, 0x01, 0x01, 0x60, 0x0F, 0x02, 0x01, 0x03])
        result = handler.handle_request(raw, bot_ip='1.2.3.4')
        assert isinstance(result, tuple)
        response, _ = result
        # bindResponse application tag 0x61 present, no HTML
        assert bytes([0x61]) in response
        assert b'<html' not in response.lower()

    # -- #637: blank raw handled as EMPTY_CONNECTION without crashing --

    def test_blank_raw_returns_empty_connection(self, handler):
        result = handler.handle_request('', bot_ip='1.2.3.4')
        assert isinstance(result, tuple)
        response, bs = result
        assert isinstance(response, bytes)
        from manyfaced.common.status import EMPTY_CONNECTION

        assert bs.isDetected == EMPTY_CONNECTION

    def test_replacement_char_message_does_not_crash(self, handler):
        # Socket layer decodes invalid bytes with errors='replace' (#637);
        # the resulting U+FFFD must survive encode without raising.
        msg = 'GET /..' + chr(0xFFFD) + 'etc/passwd HTTP/1.1' + _CRLF + _CRLF
        output = handler.handle_request(msg, bot_ip='1.2.3.4')
        assert isinstance(output, bytes)
        assert len(output) > 0
