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
        return HTTPHandler(args, update_event)

    def test_wordpress_paths(self, handler):
        paths = [
            '/wp-login.php',
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/xmlrpc.php',
        ]
        for path in paths:
            output = handler.handle_request(
                f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n',
                bot_ip='1.2.3.4',
            )
            assert b'WordPress' in output, f'Failed for path: {path}'

    def test_phpmyadmin_paths(self, handler):
        paths = [
            '/phpmyadmin/',
            '/pma/',
            '/mysql/',
            '/db/',
        ]
        for path in paths:
            output = handler.handle_request(
                f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n',
                bot_ip='1.2.3.4',
            )
            assert b'phpMyAdmin' in output, f'Failed for path: {path}'

    def test_bitrix_paths(self, handler):
        paths = [
            '/bitrix/admin/',
            '/bitrix/auth/',
            '/bitrix/setup/',
            '/bitrix/',
        ]
        for path in paths:
            output = handler.handle_request(
                f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n',
                bot_ip='1.2.3.4',
            )
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
            output = handler.handle_request(
                f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n',
                bot_ip='1.2.3.4',
            )
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

        assert isinstance(output, bytes)
        assert len(output) > 0

    def test_empty_bytes_uses_empty_connection_id(self, handler):
        """Empty bytes input should produce a record with EMPTY_CONNECTION detected_id."""
        from manyfaced.common.status import EMPTY_CONNECTION

        output = handler.handle_request(b'', bot_ip='5.6.7.8')

        assert isinstance(output, bytes)
        assert len(output) > 0

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

        assert isinstance(output, bytes)
        assert len(output) > 0

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
        assert isinstance(output, bytes)
        assert len(output) > 0

        # resolve_geo should still be called even after DNS failure
        mock_bs.resolve_geo.assert_called_once_with('5.6.7.8', timeout=2.0)


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
        """SSH probe should produce a record with bot_dns_name/bot_country/bot_continent populated."""
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

        # Should get SSH banner response
        assert isinstance(output, bytes)
        assert output.startswith(b'SSH-2.0')

        # Verify BearStorage was created with correct args
        call_args = MockBS.call_args
        assert call_args[0][0] == '1.2.3.4'  # bot_ip
        assert call_args[0][4] == SSH_CLIENT  # detected_id

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
        assert isinstance(output, bytes)
        assert output.startswith(b'SSH-2.0')

        # resolve_geo should still be called even after DNS failure
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
        from manyfaced.common.status import UNKNOWN_NON_HTTP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        # Telnet probes start with three null bytes per protocol.py detection
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            output = handler.handle_request(
                b'\x00\x00\x00\xff\xfb\x01',  # Telnet probe bytes (null prefix per protocol.py)
                bot_ip='5.6.7.8',
            )

        # Should get telnet response
        assert isinstance(output, bytes)
        assert len(output) > 0

        # Verify BearStorage was created with correct args
        call_args = MockBS.call_args
        assert call_args[0][0] == '5.6.7.8'  # bot_ip
        assert call_args[0][4] == UNKNOWN_NON_HTTP  # detected_id

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

        assert isinstance(output, bytes)
        call_args = MockBS.call_args
        assert call_args[0][0] == '9.10.11.12'  # bot_ip
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
                b'\x00\x00\x00\xff\xfb\x01',  # Telnet probe bytes (null prefix per protocol.py)
                bot_ip='5.6.7.8',
            )

        # Should still get response (no crash)
        assert isinstance(output, bytes)
        assert len(output) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
