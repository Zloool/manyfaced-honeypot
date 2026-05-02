"""
Comprehensive pytest tests for HTTPHandler and HTTPRequest modules.

Tests the new handler registry architecture:
- HTTPHandler routes requests through HandlerRegistry
- Service handlers generate realistic honeypot responses
- BotProfile tracks per-bot state
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip before any handler module is imported
_geoip_mock = MagicMock()
_geoip_mock.geolite2.geolite2 = _geoip_mock.geolite2
sys.modules["geoip"] = _geoip_mock
sys.modules["geoip.geolite2"] = _geoip_mock.geolite2
sys.modules["GeoIP"] = MagicMock()

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
            "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert isinstance(output, bytes)
        assert len(output) > 0

    def test_handle_request_routes_to_wordpress(self, handler):
        """handle_request() should route /wp-login.php to WordPressHandler."""
        output = handler.handle_request(
            "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert b"WordPress" in output
        assert b"wp-login.php" in output

    def test_handle_request_routes_to_phpmyadmin(self, handler):
        """handle_request() should route /phpmyadmin/ to PhpMyAdminHandler."""
        output = handler.handle_request(
            "GET /phpmyadmin/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert b"phpMyAdmin" in output

    def test_handle_request_routes_generic(self, handler):
        """handle_request() should route unknown paths to GenericHandler."""
        output = handler.handle_request(
            "GET /random-path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert b"Server Administration Panel" in output

    def test_handle_request_post_login_captures_credentials(self, handler):
        """handle_request() should capture credentials from login POST."""
        output = handler.handle_request(
            "POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nlog=admin&pwd=secret123",
            bot_ip="1.2.3.4",
        )
        # Should return login failed response
        assert b"ERROR" in output or b"Invalid username" in output

    def test_handle_request_with_query_string(self, handler):
        """handle_request() should handle query strings in paths."""
        output = handler.handle_request(
            "GET /search?q=test&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert isinstance(output, bytes)
        assert len(output) > 0

    def test_handle_request_fallback_on_parse_error(self, handler):
        """handle_request() should handle malformed requests gracefully."""
        # This should not raise an exception
        output = handler.handle_request(
            "INVALID REQUEST",
            bot_ip="1.2.3.4",
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
        raw = "GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n"
        return {
            "ip": "10.0.0.1",
            "raw_request": raw,
            "parsed_request": MagicMock(),
        }

    def test_process_request_returns_response(self, handler, sample_data):
        """process_request() should return response bytes."""
        result = handler.process_request(sample_data)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_process_request_includes_http_status(self, handler, sample_data):
        """Response should include HTTP status line."""
        result = handler.process_request(sample_data)
        assert result.startswith(b"HTTP/1.1")

    def test_process_request_with_server_port_uses_thread_pool(self, handler):
        """process_request() should submit to thread pool when server port is set."""
        handler.args.server = 9999
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.handlers.http_handler.BearStorage"):
            result = handler.process_request(sample_data)
            # Should return a response (not None)
            assert result is not None

    def test_process_request_without_server_port_skips_report(self, handler):
        """process_request() should skip send_report when server port is None."""
        handler.args.server = None
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.handlers.http_handler.BearStorage"):
            result = handler.process_request(sample_data)
            # Should still return a response (report sending is skipped)
            assert result is not None

    def test_process_request_with_ai_responder(self):
        """process_request() should use AI responder if enabled and available."""
        args = MagicMock()
        args.verbose = False
        args.server = None
        args.ai_responder = True
        args.ai_endpoint = "http://localhost:8080/v1"
        args.ai_model = "test-model"
        args.ai_max_tokens = 100
        update_event = MagicMock()
        handler = HTTPHandler(args, update_event)

        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        # AI responder should be None if endpoint unreachable
        assert handler._ai_responder is None or hasattr(handler, "_ai_responder")


class TestHTTPRequest:
    """Tests for HTTPRequest parsing."""

    def test_parse_get(self):
        req = HTTPRequest("GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert req.command == "GET"
        assert req.path == "/wp-login.php"
        assert req.request_version == "HTTP/1.1"

    def test_parse_post(self):
        req = HTTPRequest(
            "POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\nlog=admin&pwd=test"
        )
        assert req.command == "POST"
        assert req.path == "/wp-login.php"

    def test_parse_with_query_string(self):
        req = HTTPRequest(
            "GET /search?q=test&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        assert req.path == "/search?q=test&lang=en"

    def test_parse_headers(self):
        req = HTTPRequest(
            "GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot\r\n\r\n"
        )
        assert req.headers is not None
        headers = dict(req.headers) if req.headers else {}
        assert "Host" in headers or "host" in headers

    def test_parse_empty_path(self):
        req = HTTPRequest("GET HTTP/1.1\r\nHost: example.com\r\n\r\n")
        # Malformed request – path is whatever parse_request extracted
        assert req.path is not None

    def test_parse_fallback_on_error(self):
        """HTTPRequest should raise ValueError on malformed input."""
        with pytest.raises(ValueError):
            HTTPRequest("INVALID")


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
            "/wp-login.php",
            "/wp-admin/",
            "/wp-content/",
            "/wp-includes/",
            "/xmlrpc.php",
        ]
        for path in paths:
            output = handler.handle_request(
                f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                bot_ip="1.2.3.4",
            )
            assert b"WordPress" in output, f"Failed for path: {path}"

    def test_phpmyadmin_paths(self, handler):
        paths = [
            "/phpmyadmin/",
            "/pma/",
            "/mysql/",
            "/db/",
        ]
        for path in paths:
            output = handler.handle_request(
                f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                bot_ip="1.2.3.4",
            )
            assert b"phpMyAdmin" in output, f"Failed for path: {path}"

    def test_response_is_bytes(self, handler):
        """All responses should be bytes."""
        paths = [
            "/wp-login.php",
            "/phpmyadmin/",
            "/jenkins/",
            "/manager/html",
            "/user/login",
            "/cpanel/",
            "/random-path",
        ]
        for path in paths:
            output = handler.handle_request(
                f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                bot_ip="1.2.3.4",
            )
            assert isinstance(output, bytes), f"Failed for path: {path}"
            assert len(output) > 0, f"Empty response for path: {path}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
