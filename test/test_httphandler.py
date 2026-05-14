"""Tests for HTTPRequest (manyfaced.common.httphandler)."""

import os
import sys
from unittest.mock import MagicMock


# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip modules before any module that uses it is imported
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules['geoip'] = geoip_mock
sys.modules['geoip.geolite2'] = geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()

from manyfaced.common.httphandler import HTTPRequest


class TestHTTPRequestParse:
    """Tests for HTTPRequest parsing of simple GET requests."""

    def test_parse_simple_get(self):
        """Parse a simple GET request and verify command, path, request_version."""
        request_text = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'GET'
        assert req.path == '/index.html'
        assert req.request_version == 'HTTP/1.1'

    def test_parse_get_without_path(self):
        """Parse a GET request with root path."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'GET'
        assert req.path == '/'
        assert req.request_version == 'HTTP/1.1'

    def test_parse_get_with_query_string(self):
        """Parse a GET request with query string."""
        request_text = 'GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'GET'
        assert req.path == '/search?q=test&page=1'
        assert req.request_version == 'HTTP/1.1'

    def test_parse_http_1_0(self):
        """Parse an HTTP/1.0 request."""
        request_text = 'GET / HTTP/1.0\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.request_version == 'HTTP/1.0'

    def test_parse_raw_bytes(self):
        """HTTPRequest should accept raw bytes input."""
        request_text = b'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'GET'
        assert req.path == '/test'

    def test_parse_string_input(self):
        """HTTPRequest should accept string input and encode to iso-8859-1."""
        request_text = 'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'GET'
        assert req.path == '/test'

    def test_parse_preserves_raw_request(self):
        """The raw request text should be accessible via data attribute."""
        request_text = 'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.data == request_text.encode('iso-8859-1')

    def test_parse_error_attributes_initialized(self):
        """error_code and error_message should be initialized to None."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.error_code is None
        assert req.error_message is None


class TestHTTPRequestParseHeaders:
    """Tests for HTTPRequest parsing of requests with headers."""

    def test_parse_single_header(self):
        """Parse a request with a single header."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert 'host' in req.headers
        assert req.headers['host'] == 'example.com'

    def test_parse_multiple_headers(self):
        """Parse a request with multiple headers."""
        request_text = (
            'GET / HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'User-Agent: Mozilla/5.0\r\n'
            'Accept: text/html\r\n'
            'Connection: keep-alive\r\n'
            '\r\n'
        )
        req = HTTPRequest(request_text)

        assert req.headers['host'] == 'example.com'
        assert req.headers['user-agent'] == 'Mozilla/5.0'
        assert req.headers['accept'] == 'text/html'
        assert req.headers['connection'] == 'keep-alive'

    def test_parse_case_insensitive_headers(self):
        """Headers should be lowercased in the dict."""
        request_text = 'GET / HTTP/1.1\r\nX-Custom-Header: value\r\n\r\n'
        req = HTTPRequest(request_text)

        assert 'x-custom-header' in req.headers
        assert req.headers['x-custom-header'] == 'value'

    def test_parse_empty_body(self):
        """Request with headers but no body should parse correctly."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert len(req.headers) >= 1
        assert req.headers['host'] == 'example.com'

    def test_parse_headers_dict_type(self):
        """Headers should be a dict-like object."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert hasattr(req.headers, 'keys')
        assert hasattr(req.headers, '__getitem__')
        assert 'host' in req.headers


class TestHTTPRequestParsePOST:
    """Tests for HTTPRequest parsing of POST requests."""

    def test_parse_simple_post(self):
        """Parse a simple POST request."""
        request_text = 'POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'POST'
        assert req.path == '/login'
        assert req.request_version == 'HTTP/1.1'

    def test_parse_post_with_content_length(self):
        """Parse a POST request with Content-Length header."""
        request_text = (
            'POST /api/data HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            'Content-Length: 27\r\n'
            '\r\n'
        )
        req = HTTPRequest(request_text)

        assert req.command == 'POST'
        assert req.path == '/api/data'
        assert req.headers['content-type'] == 'application/x-www-form-urlencoded'
        assert req.headers['content-length'] == '27'

    def test_parse_put_request(self):
        """Parse a PUT request."""
        request_text = 'PUT /resource/1 HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'PUT'
        assert req.path == '/resource/1'

    def test_parse_delete_request(self):
        """Parse a DELETE request."""
        request_text = 'DELETE /resource/1 HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'DELETE'
        assert req.path == '/resource/1'

    def test_parse_head_request(self):
        """Parse a HEAD request."""
        request_text = 'HEAD /health HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        assert req.command == 'HEAD'
        assert req.path == '/health'


class TestHTTPRequestSendError:
    """Tests for HTTPRequest.send_error()."""

    def test_send_error_sets_code(self):
        """send_error() should set error_code."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        req.send_error(404, 'Not Found')

        assert req.error_code == 404

    def test_send_error_sets_message(self):
        """send_error() should set error_message."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        req.send_error(404, 'Not Found')

        assert req.error_message == 'Not Found'

    def test_send_error_overwrites_previous(self):
        """send_error() should overwrite previously set values."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        req.send_error(500, 'Internal Server Error')
        req.send_error(404, 'Not Found')

        assert req.error_code == 404
        assert req.error_message == 'Not Found'

    def test_send_error_with_various_codes(self):
        """send_error() should work with various HTTP status codes."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        codes_and_messages = [
            (400, 'Bad Request'),
            (401, 'Unauthorized'),
            (403, 'Forbidden'),
            (500, 'Internal Server Error'),
            (502, 'Bad Gateway'),
            (503, 'Service Unavailable'),
        ]

        for code, message in codes_and_messages:
            req.send_error(code, message)
            assert req.error_code == code
            assert req.error_message == message

    def test_send_error_after_parse(self):
        """send_error() should work after a successful parse."""
        request_text = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        req = HTTPRequest(request_text)

        req.send_error(500, 'Error')

        assert req.error_code == 500
        assert req.error_message == 'Error'
