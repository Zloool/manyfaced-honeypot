"""NginxHandler – emulates an Nginx web server face (issue #294).

Provides realistic Nginx responses including:
- The default Nginx welcome page (/) and index.html
- A stub ``nginx_status`` / ``stub_status`` / ``status`` page
- A stub Apache-style ``server-status`` page
- Generic 404-style stubs for ``/api/`` and ``/nginx/`` probe paths
  (including encoded ``%2e`` -> ``.`` and ``%2f`` -> ``/`` traversal paths)
- Captures login credentials from POST requests and returns a fake error

Nginx is one of the most heavily probed services on the internet, so a
realistic welcome / status page catches a large fraction of automated scans.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import urllib.parse

from manyfaced.handlers.base_handler import HTTPHandlerBase

# Issue #294 specifies the constant as NGINX_HTTP with value 1029. The shared
# status.py already defines NGINX_PROBE_HTTP = 1029 (the canonical Nginx face
# ID). We alias it here rather than editing the shared status.py.
from manyfaced.common.status import NGINX_PROBE_HTTP as NGINX_HTTP

logger = logging.getLogger(__name__)


class NginxHandler(HTTPHandlerBase):
    """Nginx web-server honeypot handler."""

    domain = 'nginx'
    DETECTED_ID = NGINX_HTTP
    VERSION = '1.25.3'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an Nginx response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {
            'path': path,
            'method': self._extract_method(raw_request),
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        path_lower = path.lower()

        # Handle login POST requests (capture credentials, fake failure)
        if method == 'POST' and any(kw in path_lower for kw in ('login', 'auth')):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Decode URL-encoded traversal probes (e.g. /nginx/%2eenv -> /nginx/.env)
        decoded = self._decode_path(path)

        # Route to the appropriate response body
        if decoded in ('/', '/index.html'):
            body = self._welcome_page()
        elif decoded in ('/nginx_status', '/stub_status', '/status'):
            body = self._status_page()
        elif decoded == '/server-status':
            body = self._server_status_page()
        elif decoded.startswith('/api/'):
            body = self._api_page()
        elif decoded.startswith('/nginx/'):
            body = self._server_probe_page(decoded)
        else:
            body = self._welcome_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------
    # Response bodies
    # ------------------------------------------------------------------

    def _welcome_page(self) -> str:
        """The default Nginx welcome page."""
        return (
            '<!DOCTYPE html>\n'
            '<html lang="en">\n'
            '<head>\n'
            '<meta charset="utf-8">\n'
            '<title>Welcome to nginx!</title>\n'
            '<style>\n'
            'html { color-scheme: light dark; }\n'
            'body { width: 35em; margin: 0 auto;\n'
            'font-family: Tahoma, Verdana, Arial, sans-serif; }\n'
            '</style>\n'
            '</head>\n'
            '<body>\n'
            '<h1>Welcome to nginx!</h1>\n'
            '<p>If you see this page, the nginx web server is successfully '
            'installed and\nworking. Further configuration is required.</p>\n'
            '<p>For online documentation and support please refer to\n'
            '<a href="http://nginx.org/">nginx.org</a>.<br/>\n'
            'Commercial support is available at\n'
            '<a href="http://nginx.com/">nginx.com</a>.</p>\n'
            '<p><em>Thank you for using nginx.</em></p>\n'
            '</body>\n'
            '</html>\n'
        )

    def _status_page(self) -> str:
        """Stub nginx ``stub_status`` style page."""
        return (
            'Active connections: 1 \n'
            'server accepts handled requests\n'
            ' 12 12 34 \n'
            'Reading: 0 Writing: 1 Waiting: 0 \n'
        )

    def _server_status_page(self) -> str:
        """Stub Apache-style ``server-status`` page."""
        return (
            '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n'
            '<html><head><title>Apache Status</title></head>\n'
            '<body>\n'
            '<h1>Apache Server Status for localhost</h1>\n'
            '<dl><dt>Current Time: '
            + datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')
            + ' GMT</dt>\n'
            '<dt>Server Version: nginx/' + self.VERSION + '</dt>\n'
            '<dt>Server MPM: event</dt>\n'
            '<dt>Server Built: ' + datetime.now(timezone.utc).strftime('%b %d %Y') + '</dt></dl>\n'
            '</body></html>\n'
        )

    def _api_page(self) -> str:
        """Generic stub for ``/api/`` probe paths."""
        return (
            '<!DOCTYPE html><html><head><title>404 Not Found</title></head>\n'
            '<body><center><h1>404 Not Found</h1></center>\n'
            '<hr><center>nginx/' + self.VERSION + '</center>\n'
            '</body></html>\n'
        )

    def _server_probe_page(self, decoded_path: str) -> str:
        """Stub for ``/nginx/`` probe paths (e.g. ``/nginx/%2eenv``)."""
        return (
            '<!DOCTYPE html><html><head><title>404 Not Found</title></head>\n'
            '<body><center><h1>404 Not Found</h1></center>\n'
            '<center>nginx/' + self.VERSION + '</center>\n'
            '</body></html>\n'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response – encourages further probing."""
        body = (
            '<!DOCTYPE html><html><head><title>Authorization Error</title></head>\n'
            '<body><h3>Authorization Error</h3>\n'
            '<p>Invalid login or password. Please try again.</p>\n'
            '<p><a href="/">Return to home</a></p>\n'
            '</body></html>\n'
        )
        return self._build_http_response(body, 200, 'OK')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_path(path: str) -> str:
        """Decode ``%2e`` -> ``.`` and ``%2f`` -> ``/`` traversal probes."""
        try:
            decoded = urllib.parse.unquote(path)
        except (ValueError, UnicodeError):
            decoded = path
        return decoded.replace('%2e', '.').replace('%2f', '/')

    @staticmethod
    def _extract_method(raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        status_code: int = 200,
        status_text: str = 'OK',
        content_type: str = 'text/html; charset=utf-8',
    ) -> bytes:
        """Build a complete HTTP response (iso-8859-1 encoded)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: nginx/{self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'NginxHandler(domain={self.domain!r})'
