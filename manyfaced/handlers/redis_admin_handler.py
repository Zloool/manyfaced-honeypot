"""RedisAdminHandler – handles Redis web-admin specific paths and interactions.

Provides realistic Redis web-admin (redis-commander / redis-insight style)
responses including:
- Redis admin UI landing pages (/redis-commander, /redis-insight)
- A connection form that captures credentials from POST requests
- A JSON config endpoint (/api/config)
- API/prefix routes for common probe paths (/api/, /admin/, /redis/)

Redis web-admin UIs are frequently scanned by bots looking for exposed
management consoles.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import REDIS_ADMIN_HTTP

logger = logging.getLogger(__name__)


class RedisAdminHandler(HTTPHandlerBase):
    """Redis web-admin honeypot handler."""

    domain = 'redis_admin'
    DETECTED_ID = REDIS_ADMIN_HTTP
    VERSION = '1.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Redis web-admin response for the given request."""
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

        # Handle login POST requests (capture credentials).
        if method == 'POST' and ('login' in path_lower or 'auth' in path_lower):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Decode URL-encoded path segments (e.g. %2e -> '.', %2f -> '/').
        decoded = self._decode_path(path)

        # Route to appropriate response.
        if decoded == '/api/config':
            body = self._config_json()
            return self._build_http_response(
                body, 200, 'OK', content_type='application/json; charset=utf-8'
            ), self.DETECTED_ID
        if decoded.startswith('/api/'):
            body = self._api_response(decoded)
            return self._build_http_response(
                body, 200, 'OK', content_type='application/json; charset=utf-8'
            ), self.DETECTED_ID
        if decoded.startswith('/admin/'):
            body = self._admin_page()
        else:
            body = self._main_page(decoded)

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------
    # Response builders
    # ------------------------------------------------------------------

    def _main_page(self, path: str = '') -> str:
        """Redis web-admin landing page (redis-commander / redis-insight style)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Redis Commander</title>
<link rel="stylesheet" type="text/css" href="/redis-commander/static/app.css">
<script type="text/javascript" src="/redis-commander/static/app.js"></script>
</head>
<body class="redis-admin">
<div id="app">
    <div class="login-container">
        <div class="login-logo">
            <img src="/redis-commander/static/redis-logo.svg" alt="Redis" width="64">
            <h1>Redis</h1>
        </div>
        <div class="login-form">
            <h2>Redis Commander</h2>
            <form method="POST" action="/login" name="connectionForm">
                <div class="form-group">
                    <label for="host">Host</label>
                    <input type="text" name="host" id="host" value="127.0.0.1" autocomplete="off">
                </div>
                <div class="form-group">
                    <label for="port">Port</label>
                    <input type="number" name="port" id="port" value="6379">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" name="password" id="password">
                </div>
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" name="username" id="username" autocomplete="off">
                </div>
                <div class="form-actions">
                    <input type="submit" name="Login" value="Connect" class="btn btn-primary">
                </div>
            </form>
            <p class="version">Redis Commander 2.0.0</p>
        </div>
    </div>
</div>
</body>
</html>"""

    def _admin_page(self) -> str:
        """Redis admin console page (when /admin/ is requested)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redis Admin</title>
</head>
<body>
<div class="redis-admin">
    <h1>Redis</h1>
    <h2>Administration Console</h2>
    <form method="POST" action="/admin/login">
        <label>Username <input type="text" name="username"></label>
        <label>Password <input type="password" name="password"></label>
        <input type="submit" value="Login">
    </form>
</div>
</body>
</html>"""

    def _config_json(self) -> str:
        """Return a realistic Redis admin config endpoint payload (JSON)."""
        config = {
            'version': self.VERSION,
            'service': 'redis-commander',
            'redis': {
                'host': '127.0.0.1',
                'port': 6379,
                'password': '',
                'db': 0,
            },
            'server': {
                'address': '10.0.0.15',
                'port': 8081,
                'host': 'redis',
            },
            'ui': {
                'name': 'Redis Commander',
                'theme': 'dark',
            },
        }
        return json.dumps(config, indent=2)

    def _api_response(self, path: str) -> str:
        """Return a generic JSON API response for /api/* probe paths."""
        return json.dumps(
            {
                'service': 'redis-admin',
                'path': path,
                'status': 'ok',
            }
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = (
            '<html><body><h3>Authorization Error</h3>'
            '<p>Invalid credentials. Please try again.</p></body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Decode URL-encoded path segments (e.g. %2e -> '.', %2f -> '/')."""
        try:
            decoded = urllib.parse.unquote(path)
        except (ValueError, UnicodeDecodeError):
            decoded = path
        return decoded

    def _extract_method(self, raw_request: str) -> str:
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
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: redis-commander/{self.VERSION}\r\n'
            f'X-Powered-By: Node.js\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'RedisAdminHandler(domain={self.domain!r})'
