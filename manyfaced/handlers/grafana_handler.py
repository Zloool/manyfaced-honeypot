"""GrafanaHandler – impersonates the Grafana web UI and REST API.

Provides realistic Grafana (observability platform) responses including:
- Grafana login page (/grafana, /login, /grafana/login)
- Grafana REST API responses (/api/org, /api/dashboards/home,
  /api/frontend/settings, /api/search, datasource proxy)
- Captures login credentials from POST requests
- Decodes URL-encoded probe paths (%2e -> '.', %2f -> '/')

Grafana is a popular open-source analytics & monitoring platform widely
targeted by bots probing for exposed dashboards and API access.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import urllib.parse

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import GRAFANA_HTTP

logger = logging.getLogger(__name__)


class GrafanaHandler(HTTPHandlerBase):
    """Grafana honeypot handler."""

    domain = 'grafana'
    DETECTED_ID = GRAFANA_HTTP
    VERSION = '11.0.0'

    # --- canonical API endpoints we emulate (realistic probe paths) ---------
    _ORG_JSON = {'datasources': [], 'orgId': 1}
    _DASHBOARDS_HOME_JSON = {
        'title': 'Home',
        'uid': 'home',
        'uri': 'db/home',
        'url': '/d/home/home',
        'type': 'dash-db',
        'tags': [],
        'isStarred': False,
        'schemaVersion': 39,
    }
    _FRONTEND_SETTINGS_JSON = {
        'plugins': {},
        'datasources': {},
        'panels': {},
        'appSubUrl': '',
        'buildInfo': {
            'version': VERSION,
            'commit': 'unknown',
            'env': 'production',
            'edition': 'oss',
            'latestVersion': VERSION,
            'hasUpdate': False,
            'versionString': f'{VERSION} (commit: unknown, branch: HEAD)',
        },
        'licenseInfo': {
            'expiry': 0,
            'token': '',
            'level': 'oss',
            'licensed': False,
        },
        'featureToggles': {},
        'anonEnabled': False,
        'allowOrgCreate': False,
        'defaultDatasource': '',
    }
    _SEARCH_JSON = []

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Grafana response for the given request."""
        # Decode URL-encoded probe paths (e.g. /api/%2e%2e -> /api/..).
        path = self._normalize_path(path)

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

        # Handle login POST requests — capture credentials, return failure.
        if method == 'POST' and 'login' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to the appropriate response.
        if path_lower == '/api/org':
            body = json.dumps(self._ORG_JSON)
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID
        if path_lower.startswith('/api/'):
            body = self._api_response(path_lower)
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID
        if path_lower in ('/grafana', '/login', '/grafana/login') or path_lower.startswith('/grafana/'):
            body = self._login_page()
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # Default: serve the Grafana login page.
        body = self._login_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # --- response builders --------------------------------------------------

    def _api_response(self, path_lower: str) -> str:
        """Return a realistic JSON body for a Grafana API path."""
        if path_lower == '/api/dashboards/home':
            return json.dumps(self._DASHBOARDS_HOME_JSON)
        if path_lower == '/api/frontend/settings':
            return json.dumps(self._FRONTEND_SETTINGS_JSON)
        if path_lower == '/api/search':
            return json.dumps(self._SEARCH_JSON)
        if path_lower == '/api/datasources':
            return json.dumps([])
        if path_lower == '/api/health':
            return json.dumps({'database': 'ok', 'commit': 'unknown', 'version': self.VERSION})
        # Path-traversal / unknown API probes (e.g. /api/%2e%2e -> /api/..).
        return json.dumps({'message': 'Not Found', 'status': 'not-found'})

    def _login_page(self) -> str:
        """Grafana login HTML page (logo, title, login form)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Grafana</title>
<link rel="icon" href="/public/img/fav32.png">
<style>
  html, body { height: 100%; margin: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #111217; color: #d8d9da; display: flex; align-items: center; justify-content: center;
  }
  .login-box { width: 340px; background: #181b1f; padding: 32px; border-radius: 4px; box-shadow: 0 0 24px rgba(0,0,0,0.4); }
  .login-logo { text-align: center; margin-bottom: 24px; }
  .login-logo h1 { font-size: 28px; font-weight: 500; letter-spacing: -0.5px; margin: 8px 0 0; color: #f2f3f5; }
  .login-logo .glyph { display: inline-block; width: 48px; height: 48px; border-radius: 50%; background: #f05a28; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 13px; margin-bottom: 6px; color: #a9a9ac; }
  .form-group input { width: 100%; box-sizing: border-box; padding: 9px 10px; background: #0e0f12; border: 1px solid #2c3036; border-radius: 3px; color: #d8d9da; font-size: 14px; }
  .form-group input:focus { outline: none; border-color: #f05a28; }
  .btn-login { width: 100%; padding: 10px; background: #f05a28; border: none; border-radius: 3px; color: #fff; font-size: 14px; font-weight: 500; cursor: pointer; }
  .btn-login:hover { background: #d94e20; }
  .login-footer { margin-top: 16px; text-align: center; font-size: 12px; color: #6e7177; }
</style>
</head>
<body>
  <div class="login-box">
    <div class="login-logo">
      <span class="glyph"></span>
      <h1>Grafana</h1>
    </div>
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="user">User</label>
        <input type="text" id="user" name="user" autocomplete="off" placeholder="admin">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="off">
      </div>
      <button type="submit" class="btn-login">Log in</button>
    </form>
    <div class="login-footer">
      <p>Grafana 11.0.0 &middot; Open source observability platform</p>
    </div>
  </div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Login failed response — encourages further probing."""
        body = (
            '<!DOCTYPE html><html><head><title>Grafana</title></head><body>'
            '<div class="login-error"><h3>Error</h3>'
            '<p>Invalid username or password.</p></div>'
            '</body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    # --- helpers ------------------------------------------------------------

    def _normalize_path(self, path: str) -> str:
        """Decode URL-encoded probe paths (%2e -> '.', %2f -> '/')."""
        try:
            return urllib.parse.unquote(path)
        except (ValueError, UnicodeDecodeError):
            return path

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
            f'Server: Grafana/{self.VERSION}\r\n'
            f'Cache-Control: no-cache\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'X-Frame-Options: deny\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'GrafanaHandler(domain={self.domain!r})'
