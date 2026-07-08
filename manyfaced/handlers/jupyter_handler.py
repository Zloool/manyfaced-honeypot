"""JupyterHandler – emulates a Jupyter Notebook server (issue #288).

Provides realistic Jupyter Notebook server responses including:
- Jupyter login page (/jupyter, /login, /lab)
- Notebook tree / file listing (JSON via /api/contents)
- Notebook sessions API (/api/sessions)
- A JSON error body for failed login attempts

Jupyter Notebook is a popular interactive computing environment frequently
scanned by bots looking for unauthenticated notebook servers to hijack.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import logging
from urllib.parse import unquote

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import JUPYTER_HTTP

logger = logging.getLogger(__name__)


class JupyterHandler(HTTPHandlerBase):
    """Jupyter Notebook honeypot handler."""

    domain = 'jupyter'
    DETECTED_ID = JUPYTER_HTTP
    VERSION = '6.5.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Jupyter response for the given request."""
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
        # Decode percent-encoded probe paths (%2e -> '.', %2f -> '/').
        decoded_path = self._decode_path(path)
        path_lower = decoded_path.lower()

        # Handle login POST requests.
        if method == 'POST' and ('login' in path_lower or 'auth' in path_lower):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # API endpoints return JSON.
        if path_lower.startswith('/api/contents'):
            body = self._api_contents(path_lower)
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

        if path_lower.startswith('/api/sessions'):
            body = self._api_sessions()
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

        if path_lower.startswith('/api'):
            body = self._api_root()
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

        # Login page for the main entry points.
        if path_lower in ('/jupyter', '/login', '/lab', '/tree', '/notebook'):
            body = self._login_page()
        elif path_lower.startswith('/jupyter/') or path_lower.startswith('/notebook'):
            body = self._login_page()
        else:
            body = self._login_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # -- Response builders --------------------------------------------------

    def _login_page(self) -> str:
        """Jupyter Notebook login page with logo and login form."""
        return """<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Jupyter Notebook</title>
<link rel="stylesheet" href="/static/style/style.min.css">
<link rel="stylesheet" href="/static/auth/css/override.css">
</head>
<body class="login-page">
<div id="login_container" class="container">
    <div class="row">
        <div class="col-sm-12">
            <div id="login-logo" class="logo">
                <img src="/static/base/images/logo.png" alt="Jupyter Logo" width="128">
            </div>
            <h1>Jupyter</h1>
            <p class="login-subtitle">Jupyter Notebook</p>
            <form action="/login" method="post" class="login_form">
                <input type="hidden" name="_xsrf" value="2|abc123|def456|ghi789">
                <div class="form-group">
                    <label for="username_input">Username:</label>
                    <input type="text" name="username" id="username_input"
                           class="form-control" autocomplete="off" autofocus>
                </div>
                <div class="form-group">
                    <label for="password_input">Password:</label>
                    <input type="password" name="password" id="password_input"
                           class="form-control">
                </div>
                <div class="form-group login-submit">
                    <input type="submit" value="Sign in" class="btn btn-jupyter">
                </div>
            </form>
            <p class="login-footer">
                Powered by Jupyter Notebook 6.5.0
            </p>
        </div>
    </div>
</div>
<script src="/static/auth/js/main.min.js"></script>
</body>
</html>"""

    def _api_contents(self, path_lower: str) -> str:
        """Jupyter /api/contents JSON listing of the notebook tree."""
        if path_lower.rstrip('/') in ('/api/contents', '/api/contents/'):
            contents = {
                'content': [
                    {
                        'name': 'welcome.ipynb',
                        'path': 'welcome.ipynb',
                        'type': 'notebook',
                        'last_modified': '2024-01-15T10:00:00Z',
                        'created': '2024-01-15T10:00:00Z',
                        'writable': True,
                        'mimetype': None,
                        'size': 2048,
                    },
                    {
                        'name': 'work',
                        'path': 'work',
                        'type': 'directory',
                        'last_modified': '2024-01-15T10:00:00Z',
                        'created': '2024-01-15T10:00:00Z',
                        'writable': True,
                        'mimetype': None,
                        'size': 0,
                    },
                ],
                'name': '',
                'path': '',
                'type': 'directory',
                'writable': True,
                'last_modified': '2024-01-15T10:00:00Z',
                'created': '2024-01-15T10:00:00Z',
                'mimetype': None,
                'format': 'json',
            }
        else:
            # A specific file path -> serve a minimal notebook.
            contents = {
                'name': 'notebook.ipynb',
                'path': 'notebook.ipynb',
                'type': 'notebook',
                'writable': True,
                'last_modified': '2024-01-15T10:00:00Z',
                'created': '2024-01-15T10:00:00Z',
                'mimetype': None,
                'format': 'json',
                'content': {
                    'cells': [],
                    'metadata': {},
                    'nbformat': 4,
                    'nbformat_minor': 5,
                },
            }
        return json.dumps(contents)

    def _api_sessions(self) -> str:
        """Jupyter /api/sessions JSON (list of active kernel sessions)."""
        return json.dumps([])

    def _api_root(self) -> str:
        """Jupyter /api root metadata."""
        return json.dumps(
            {
                'version': self.VERSION,
                'notebook_version': [6, 5, 0],
            }
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response – returns a JSON error to encourage retries."""
        body = json.dumps(
            {
                'message': 'Invalid credentials',
                'error': 'Error: Invalid username or password.',
            }
        )
        return self._build_http_response(body, 200, 'OK', 'application/json')

    # -- Helpers ------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Decode percent-encoded probe paths (%2e -> '.', %2f -> '/')."""
        try:
            return unquote(path)
        except Exception:
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
        body_bytes = body.encode('utf-8')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: TornadoServer/6.1\r\n'
            f'X-JupyterHub-Version: {self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        ).encode('iso-8859-1') + body_bytes
        return response

    def __repr__(self) -> str:
        return f'JupyterHandler(domain={self.domain!r})'
