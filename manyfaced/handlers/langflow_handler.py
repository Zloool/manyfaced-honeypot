"""LangflowHandler – impersonates the Langflow web UI and REST API.

Provides realistic Langflow (low-code LLM app builder) responses including:
- Langflow login page (/ and /login)
- Langflow REST API responses (/api/v1/run, /api/v1/flows,
  /api/v1/validate, /api/v1/upload)
- Captures login credentials from POST requests
- Upload endpoint (/api/v1/upload) is reachable without authentication,
  mirroring CVE-2026-55255 (authorization-bypass file upload) exploitation
  attempts — returns 200 to capture the probe.

Langflow is a popular open-source LLM orchestration platform widely targeted
by bots probing for exposed builder instances and API access.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class LangflowHandler(HTTPHandlerBase):
    """Langflow honeypot handler."""

    domain = 'langflow'
    DETECTED_ID = 1041
    VERSION = '1.0.0'

    # --- canonical API endpoints we emulate (realistic probe paths) ---------
    _FLOWS_JSON = [
        {
            'id': '00000000-0000-0000-0000-000000000001',
            'name': 'Basic Prompting',
            'description': 'A simple flow that prompts an LLM.',
            'data': {},
            'user_id': None,
            'updated_at': '2024-01-01T00:00:00Z',
            'created_at': '2024-01-01T00:00:00Z',
        }
    ]

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Langflow response for the given request."""
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
        path_lower = path.lower().rstrip('/') or '/'

        # Capture credentials from credential-bearing POST endpoints.
        if method == 'POST' and path_lower in (
            '/login',
            '/api/v1/upload',
            '/api/v1/run',
        ):
            credentials = self._extract_credentials(raw_request, headers or {})
            if credentials:
                profile.capture_credentials(credentials)
                # Return a success response to encourage further probing.
                if path_lower == '/login':
                    body = self._login_success_json()
                    return (
                        self._build_http_response(body, 200, 'OK', 'application/json'),
                        self.DETECTED_ID,
                    )
                if path_lower == '/api/v1/upload':
                    body = json.dumps({'flow_id': None, 'file_path': 'uploads/flow_8f3a.json'})
                    return (
                        self._build_http_response(body, 200, 'OK', 'application/json'),
                        self.DETECTED_ID,
                    )
                # /api/v1/run
                body = json.dumps({'outputs': []})
                return (
                    self._build_http_response(body, 200, 'OK', 'application/json'),
                    self.DETECTED_ID,
                )

        # Route to the appropriate response.
        if path_lower == '/api/v1/run':
            body = json.dumps({'outputs': []})
            return (
                self._build_http_response(body, 200, 'OK', 'application/json'),
                self.DETECTED_ID,
            )
        if path_lower == '/api/v1/flows':
            body = json.dumps(self._FLOWS_JSON)
            return (
                self._build_http_response(body, 200, 'OK', 'application/json'),
                self.DETECTED_ID,
            )
        if path_lower == '/api/v1/validate':
            body = json.dumps({'valid': True, 'details': {}})
            return (
                self._build_http_response(body, 200, 'OK', 'application/json'),
                self.DETECTED_ID,
            )
        if path_lower == '/api/v1/upload':
            # CVE-2026-55255 authorization-bypass upload endpoint.
            body = json.dumps({'flow_id': None, 'file_path': 'uploads/flow_8f3a.json'})
            return (
                self._build_http_response(body, 200, 'OK', 'application/json'),
                self.DETECTED_ID,
            )
        if path_lower in ('/', '/login'):
            body = self._login_page()
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # Default: serve the Langflow login page.
        body = self._login_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # --- response builders --------------------------------------------------

    def _login_success_json(self) -> str:
        """Return a fake login success JSON (Langflow session token)."""
        return json.dumps(
            {
                'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake',
                'token_type': 'bearer',
            }
        )

    def _login_page(self) -> str:
        """Langflow login HTML page (logo, title, login form)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Langflow</title>
<link rel="icon" href="/favicon.ico">
<style>
  html, body { height: 100%; margin: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #0c0c0c; color: #f5f5f5; display: flex; align-items: center; justify-content: center;
  }
  .login-box { width: 360px; background: #171717; padding: 32px; border-radius: 12px; box-shadow: 0 0 24px rgba(0,0,0,0.5); }
  .login-logo { text-align: center; margin-bottom: 24px; }
  .login-logo h1 { font-size: 26px; font-weight: 600; margin: 8px 0 0; color: #fff; }
  .login-logo .glyph { display: inline-block; width: 44px; height: 44px; border-radius: 10px; background: linear-gradient(135deg,#7c3aed,#db2777); }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 13px; margin-bottom: 6px; color: #a1a1aa; }
  .form-group input { width: 100%; box-sizing: border-box; padding: 10px 12px; background: #0c0c0c; border: 1px solid #2c2c2c; border-radius: 8px; color: #f5f5f5; font-size: 14px; }
  .form-group input:focus { outline: none; border-color: #7c3aed; }
  .btn-login { width: 100%; padding: 11px; background: #7c3aed; border: none; border-radius: 8px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; }
  .btn-login:hover { background: #6d28d9; }
  .login-footer { margin-top: 16px; text-align: center; font-size: 12px; color: #52525b; }
</style>
</head>
<body>
  <div class="login-box">
    <div class="login-logo">
      <span class="glyph"></span>
      <h1>Langflow</h1>
    </div>
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="off" placeholder="admin">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="off">
      </div>
      <button type="submit" class="btn-login">Log in</button>
    </form>
    <div class="login-footer">
      <p>Langflow 1.0.0 &middot; Build LLM apps visually</p>
    </div>
  </div>
</body>
</html>"""

    # --- helpers ------------------------------------------------------------

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
            f'Server: uvloop\r\n'
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
        return f'LangflowHandler(domain={self.domain!r})'
