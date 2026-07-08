"""ZabbixHandler – handles Zabbix frontend / JSON-RPC API probe paths.

Provides realistic Zabbix (6.4.0) honeypot responses covering the production
probe paths recorded in issue #282:

  /zc?action=getinfo      – Zabbix "zc" status/info endpoint
  /evox/about             – EVOX/Zabbix-flavoured "about" page
  /zabbix/favicon.ico     – static asset
  /zabbix.php             – Zabbix frontend sign-in page
  /api_jsonrpc.php        – Zabbix JSON-RPC API

The handler serves a believable Zabbix sign-in page for the frontend routes,
a JSON-RPC-ish response for the API endpoint, and captures credentials from
any login/auth POST.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import ZABBIX_HTTP

logger = logging.getLogger(__name__)


class ZabbixHandler(HTTPHandlerBase):
    """Zabbix 6.4.0 honeypot handler."""

    domain = 'zabbix'
    DETECTED_ID = ZABBIX_HTTP
    VERSION = '6.4.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Zabbix response for the given request."""
        # Strip any query string before matching (router may pass it through).
        clean_path = path.split('?', 1)[0]

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
        path_lower = clean_path.lower()

        # Handle login POST requests. The Zabbix frontend sign-in form posts
        # to /zabbix.php, the "zc" info endpoint accepts auth-style POSTs, and
        # any explicit login/auth path triggers credential capture too.
        is_login_path = (
            'login' in path_lower
            or 'auth' in path_lower
            or path_lower == '/zabbix.php'
            or path_lower == '/zc'
        )
        if method == 'POST' and is_login_path:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to the appropriate response.
        if path_lower == '/api_jsonrpc.php':
            body = self._jsonrpc_response(raw_request)
            return self._build_http_response(
                body, 200, 'OK', content_type='application/json; charset=UTF-8'
            ), self.DETECTED_ID

        if path_lower == '/zabbix/favicon.ico':
            return self._favicon_response(), self.DETECTED_ID

        if path_lower == '/evox/about':
            body = self._about_page()
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # /zabbix.php, /zc (with or without ?action=getinfo), and any other
        # Zabbix frontend path all serve the sign-in page.
        body = self._frontend_page(clean_path)
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    def _frontend_page(self, path: str = '') -> str:
        """Zabbix frontend sign-in page (realistic 6.4.0 markup)."""
        action = ''
        if 'getinfo' in path.lower():
            action = '?action=getinfo'
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zabbix 6.4.0</title>
<link rel="icon" href="/zabbix/favicon.ico">
<link rel="stylesheet" type="text/css" href="/zabbix/assets/styles.css">
<script type="text/javascript" src="/zabbix/js/bundle.js"></script>
</head>
<body class="zabbix-frontend">
<div class="zabbix-logo">
    <a href="/zabbix.php"><img src="/zabbix/img/zabbix_logo.png" alt="Zabbix" width="160"></a>
</div>
<div class="signin-container">
    <h1>Zabbix {self.VERSION}</h1>
    <form method="POST" action="/zabbix.php{action}" name="zabbix_login" id="zabbix_login">
        <input type="hidden" name="form_refresh" value="1">
        <div class="form-field">
            <label for="name">Username</label>
            <input type="text" name="name" id="name" autocomplete="off" maxlength="255">
        </div>
        <div class="form-field">
            <label for="password">Password</label>
            <input type="password" name="password" id="password" autocomplete="off" maxlength="255">
        </div>
        <div class="form-actions">
            <button type="submit" name="enter" value="Sign in">Sign in</button>
        </div>
    </form>
    <div class="zabbix-meta">
        <p>Monitoring, alerting and visualization platform.</p>
        <p class="zabbix-version">Zabbix {self.VERSION} &middot; Copyright &copy; Zabbix SIA</p>
    </div>
</div>
</body>
</html>"""

    def _about_page(self) -> str:
        """EVOX-flavoured Zabbix 'about' page (/evox/about)."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>About Zabbix 6.4.0</title>
<link rel="stylesheet" type="text/css" href="/zabbix/assets/styles.css">
</head>
<body class="zabbix-about">
<div class="about-container">
    <h1>Zabbix {self.VERSION}</h1>
    <p>Zabbix is an enterprise-class open source distributed monitoring solution.</p>
    <ul>
        <li>High performance, high capacity monitoring</li>
        <li>Agentless and agent-based checks</li>
        <li>Flexible escalation and alerting</li>
    </ul>
    <p class="zabbix-version">Zabbix {self.VERSION} &middot; EVOX build</p>
    <p><a href="/zabbix.php">Back to sign in</a></p>
</div>
</body>
</html>"""

    def _jsonrpc_response(self, raw_request: str) -> str:
        """Build a JSON-RPC response for the Zabbix API endpoint.

        Mirrors the shape of a Zabbix API reply:
            {"jsonrpc": "2.0", "result": {...}, "id": <id>}
        For user.login it returns a fake auth token; otherwise a generic
        success result — enough to keep a probe engaging with the face.
        """
        method = ''
        req_id = 1
        try:
            body = self._extract_body(raw_request)
            payload = json.loads(body) if body else {}
            method = (payload.get('method') or '').lower()
            req_id = payload.get('id', 1)
        except (json.JSONDecodeError, ValueError):
            pass

        if method == 'user.login':
            result = {
                'auth': 'b07c4e9d2f8a1c6e3b5d7a0f9c2e4b6d',
                'sessionid': 'b07c4e9d2f8a1c6e3b5d7a0f9c2e4b6d',
            }
        elif method == 'apiinfo.version':
            result = self.VERSION
        else:
            result = {
                'zabbix': self.VERSION,
                'status': 'ok',
                'server': 'manyfaced-honeypot',
            }

        return json.dumps(
            {'jsonrpc': '2.0', 'result': result, 'id': req_id},
            separators=(',', ':'),
        )

    def _favicon_response(self) -> bytes:
        """Minimal valid ICO favicon so /zabbix/favicon.ico resolves."""
        # 16x16 32-bit ICO header + a single blank-ish bitmap header.
        ico = (
            b'\x00\x00'          # Reserved
            b'\x01\x00'          # Type = icon
            b'\x01\x00'          # Count = 1
            # Directory entry
            b'\x10'              # Width 16
            b'\x10'              # Height 16
            b'\x00'              # Palette
            b'\x00'              # Reserved
            b'\x01\x00'          # Color planes
            b'\x20\x00'          # Bit count 32
            b'\x00\x00\x00\x00'  # Data size (placeholder, ignored by most clients)
            b'\x16\x00\x00\x00'  # Offset = 22
            # BITMAPINFOHEADER (40 bytes) + 16x16x4 RGBA
            b'\x28\x00\x00\x00'  # Header size
            b'\x10\x00\x00\x00'  # Width
            b'\x20\x00\x00\x00'  # Height (2 * 16)
            b'\x01\x00'          # Planes
            b'\x20\x00'          # Bit count
            + b'\x00' * 72       # Remaining header + pixel data (zeroed)
        )
        return self._build_http_response(
            ico.decode('latin-1'), 200, 'OK', content_type='image/x-icon'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response – contains 'Error' (credential-capture probe)."""
        body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Zabbix 6.4.0</title>
</head>
<body class="zabbix-frontend">
<div class="signin-error">
    <h3>Login Error</h3>
    <p>Incorrect user name or password or account is temporarily blocked.</p>
    <p><a href="/zabbix.php">Return to sign in</a></p>
</div>
</body>
</html>"""
        return self._build_http_response(body, 200, 'OK')

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    @staticmethod
    def _extract_body(raw_request: str) -> str:
        """Extract the body portion of a raw HTTP request."""
        if '\r\n\r\n' in raw_request:
            return raw_request.split('\r\n\r\n', 1)[1]
        if '\n\n' in raw_request:
            return raw_request.split('\n\n', 1)[1]
        return ''

    def _build_http_response(
        self,
        body: str,
        status_code: int = 200,
        status_text: str = 'OK',
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('iso-8859-1')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Zabbix/{self.VERSION}\r\n'
            f'X-Powered-By: PHP/8.2.15\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'\r\n'
        )
        return response.encode('iso-8859-1') + body_bytes

    def __repr__(self) -> str:
        return f'ZabbixHandler(domain={self.domain!r})'
