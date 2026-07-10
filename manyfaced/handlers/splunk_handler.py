"""SplunkHandler — Splunk Enterprise honeypot handler (issue #397 / CVE-2026-20253).

Emulates the Splunk Enterprise Web UI (Splunk Web) and the splunkd REST API
surface so that real-world Splunk probes — the landing page, the login form,
the ``/services/auth/login`` session endpoint, search job creation, the
``/servicesNS/`` REST config, generic ``/api/`` calls, and the
CVE-2026-20253 path-traversal / SSRF probe path — receive plausible responses.

Captured login attempts on ``/services/auth/login`` return a fake session token
so the bot keeps probing.  Full-fidelity emulation is intentionally NOT provided
(log-and-respond only).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)

# Hardcoded detected-id for the Splunk face (do NOT touch status.py).
DETECTED_ID = 1046

# Splunk Enterprise version advertised in responses.
SPLUNK_VERSION = '9.2.1'

# CVE-2026-20253 — path-traversal / SSRF probe signatures seen in the wild.
# The vulnerability is reachable via the splunkd REST endpoint used for app
# packaging / externallookup / scripted inputs; probes typically carry encoded
# ".." traversal segments or an embedded "http(s)://" SSRF target.
_CVE_TRAVERSAL_RE = re.compile(r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)', re.IGNORECASE)
_CVE_SSRF_RE = re.compile(r'(https?://|file://|gopher://|dict://)', re.IGNORECASE)


class SplunkHandler(HTTPHandlerBase):
    """Splunk Enterprise honeypot handler."""

    domain = 'splunk'
    DETECTED_ID = DETECTED_ID
    VERSION = SPLUNK_VERSION

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Splunk Enterprise response for the given request."""
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
        decoded = self._decode_path(path)
        path_lower = decoded.lower()

        # ---- CVE-2026-20253: path-traversal / SSRF probe -> capture, 200 ----
        if _CVE_TRAVERSAL_RE.search(decoded) or _CVE_SSRF_RE.search(decoded):
            logger.info('CVE-2026-20253 probe from %s: %s', bot_ip, decoded)
            profile.record_request({'cve_2026_20253_probe': decoded})
            body = self._cve_probe_response(decoded)
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID

        # ---- Login POST: extract creds, capture, return fake session token --
        if method == 'POST' and 'auth/login' in path_lower:
            credentials = self._extract_credentials(raw_request, headers or {})
            if credentials:
                profile.capture_credentials(credentials)
                body = self._auth_login_success_response(credentials)
                return (
                    self._build_http_response(body, 200, 'OK', self._json_type()),
                    self.DETECTED_ID,
                )

        # ---- Search job creation: POST /services/search/jobs -> 201 + sid ----
        if method == 'POST' and 'search/jobs' in path_lower:
            body = self._search_jobs_response()
            return (
                self._build_http_response(body, 201, 'Created', self._json_type()),
                self.DETECTED_ID,
            )

        # ---- REST config surface: /servicesNS/ ----------------------------
        if decoded.startswith('/servicesns/') or path_lower.startswith('/servicesns/'):
            body = self._servicesns_response(path)
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID

        # ---- Generic API surface: /api/ ------------------------------------
        if decoded.startswith('/api/') or path_lower.startswith('/api/'):
            body = self._api_response(path)
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID

        # ---- Login page: /en-US/account/login ------------------------------
        if decoded == '/en-us/account/login':
            body = self._login_page()
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # ---- Splunk Web landing pages: / and /en-US/ -----------------------
        if decoded in ('/', '/en-us/', '/en-us'):
            body = self._landing_page()
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # ---- Anything else Splunk-ish falls back to the Web landing page ---
        body = self._landing_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # -- Response builders --------------------------------------------------

    def _landing_page(self) -> str:
        """Splunk Web landing page (mentions Splunk)."""
        return (
            """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Splunk Enterprise</title>
<link rel="icon" href="/static/img/favicon.ico" type="image/x-icon">
<style>
  body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; background: #f4f4f4; color: #2c2c2c; }
  .topbar { background: #1a1a1a; color: #fff; padding: 12px 24px; display: flex; align-items: center; }
  .logo { font-size: 22px; font-weight: bold; }
  .logo span { color: #f5a623; }
  .wrap { max-width: 960px; margin: 40px auto; padding: 0 24px; }
  h1 { font-size: 28px; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 20px; margin-top: 20px; }
  a { color: #1a73e8; text-decoration: none; }
  .footer { margin-top: 40px; font-size: 12px; color: #aaa; text-align: center; }
</style>
</head>
<body>
  <div class="topbar">
    <div class="logo">Splunk<span>®</span></div>
  </div>
  <div class="wrap">
    <h1>Welcome to Splunk Enterprise</h1>
    <p>Turn data into answers. Use Search & Reporting, dashboards, and alerts to
    investigate and monitor your machine data.</p>
    <div class="card">
      <h2>Get started</h2>
      <p><a href="/en-US/account/login">Sign in to Splunk</a> to search and analyze
      your data, or explore the <a href="/en-US/app/search/">Search & Reporting</a> app.</p>
    </div>
    <div class="footer">
      Powered by Splunk Enterprise &middot; Version """
            + self.VERSION
            + """
    </div>
  </div>
</body>
</html>"""
        )

    def _login_page(self) -> str:
        """Splunk Web account login page (mentions Splunk)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to Splunk</title>
<link rel="icon" href="/static/img/favicon.ico" type="image/x-icon">
<style>
  body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; background: #1a1a1a; color: #fff; }
  .login { width: 360px; margin: 80px auto; background: #2c2c2c; border-radius: 8px; padding: 32px; }
  .logo { font-size: 24px; font-weight: bold; text-align: center; margin-bottom: 24px; }
  .logo span { color: #f5a623; }
  label { display: block; font-size: 13px; margin: 12px 0 4px; }
  input[type=text], input[type=password] { width: 100%; padding: 10px; border: 1px solid #444; border-radius: 4px; background: #1a1a1a; color: #fff; box-sizing: border-box; }
  button { width: 100%; margin-top: 20px; padding: 10px; background: #f5a623; border: 0; border-radius: 4px; font-weight: bold; cursor: pointer; }
</style>
</head>
<body>
  <div class="login">
    <div class="logo">Splunk<span>®</span></div>
    <form method="post" action="/en-US/account/login" id="login_form">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"""

    def _auth_login_success_response(self, credentials: dict[str, str]) -> str:
        """Fake successful ``/services/auth/login`` response with session token."""
        session_key = (
            'a'
            + ''.join(
                re.findall(
                    r'[0-9a-f]',
                    __import__('hashlib')
                    .sha256(
                        f'{credentials.get("username", "")}:{datetime.now(timezone.utc).isoformat()}'.encode()
                    )
                    .hexdigest(),
                )
            )[:31]
        )
        payload = {
            'sessionKey': session_key,
            'userId': credentials.get('username', 'admin'),
            'username': credentials.get('username', 'admin'),
            'realName': credentials.get('username', 'admin'),
            'roles': ['admin', 'power', 'user'],
            'type': 'normal',
            'authType': 'Splunk',
        }
        return json.dumps(payload)

    def _search_jobs_response(self) -> str:
        """Fake created search job (201) with a sid."""
        sid = f'scheduler__admin__search__{"%08x" % (int(datetime.now(timezone.utc).timestamp()) & 0xFFFFFFFF)}_0'
        payload = {
            'sid': sid,
            'results': '/services/search/jobs/' + sid + '/results',
            'summary': '/services/search/jobs/' + sid + '/summary',
            'timeline': '/services/search/jobs/' + sid + '/timeline',
            'events': '/services/search/jobs/' + sid + '/events',
            'control': '/services/search/jobs/' + sid + '/control',
            'author': 'admin',
            'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z'),
        }
        return json.dumps(payload)

    def _servicesns_response(self, path: str) -> str:
        """Fake REST config response for ``/servicesNS/``."""
        payload = {
            'links': {
                'alternate': path,
                'list': path,
                'edit': path,
            },
            'origin': 'https://localhost:8089/servicesNS/',
            'updated': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z'),
            'generator': {
                'build': self.VERSION,
                'version': self.VERSION,
                'license': 'enterprise',
            },
            'entry': [
                {
                    'name': 'search',
                    'id': path,
                    'content': {
                        'eai:appName': 'search',
                        'eai:userName': 'admin',
                        'disabled': False,
                        'visible': True,
                    },
                }
            ],
        }
        return json.dumps(payload)

    def _api_response(self, path: str) -> str:
        """Fake generic ``/api/`` response mentioning Splunk."""
        payload = {
            'service': 'splunk',
            'version': self.VERSION,
            'path': path,
            'status': 'ok',
        }
        return json.dumps(payload)

    def _cve_probe_response(self, decoded_path: str) -> str:
        """Capture response for a CVE-2026-20253 probe (path-traversal / SSRF)."""
        payload = {
            'service': 'splunk',
            'version': self.VERSION,
            'captured_probe': decoded_path,
            'status': 'ok',
        }
        return json.dumps(payload)

    # -- Helpers ------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Decode percent-encoded probe segments (``%2e`` -> '.', ``%2f`` -> '/')."""
        decoded = unquote_plus(path)
        decoded = decoded.replace('%2E', '.').replace('%2F', '/')
        decoded = decoded.replace('%2e', '.').replace('%2f', '/')
        return decoded

    def _json_type(self) -> str:
        return 'application/json; charset=UTF-8'

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        status_code: int = 200,
        status_text: str = 'OK',
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP/1.1 response (iso-8859-1 wire encoding)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Splunkd\r\n'
            f'X-Splunk-Version: {self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'SplunkHandler(domain={self.domain!r})'
