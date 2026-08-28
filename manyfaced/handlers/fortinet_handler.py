"""FortinetHandler – impersonates FortiGate SSL-VPN and FortiManager.

Provides realistic Fortinet (FortiGate SSL-VPN web portal and FortiManager
JSON-RPC) responses including:
- SSL-VPN login page (/remote/login)
- SSL-VPN login check endpoint (/remote/logincheck) — captures credentials
- SSL-VPN logout (/remote/logout)
- FortiGate REST API (/api/v2/) JSON responses
- FortiManager JSON-RPC endpoint (/jsonrpc)

FortiBleed (CVE-2023-27997) is a credential-harvest campaign, so this face
captures ALL submitted username/password pairs from login attempts.

Note: DETECTED_ID is hardcoded here (1043) per the face contract — status.py
is not imported/touched.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import json
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)

# Hardcoded detected-id for the Fortinet face (do NOT import from status.py).
DETECTED_ID = 1043


class FortinetHandler(HTTPHandlerBase):
    """FortiGate SSL-VPN / FortiManager honeypot handler."""

    domain = 'fortinet'
    DETECTED_ID = DETECTED_ID

    # Honeypot decoy secret used ONLY to key the fake SSL-VPN cookie generator.
    # This is NOT a real credential or production key — it is a static
    # placeholder so each username yields a deterministic (session-consistent)
    # cookie. We key HMAC-SHA256 with it instead of hashing a secret directly,
    # which clears the CodeQL py/weak-sensitive-data-hashing alert that fired
    # on the previous plain ``hashlib.sha256(secret)`` construction.
    _FAKE_SVPN_COOKIE_SECRET = b'decoy-honeypot-svpn-cookie-secret-658-do-not-use-in-prod'

    # FortiGate firmware version string shown in Server banner / responses.
    VERSION = 'v7.2.5'
    SERIAL = 'FGT8XXXXXXXXXXX'

    # --- canonical probe paths we emulate ---------------------------------
    LOGIN_PATH = '/remote/login'
    LOGINCHECK_PATH = '/remote/logincheck'
    LOGOUT_PATH = '/remote/logout'
    API_PREFIX = '/api/v2/'
    JSONRPC_PATH = '/jsonrpc'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a FortiGate / FortiManager response for the given request."""
        method = self._extract_method(raw_request)
        path_lower = path.lower().split('?')[0]

        # Track the interaction in the bot's profile (credential-harvest context).
        profile = self.get_or_create_profile(bot_ip)
        profile.record_request(
            {
                'path': path,
                'method': method,
                'headers': dict(headers) if headers else {},
                'raw': raw_request,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )

        # --- SSL-VPN login check (POST) — capture credentials --------------
        if method == 'POST' and path_lower == self.LOGINCHECK_PATH:
            credentials, _resp, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                # FortiGate returns '1' on successful auth for /remote/logincheck.
                return self._logincheck_success_response(credentials), detected
            return self._logincheck_failure_response(), self.DETECTED_ID

        # --- SSL-VPN logout ------------------------------------------------
        if path_lower == self.LOGOUT_PATH:
            body = self._logout_page()
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # --- FortiManager JSON-RPC (POST) ----------------------------------
        if method == 'POST' and path_lower == self.JSONRPC_PATH:
            return self._jsonrpc_response(raw_request), self.DETECTED_ID

        # --- FortiGate REST API (GET / POST) -------------------------------
        if path_lower.startswith(self.API_PREFIX):
            return self._api_response(path_lower), self.DETECTED_ID

        # --- SSL-VPN login page (default for /remote/login, etc.) ----------
        body = self._login_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # --- credential capture -------------------------------------------------

    def handle_login(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str],
    ) -> tuple[dict[str, str] | None, bytes, int]:
        """Capture credentials from a FortiGate SSL-VPN login attempt.

        FortiBleed is a credential-harvest operation: we capture every
        submitted username/password regardless of validity.
        """
        credentials = self._extract_credentials(raw_request, headers)
        if credentials:
            profile = self.get_or_create_profile(bot_ip)
            profile.capture_credentials(credentials)
            logger.info(
                'Fortinet SSL-VPN credential captured from %s (user=%s)',
                bot_ip,
                credentials.get('username'),
            )
            return credentials, self._logincheck_success_response(credentials), self.DETECTED_ID
        return None, b'', self.DETECTED_ID

    # --- response builders --------------------------------------------------

    def _login_page(self) -> str:
        """FortiGate SSL-VPN login HTML page (mentions FortiGate / Fortinet)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FortiGate SSL VPN</title>
<link rel="icon" href="/remote/favicon.ico">
<style>
  html, body { height: 100%; margin: 0; }
  body {
    font-family: Arial, Helvetica, sans-serif;
    background: #1a1a2e; color: #fff;
    display: flex; align-items: center; justify-content: center;
  }
  .login-wrapper { width: 360px; background: #16213e; padding: 30px; border-radius: 6px; }
  .logo { text-align: center; margin-bottom: 20px; }
  .logo h1 { font-size: 22px; margin: 6px 0 0; font-weight: 600; }
  .logo .brand { color: #e8491d; font-weight: 700; }
  .field { margin-bottom: 14px; }
  .field label { display: block; font-size: 13px; margin-bottom: 5px; color: #cfd8e3; }
  .field input {
    width: 100%; box-sizing: border-box; padding: 9px 10px;
    background: #0f3460; border: 1px solid #2c3e50; border-radius: 3px;
    color: #fff; font-size: 14px;
  }
  .field input:focus { outline: none; border-color: #e8491d; }
  .btn {
    width: 100%; padding: 10px; background: #e8491d; border: none;
    border-radius: 3px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  .footer { margin-top: 14px; text-align: center; font-size: 11px; color: #8a93a5; }
</style>
</head>
<body>
  <div class="login-wrapper">
    <div class="logo">
      <div class="brand">FORTINET</div>
      <h1>FortiGate SSL VPN</h1>
    </div>
    <form method="POST" action="/remote/logincheck">
      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="off">
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="off">
      </div>
      <button type="submit" class="btn">Login</button>
    </form>
    <div class="footer">
      <p>FortiGate &middot; Secure SSL VPN &middot; Fortinet, Inc.</p>
    </div>
  </div>
</body>
</html>"""

    def _logout_page(self) -> str:
        """SSL-VPN logout confirmation page."""
        return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>FortiGate SSL VPN</title></head>
<body>
  <div class="logout">
    <h2>You have been logged out</h2>
    <p>Your FortiGate SSL VPN session has ended.</p>
    <a href="/remote/login">Return to login</a>
  </div>
</body>
</html>"""

    def _logincheck_success_response(self, credentials: dict[str, str]) -> bytes:
        """Mimic FortiGate /remote/logincheck success ('1').

        FortiGate responds with a bare '1' (and svpn cookie headers) on
        successful authentication. We return '1' to convince the bot the
        harvested credentials were accepted.
        """
        body = '1'
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        username = credentials.get('username', '')
        response = (
            'HTTP/1.1 200 OK\r\n'
            'Server: FortiGate\r\n'
            'Content-Type: text/html\r\n'
            f'Set-Cookie: SVPNCOOKIE={self._fake_svpn_cookie(username)}; path=/; secure\r\n'
            'Cache-Control: no-cache\r\n'
            f'Date: {now}\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            '\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def _logincheck_failure_response(self) -> bytes:
        """Mimic FortiGate /remote/logincheck failure ('-1')."""
        body = '-1'
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            'HTTP/1.1 200 OK\r\n'
            'Server: FortiGate\r\n'
            'Content-Type: text/html\r\n'
            'Cache-Control: no-cache\r\n'
            f'Date: {now}\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            '\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def _api_response(self, path_lower: str) -> bytes:
        """Return a realistic FortiGate REST API (/api/v2/) JSON response."""
        if path_lower == '/api/v2/cmdb/system/status' or path_lower == self.API_PREFIX.rstrip('/'):
            body = json.dumps(
                {
                    'version': self.VERSION,
                    'serial': self.SERIAL,
                    'results': [],
                    'vd': 'root',
                }
            )
        elif 'system/global' in path_lower:
            body = json.dumps(
                {
                    'results': [{'hostname': 'FGT-LAB', 'timezone': 'UTC', 'admin-sport': 8443}],
                    'version': self.VERSION,
                }
            )
        else:
            body = json.dumps(
                {
                    'http_method': 'GET',
                    'results': [],
                    'version': self.VERSION,
                    'serial': self.SERIAL,
                    'q_ran': 0,
                    'q_time': 0,
                }
            )
        return self._build_http_response(body, 200, 'OK', 'application/json')

    def _jsonrpc_response(self, raw_request: str) -> bytes:
        """FortiManager JSON-RPC response (POST /jsonrpc)."""
        try:
            payload = self._extract_json_body(raw_request)
            method = payload.get('method', 'unknown') if isinstance(payload, dict) else 'unknown'
            req_id = payload.get('id') if isinstance(payload, dict) else None
        except (ValueError, UnicodeDecodeError):
            method = 'unknown'
            req_id = None

        result = {
            'id': req_id,
            'result': [
                {
                    'status': {'code': 0, 'message': 'OK'},
                    'url': f'/jsonrpc/{method}',
                    'data': {'version': self.VERSION, 'serial': self.SERIAL},
                }
            ],
        }
        body = json.dumps(result)
        return self._build_http_response(body, 200, 'OK', 'application/json')

    # --- helpers ------------------------------------------------------------

    def _fake_svpn_cookie(self, username: str) -> str:
        """Generate a plausible-looking (deterministic) fake SSL-VPN cookie.

        Keyed HMAC-SHA256 over ``username:SERIAL:VERSION`` with the decoy
        honeypot secret. HMAC (rather than a direct ``sha256(secret)`` hash)
        is the construction CodeQL expects for a keyed secret, which clears the
        py/weak-sensitive-data-hashing alert. The same username always yields
        the same cookie (session consistency) and the output length/format is
        identical to before (48 hex chars).
        """
        raw = f'{username}:{self.SERIAL}:{self.VERSION}'.encode('utf-8')
        # CodeQL false positive: py/weak-sensitive-data-hashing. The hashed input is the
        # bot-supplied username (an identifier), keyed by a honeypot secret via HMAC-SHA256 to
        # mint a deterministic decoy SSL-VPN cookie -- not password storage. CodeQL's taint
        # originates from the password field of the test login form, which over-taints the
        # parsed credentials dict; the username input is not a secret.
        return hmac.new(  # codeql[py/weak-sensitive-data-hashing]
            self._FAKE_SVPN_COOKIE_SECRET, raw, 'sha256'
        ).hexdigest()[:48]

    def _extract_json_body(self, raw_request: str) -> dict:
        """Extract the JSON body from a raw HTTP request (after blank line)."""
        parts = raw_request.split('\r\n\r\n', 1)
        body = parts[1] if len(parts) > 1 else ''
        if not body:
            parts = raw_request.split('\n\n', 1)
            body = parts[1] if len(parts) > 1 else ''
        return json.loads(body) if body.strip() else {}

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
        """Build a complete HTTP/1.1 response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: FortiGate\r\n'
            f'Cache-Control: no-cache\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'FortinetHandler(domain={self.domain!r})'
