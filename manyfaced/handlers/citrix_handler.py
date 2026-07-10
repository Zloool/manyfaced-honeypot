"""CitrixHandler – emulates a Citrix NetScaler Gateway honeypot.

Provides realistic NetScaler Gateway / Citrix Gateway responses covering:
- VPN login page (/vpn/index.html)
- CGI login endpoint (/cgi/login) — captures brute-forced credentials
- nFactor / WebAuth flow (/nf/auth/...)
- StoreFront / LogonPoint (/logon/LogonPoint/)
- CVE-2026-3055 out-of-bounds-read probe paths (/pcidss/, /oauth, /saml)

All submitted credentials are captured (Citrix Gateway is heavily brute-forced).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)

# Hardcoded detected id for the Citrix NetScaler Gateway face (do NOT touch status.py).
DETECTED_ID = 1044


class CitrixHandler(HTTPHandlerBase):
    """Citrix NetScaler Gateway honeypot handler."""

    domain = 'citrix'
    DETECTED_ID = DETECTED_ID

    # CVE-2026-3055 out-of-bounds-read probe prefixes — always return 200.
    _CVE_2026_3055_PREFIXES = ('/pcidss/', '/oauth', '/saml', '/cgi/oauth')

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a NetScaler Gateway response for the given request."""
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

        # CVE-2026-3055 out-of-bounds-read probe — return 200 with a benign body.
        if self._is_cve_probe(path_lower):
            return self._build_http_response(self._probe_response(), path), self.DETECTED_ID

        # Login POST — capture credentials and return a success/redirect to
        # encourage further brute-force probing.
        if method == 'POST' and self._is_login_path(path_lower):
            credentials = self._extract_credentials(raw_request, headers or {})
            if credentials:
                profile.capture_credentials(credentials)
                return self._login_success_response(), self.DETECTED_ID
            # Malformed login POST — echo a generic failure page.
            return self._login_failed_response(), self.DETECTED_ID

        # GET login / index pages.
        if path_lower == '/vpn/index.html':
            body = self._vpn_index_page()
        elif '/cgi/login' in path_lower:
            body = self._login_page()
        elif '/nf/auth' in path_lower or path_lower.startswith('/nf/'):
            body = self._nf_auth_page()
        elif '/logon/logonpoint' in path_lower or path_lower.startswith('/logon/'):
            body = self._logon_point_page()
        elif path_lower == '/vpn/index.html' or path_lower == '/':
            body = self._vpn_index_page()
        else:
            body = self._vpn_index_page()

        response = self._build_http_response(body, path)
        self._response_count += 1
        return response, self.DETECTED_ID

    # -- path helpers -------------------------------------------------------

    @staticmethod
    def _is_login_path(path_lower: str) -> bool:
        return '/cgi/login' in path_lower or '/nf/auth' in path_lower or '/logon' in path_lower

    @staticmethod
    def _is_cve_probe(path_lower: str) -> bool:
        return any(path_lower.startswith(p) for p in CitrixHandler._CVE_2026_3055_PREFIXES)

    @staticmethod
    def _extract_method(raw_request: str) -> str:
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    # -- response builders --------------------------------------------------

    def _build_http_response(self, body: str, path: str, status: str = '200 OK') -> bytes:
        """Build a complete HTTP/1.1 response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('utf-8')
        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: NetScaler Gateway\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: text/html; charset=utf-8\r\n'
            f'Set-Cookie: NSC_TASS=ffffffff; Path=/; Secure; HttpOnly\r\n'
            f'X-Citrix-Transaction: {self._tx_id()}\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        ).encode('iso-8859-1') + body_bytes
        return response

    @staticmethod
    def _tx_id() -> str:
        return datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S') + 'abc123'

    def _login_success_response(self) -> bytes:
        """Return a fake login success / redirect response (302)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body = (
            '<html><head><title>302 Found</title></head><body>'
            'The document has moved <a href="/vpn/index.html">here</a>.</body></html>'
        )
        body_bytes = body.encode('utf-8')
        response = (
            'HTTP/1.1 302 Found\r\n'
            'Server: NetScaler Gateway\r\n'
            f'Date: {now}\r\n'
            'Location: /vpn/index.html\r\n'
            'Set-Cookie: NSC_TASS=ffffffff; Path=/; Secure; HttpOnly\r\n'
            'Content-Type: text/html; charset=utf-8\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            'Connection: close\r\n'
            '\r\n'
        ).encode('iso-8859-1') + body_bytes
        return response

    def _login_failed_response(self) -> bytes:
        """Return a fake login failed page (200) to keep the bot engaged."""
        body = self._login_page(error=True)
        return self._build_http_response(body, '/cgi/login')

    # -- page bodies --------------------------------------------------------

    def _vpn_index_page(self) -> str:
        """NetScaler Gateway VPN login landing page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Citrix Gateway</title>
    <link rel="stylesheet" type="text/css" href="/vpn/resources/css/login.css">
</head>
<body class="login-body">
    <div id="login-container">
        <div id="login-header">
            <img src="/vpn/resources/img/logo.png" alt="Citrix" />
            <h1>Citrix Gateway</h1>
            <h2>NetScaler Access Gateway</h2>
        </div>
        <form name="login" action="/cgi/login" method="post" id="login-form">
            <div class="form-group">
                <label for="login">User name</label>
                <input type="text" name="login" id="login" autocomplete="username" />
            </div>
            <div class="form-group">
                <label for="passwd">Password</label>
                <input type="password" name="password" id="passwd" autocomplete="current-password" />
            </div>
            <div class="form-group">
                <input type="submit" name="Log On" value="Log On" id="logonButton" />
            </div>
            <input type="hidden" name="url" value="https://vpn.example.com/" />
            <input type="hidden" name="urlhost" value="vpn.example.com" />
        </form>
        <div id="footer">
            <p>Copyright &copy; Citrix Systems, Inc. All rights reserved.</p>
            <p>Powered by NetScaler Gateway</p>
        </div>
    </div>
</body>
</html>"""

    def _login_page(self, error: bool = False) -> str:
        """Standalone login page (also served at /cgi/login GET)."""
        msg = ''
        if error:
            msg = (
                '<div id="error-box">The username or password is incorrect. Please try again.</div>'
            )
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Citrix Gateway - Log On</title>
</head>
<body>
    <div id="login-container">
        <h1>NetScaler Gateway</h1>
        {msg}
        <form action="/cgi/login" method="post">
            <label for="login">User name</label>
            <input type="text" name="login" id="login" />
            <label for="passwd">Password</label>
            <input type="password" name="password" id="passwd" />
            <input type="submit" name="Log On" value="Log On" />
        </form>
    </div>
</body>
</html>"""

    def _nf_auth_page(self) -> str:
        """nFactor / WebAuth (nf) authentication page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Citrix Gateway - Authentication</title>
</head>
<body>
    <div id="auth-container">
        <h1>NetScaler Gateway</h1>
        <p>Please authenticate to continue.</p>
        <form action="/nf/auth/login.aspx" method="post">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" />
            <label for="password">Password</label>
            <input type="password" name="password" id="password" />
            <input type="submit" value="Continue" />
        </form>
    </div>
</body>
</html>"""

    def _logon_point_page(self) -> str:
        """StoreFront / LogonPoint authentication page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Citrix Receiver - Logon</title>
</head>
<body>
    <div id="logon-point">
        <h1>Citrix Receiver</h1>
        <form action="/logon/LogonPoint/Login" method="post">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" />
            <label for="password">Password</label>
            <input type="password" name="password" id="password" />
            <input type="submit" value="Sign In" />
        </form>
    </div>
</body>
</html>"""

    def _probe_response(self) -> str:
        """Benign body returned for CVE-2026-3055 out-of-bounds-read probes."""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            '</samlp:Status></samlp:AuthnRequest>'
        )

    def __repr__(self) -> str:
        return f'CitrixHandler(domain={self.domain!r})'
