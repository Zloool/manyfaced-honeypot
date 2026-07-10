"""ColdFusionHandler – Adobe ColdFusion HTTP honeypot face.

Emulates an exposed Adobe ColdFusion instance (CF2023), including the
ColdFusion Administrator login, the /CFIDE/ and /cfusion/ web roots, the
/ccm/ component manager, and the historically-vulnerable graph / path-traversal
AJAX endpoints (CVE-2026-48282).

Credential POSTs (administrator login) are captured via the shared
credential extractor and stored in the bot's BotProfile.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)

# Adobe ColdFusion version advertised by this honeypot face.
CF_VERSION = '2023.0.0.330468'

# Hardcoded detected-id for the ColdFusion face. Do NOT edit status.py.
COLD_FUSION_DETECTED_ID = 1042


class ColdFusionHandler(HTTPHandlerBase):
    """Adobe ColdFusion honeypot handler."""

    domain = 'coldfusion'
    DETECTED_ID = COLD_FUSION_DETECTED_ID

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a ColdFusion response for the given request."""
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

        # Administrator login attempt (POST to the admin login endpoint).
        if method == 'POST' and (
            'administrator' in path_lower or 'cfide/administrator' in path_lower
        ):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                # Return a success redirect to encourage further probing.
                response = self._login_success_response()
                return response, detected

        # Route to the appropriate ColdFusion response surface.
        if 'administrator' in path_lower:
            body = self._administrator_login_page()
        elif 'cfide' in path_lower:
            body = self._cfide_page(path_lower)
        elif 'ccm' in path_lower:
            body = self._ccm_page()
        elif 'cfusion' in path_lower:
            body = self._cfusion_page(path_lower)
        elif 'cf_scripts' in path_lower or 'ajax' in path_lower:
            body = self._ajax_graph_page(path_lower)
        else:
            body = self._default_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

    # ------------------------------------------------------------------
    # Response builders
    # ------------------------------------------------------------------

    def _administrator_login_page(self) -> str:
        """ColdFusion Administrator login page."""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ColdFusion Administrator Login</title>
    <link rel="stylesheet" href="/cfide/administrator/css/login.css" type="text/css">
</head>
<body>
    <div id="container">
        <div id="logo">
            <img src="/cfide/administrator/images/cf-logo.png" alt="Adobe ColdFusion">
            <h1>ColdFusion Administrator</h1>
            <p class="version">Adobe ColdFusion {CF_VERSION}</p>
        </div>
        <form action="/CFIDE/administrator/enter.cfm" method="post" name="loginForm">
            <fieldset>
                <legend>Login</legend>
                <p>
                    <label for="cfadminPassword">Password:</label>
                    <input type="password" name="cfadminPassword" id="cfadminPassword" size="30" maxlength="50">
                </p>
                <p>
                    <label for="adminUserId">Username:</label>
                    <input type="text" name="adminUserId" id="adminUserId" size="30" maxlength="50" value="admin">
                </p>
                <p>
                    <label for="rememberMe">Remember me:</label>
                    <input type="checkbox" name="rememberMe" id="rememberMe" value="true">
                </p>
                <p class="submit">
                    <input type="submit" name="submit" value="Login">
                </p>
            </fieldset>
        </form>
        <p class="footer">Copyright &copy; 1985-2023 Adobe. All rights reserved.</p>
    </div>
</body>
</html>"""

    def _cfide_page(self, path_lower: str) -> str:
        """Generic /CFIDE/ surface (component browser, scripts, etc.)."""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>ColdFusion CFIDE</title></head>
<body>
    <h1>Adobe ColdFusion {CF_VERSION}</h1>
    <p>/CFIDE/ component path requested.</p>
    <ul>
        <li><a href="/CFIDE/administrator/">ColdFusion Administrator</a></li>
        <li><a href="/CFIDE/componentutils/">Component Browser</a></li>
        <li><a href="/CFIDE/debug/">Debugging</a></li>
        <li><a href="/cf_scripts/scripts/ajax/">Ajax root</a></li>
    </ul>
</body>
</html>"""

    def _ccm_page(self) -> str:
        """ColdFusion Component Manager (/ccm/) surface."""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>ColdFusion Component Manager</title></head>
<body>
    <h1>ColdFusion Component Manager</h1>
    <p>Adobe ColdFusion {CF_VERSION}</p>
    <p>The ColdFusion Component Manager (CCM) exposes server-side component
    metadata and graph traversal for the ORM layer.</p>
</body>
</html>"""

    def _cfusion_page(self, path_lower: str) -> str:
        """ColdFusion internal /cfusion/ graph / export endpoints.

        Covers the vulnerable graph path-traversal / __export RCE surface
        (CVE-2026-48282). When a graph or export path is hit we still return
        a plausible body so the request completes.
        """
        if '__export' in path_lower or 'graph' in path_lower:
            return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>ColdFusion Graph Service</title></head>
<body>
    <h1>ColdFusion Graph Service</h1>
    <p>Adobe ColdFusion {CF_VERSION}</p>
    <p>Serialization endpoint ready. Format accepted: json, xml.</p>
</body>
</html>"""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>ColdFusion Internal</title></head>
<body>
    <h1>ColdFusion Internal Web Root</h1>
    <p>Adobe ColdFusion {CF_VERSION}</p>
</body>
</html>"""

    def _ajax_graph_page(self, path_lower: str) -> str:
        """ColdFusion AJAX / cf_scripts surface (Spry, graph, proxy)."""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>ColdFusion Ajax</title></head>
<body>
    <h1>ColdFusion Ajax / Spry</h1>
    <p>Adobe ColdFusion {CF_VERSION}</p>
    <p>cf_scripts/scripts/ajax proxy and graph services available.</p>
</body>
</html>"""

    def _default_page(self) -> str:
        """Default ColdFusion landing page."""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>Adobe ColdFusion {CF_VERSION}</title></head>
<body>
    <h1>Adobe ColdFusion {CF_VERSION}</h1>
    <p>ColdFusion Markup Language (CFML) application server is running.</p>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_credentials(
        self, raw_request: str, headers: dict[str, str]
    ) -> dict[str, str] | None:
        """Extract credentials, including ColdFusion-specific field names.

        Falls back to the shared extractor (``adminUserId`` / ``cfadminPassword``
        are not in its default field list), then handles the ColdFusion
        Administrator login form fields directly.
        """
        creds = super()._extract_credentials(raw_request, headers)
        if creds:
            return creds

        parts = raw_request.split()
        if len(parts) < 1 or parts[0].upper() != 'POST':
            return None

        split = raw_request.split('\r\n\r\n', 1)
        if len(split) < 2:
            return None
        from urllib.parse import unquote_plus  # noqa: PLC0415

        body = unquote_plus(split[1])

        username = None
        password = None
        for field in ('adminUserId', 'username', 'user', 'login', 'email'):
            prefix = field + '='
            if prefix in body:
                username = body.split(prefix, 1)[1].split('&', 1)[0] or None
                if username:
                    break
        for field in ('cfadminPassword', 'password', 'pass', 'pwd'):
            prefix = field + '='
            if prefix in body:
                password = body.split(prefix, 1)[1].split('&', 1)[0] or None
                if password:
                    break

        result: dict[str, str] = {}
        if username:
            result['username'] = username
        if password:
            result['password'] = password
        return result or None

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _login_success_response(self) -> bytes:
        """Return a fake admin login success redirect."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body = (
            f'<html><body><h1>ColdFusion Administrator</h1>'
            f'<p>Welcome to Adobe ColdFusion {CF_VERSION}.</p></body></html>'
        )
        response = (
            f'HTTP/1.1 302 Found\r\n'
            f'Server: Microsoft-IIS/10.0\r\n'
            f'Date: {now}\r\n'
            f'Location: /CFIDE/administrator/index.cfm\r\n'
            f'Content-Type: text/html;charset=UTF-8\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def _build_http_response(self, body: str, path: str, status: str = '200 OK') -> bytes:
        """Build a complete HTTP/1.1 response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: Microsoft-IIS/10.0\r\n'
            f'X-Powered-By: ASP.NET\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: text/html;charset=UTF-8\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'ColdFusionHandler(domain={self.domain!r})'
