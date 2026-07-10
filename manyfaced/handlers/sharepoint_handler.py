"""SharePointHandler — Microsoft SharePoint front-end honeypot face.

Provides realistic (log-and-respond) SharePoint responses for the high-value
probe paths bots and scanners hit:

  /_layouts/15/start.aspx        SharePoint "modern" start page
  /_layouts/                      15-mode + legacy _layouts pages
  /_api/                          SharePoint REST API (returns JSON {"d":{}})
  /_vti_bin/                      SharePoint Web Services front-end (/_vti_bin/sites.asmx)
  /webservices/                   legacy SOAP web services directory
  /login                          forms-based login (captures POST credentials)
  <CVE-2026-45659 probe path>     deserialization probe (200 to capture)

Full-fidelity emulation is NOT attempted — the goal is a believable front-end
that mentions "SharePoint", captures credentials submitted to /login, and
returns 200 for the CVE-2026-45659 deserialization probe so the attempt is
recorded in the bot's dialogue/profile.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)

# Hard-coded detected id for this face (do NOT touch status.py).
SHAREPOINT_HTTP = 1045

# CVE-2026-45659 deserialization probe path. Bots send a crafted request to
# this endpoint to trigger the unsafe deserialization; responding 200 lets us
# capture the payload in the bot profile without executing it.
CVE_2026_45659_PROBE = '/_layouts/15/cve-2026-45659/deserialize.aspx'


class SharePointHandler(HTTPHandlerBase):
    """Microsoft SharePoint honeypot handler (CVE-2026-45659 face)."""

    domain = 'sharepoint'
    DETECTED_ID = SHAREPOINT_HTTP

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a SharePoint response for the given request.

        Returns ``(response_bytes, detected_flag)``. Credentials posted to
        /login are extracted and captured in the bot profile; the
        CVE-2026-45659 deserialization probe path is answered 200 to capture
        the payload.
        """
        profile = self.get_or_create_profile(bot_ip)
        profile.record_request(
            {
                'path': path,
                'method': self._extract_method(raw_request),
                'headers': dict(headers) if headers else {},
                'raw': raw_request,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )

        method = self._extract_method(raw_request)
        path_lower = path.lower()

        # --- CVE-2026-45659 deserialization probe ---------------------------
        if CVE_2026_45659_PROBE.lower() in path_lower or 'cve-2026-45659' in path_lower:
            logger.info('CVE-2026-45659 deserialization probe captured from %s', bot_ip)
            body = self._cve_probe_response()
            response = self._build_http_response(body, path, status='200 OK')
            self._response_count += 1
            return response, self.DETECTED_ID

        # --- Login (capture POST credentials) -------------------------------
        if method == 'POST' and 'login' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                # Return a success page to encourage further probing.
                response = self._login_success_response(path)
                return response, detected
            # No usable creds — still answer with the login form (200).
            body = self._login_page()
            response = self._build_http_response(body, path, status='200 OK')
            self._response_count += 1
            return response, self.DETECTED_ID

        if 'login' in path_lower:
            body = self._login_page()
            response = self._build_http_response(body, path, status='200 OK')
            self._response_count += 1
            return response, self.DETECTED_ID

        # --- REST API -------------------------------------------------------
        if path_lower.startswith('/_api/'):
            body = self._api_response()
            response = self._build_http_response(
                body, path, status='200 OK', content_type='application/json;odata=verbose'
            )
            self._response_count += 1
            return response, self.DETECTED_ID

        # --- Web services (SOAP) --------------------------------------------
        if path_lower.startswith('/_vti_bin/') or path_lower.startswith('/webservices/'):
            body = self._webservices_response(path)
            response = self._build_http_response(
                body, path, status='200 OK', content_type='text/xml; charset=utf-8'
            )
            self._response_count += 1
            return response, self.DETECTED_ID

        # --- Layouts / start page -------------------------------------------
        if path_lower.startswith('/_layouts/'):
            if 'start.aspx' in path_lower:
                body = self._start_page()
            else:
                body = self._layouts_page(path)
            response = self._build_http_response(body, path, status='200 OK')
            self._response_count += 1
            return response, self.DETECTED_ID

        # --- Fallback front page --------------------------------------------
        body = self._home_page()
        response = self._build_http_response(body, path, status='200 OK')
        self._response_count += 1
        return response, self.DETECTED_ID

    # -- page builders ------------------------------------------------------

    def _home_page(self) -> str:
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Home - SharePoint</title>
    <script type="text/javascript">var _spPageContextInfo = {"webServerRelativeUrl":"/","webTitle":"Intranet"};</script>
</head>
<body>
    <div id="s4-workspace">
        <h1>Welcome to SharePoint</h1>
        <p>This is the home page of your SharePoint site.</p>
        <ul>
            <li><a href="/_layouts/15/start.aspx">Site contents</a></li>
            <li><a href="/_api/web">REST API</a></li>
            <li><a href="/login">Sign in</a></li>
        </ul>
    </div>
    <div id="footer">Microsoft SharePoint Foundation</div>
</body>
</html>"""

    def _start_page(self) -> str:
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>start - SharePoint</title>
    <script type="text/javascript">var _spPageContextInfo = {"webServerRelativeUrl":"/","webTitle":"Intranet"};</script>
</head>
<body>
    <div id="start-wrapper">
        <h1>SharePoint</h1>
        <p>Working on it...</p>
        <div id="loading-area">Loading site contents.</div>
    </div>
</body>
</html>"""

    def _layouts_page(self, path: str) -> str:
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>{path} - SharePoint</title>
</head>
<body>
    <h1>SharePoint</h1>
    <p>Application page: {path}</p>
    <p>Microsoft SharePoint Foundation application page.</p>
</body>
</html>"""

    def _login_page(self) -> str:
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Sign In - SharePoint</title>
</head>
<body class="ms-login">
    <div id="authBox">
        <h1>SharePoint</h1>
        <form id="loginForm" action="/login" method="post">
            <label for="username">User name</label>
            <input type="text" id="username" name="username" autocomplete="username" />
            <label for="password">Password</label>
            <input type="password" id="password" name="password" autocomplete="current-password" />
            <input type="submit" value="Sign in" />
        </form>
        <p class="ms-error" style="display:none;">Invalid credentials.</p>
    </div>
</body>
</html>"""

    def _login_success_response(self, path: str = '/login') -> bytes:
        """Fake login-success redirect (encourages further probing)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body = """\
<!DOCTYPE html>
<html lang="en">
<head><title>SharePoint</title></head>
<body><h1>SharePoint</h1><p>You are now signed in.</p></body>
</html>"""
        response = (
            f'HTTP/1.1 200 OK\r\n'
            f'Server: Microsoft-IIS/10.0\r\n'
            f'MicrosoftSharePointTeamServices: 16.0.0.12345\r\n'
            f'SPRequestGuid: {self._fake_guid()}\r\n'
            f'Set-Cookie: FedAuth=fake-fedauth-token-{self._fake_guid()}; path=/; HttpOnly\r\n'
            f'Set-Cookie: rtFa=fake-rtfa-token; path=/; HttpOnly\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: text/html; charset=utf-8\r\n'
            f'Content-Length: {len(body.encode("utf-8"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('utf-8')

    def _api_response(self) -> str:
        """Return a minimal SharePoint REST API envelope."""
        return '{"d":{}}'

    def _webservices_response(self, path: str) -> str:
        return f"""\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SharePointWebServices>
      <Endpoint>{path}</Endpoint>
      <Product>Microsoft SharePoint Foundation</Product>
    </SharePointWebServices>
  </soap:Body>
</soap:Envelope>"""

    def _cve_probe_response(self) -> str:
        """Answer the CVE-2026-45659 deserialization probe (200 to capture)."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head><title>SharePoint</title></head>
<body><h1>SharePoint</h1><p>Object deserialization endpoint acknowledged.</p></body>
</html>"""

    # -- helpers ------------------------------------------------------------

    def _extract_method(self, raw_request: str) -> str:
        parts = raw_request.split()
        if parts:
            return parts[0].upper()
        return 'GET'

    def _fake_guid(self) -> str:
        import uuid

        return str(uuid.uuid4())

    def _build_http_response(
        self,
        body: str,
        path: str,
        status: str = '200 OK',
        content_type: str = 'text/html; charset=utf-8',
    ) -> bytes:
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: Microsoft-IIS/10.0\r\n'
            f'MicrosoftSharePointTeamServices: 16.0.0.12345\r\n'
            f'X-SharePointHealthScore: 0\r\n'
            f'SPRequestGuid: {self._fake_guid()}\r\n'
            f'X-AspNet-Version: 4.0.30319\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body.encode("utf-8"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('utf-8')

    def __repr__(self) -> str:
        return f'SharePointHandler(domain={self.domain!r})'
