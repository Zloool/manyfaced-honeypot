"""AtlassianHandler – impersonates Atlassian Confluence / Jira.

Provides realistic Atlassian responses including:
- Confluence / Jira login pages (/login, /wiki, /confluence, /jira)
- Jira secure dashboard redirect (/secure/Dashboard.jspa)
- Confluence / Jira REST API JSON (/rest/api/...)
- Captures login credentials from POST requests
- Returns realistic error pages

Atlassian Confluence and Jira are widely targeted by bots scanning for
exposed instances, weak credentials, and known CVEs (e.g. CVE-2021-26084 /
CVE-2022-26138). This face emulates the login + REST surface so probes see a
believable instance.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import ATLASSIAN_HTTP

logger = logging.getLogger(__name__)


class AtlassianHandler(HTTPHandlerBase):
    """Confluence / Jira honeypot handler."""

    domain = 'atlassian'
    DETECTED_ID = ATLASSIAN_HTTP
    VERSION = '9.4.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an Atlassian response for the given request."""
        # Decode common path-escape probes (%2e -> '.', %2f -> '/')
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

        # Handle login POST requests (credential capture)
        if method == 'POST' and ('login' in path_lower or 'auth' in path_lower):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Route to the appropriate response
        if path_lower.startswith('/rest/'):
            body = self._rest_api_response(path)
            return self._build_http_response(
                body, 200, 'OK', 'application/json; charset=UTF-8'
            ), self.DETECTED_ID

        if path_lower == '/atlassian/.env' or path_lower.startswith('/atlassian/%2eenv'):
            return self._not_found_response(), self.DETECTED_ID

        # All other Atlassian surface paths get the login page
        body = self._login_page(path_lower)
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------ pages

    def _login_page(self, path_lower: str = '') -> str:
        """Confluence / Jira login HTML page with Atlassian branding."""
        product = 'Jira' if 'jira' in path_lower or 'secure' in path_lower else 'Confluence'
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log in to {product} | Atlassian</title>
<link rel="stylesheet" type="text/css" href="/atlassian/css/atlassian-reset.css">
<link rel="stylesheet" type="text/css" href="/s/atlassian-core.css">
<script type="text/javascript" src="/atlassian/js/atl-general.js"></script>
</head>
<body class="atlassian-page">
<div id="header">
    <div class="logo">
        <a href="/wiki"><img src="/atlassian/logo.png" alt="Atlassian" width="160"></a>
    </div>
</div>
<div id="content">
    <div class="login-container">
        <h1>Log in to {product}</h1>
        <p class="subtitle">Atlassian {product} {self.VERSION}</p>
        <form method="POST" action="/login" name="loginform" id="login-form">
            <input type="hidden" name="os_destination" value="/">
            <input type="hidden" name="atl_token" value="fake-token-0000">
            <div class="form-group">
                <label for="os_username">Username</label>
                <input type="text" name="os_username" id="os_username" class="text" autocomplete="off">
            </div>
            <div class="form-group">
                <label for="os_password">Password</label>
                <input type="password" name="os_password" id="os_password" class="password">
            </div>
            <div class="form-group checkbox">
                <input type="checkbox" name="os_cookie" id="os_cookie" value="true">
                <label for="os_cookie">Remember me</label>
            </div>
            <div class="form-actions">
                <input type="submit" name="login" value="Log in" class="aui-button">
            </div>
        </form>
        <div class="login-links">
            <a href="/login/reset">Can't access your account?</a>
        </div>
    </div>
</div>
<div id="footer">
    <p>&copy; 2024 Atlassian. Confluence and Jira are registered trademarks.</p>
    <p>Atlassian Confluence {self.VERSION} (build #9400)</p>
</div>
</body>
</html>"""

    def _rest_api_response(self, path: str) -> str:
        """Return a believable Confluence / Jira REST API JSON response."""
        path_lower = path.lower()
        if 'content' in path_lower:
            return (
                '{"results":['
                '{"id":"12345","type":"page","title":"Welcome to Confluence",'
                '"space":{"key":"DS","name":"Demonstration Space"},'
                '"version":{"number":7}},'
                '{"id":"67890","type":"blogpost","title":"Release Notes",'
                '"space":{"key":"REL","name":"Releases"},"version":{"number":2}}'
                '],"start":0,"limit":25,"size":2}'
            )
        # Default: a single Jira issue descriptor
        return (
            '{"expand":"renderedFields,names,schema,operations,editmeta,'
            'changelog,versionedRepresentations","id":"10001",'
            '"self":"https://example.atlassian.net/rest/api/2/issue/10001",'
            '"key":"PROJ-1","fields":{"summary":"Example issue",'
            '"issuetype":{"name":"Task"},"status":{"name":"To Do"},'
            '"priority":{"name":"Medium"},"project":{"key":"PROJ",'
            '"name":"Sample Project"}}}'
        )

    def _not_found_response(self) -> bytes:
        """404 Not Found for disclosure probes (e.g. /atlassian/.env)."""
        body = (
            '<!DOCTYPE html><html><head><title>404 Not Found</title></head>'
            '<body><h1>404 Not Found</h1>'
            '<p>The requested URL was not found on this Atlassian server.</p>'
            '</body></html>'
        )
        return self._build_http_response(body, 404, 'Not Found')

    def _login_failed_response(self) -> bytes:
        """Login failed response — encourages further probing."""
        body = (
            '<!DOCTYPE html><html><head><title>Login Error</title></head>'
            '<body><h3>Authorization Error</h3>'
            '<p>Invalid username or password. Please try again.</p>'
            '<p><a href="/login">Return to login page</a></p></body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    # ----------------------------------------------------------------- helpers

    def _normalize_path(self, path: str) -> str:
        """Decode common path-escape probes (%2e -> '.', %2f -> '/')."""
        return path.replace('%2e', '.').replace('%2E', '.').replace('%2f', '/').replace('%2F', '/')

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
        """Build a complete HTTP response (encoded as iso-8859-1)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('iso-8859-1')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\\r\\n'
            f'Server: Atlassian Confluence/{self.VERSION}\\r\\n'
            f'X-Confluence-Request-Time: {now}\\r\\n'
            f'X-AREQUESTID: fake-req-{self.DETECTED_ID}\\r\\n'
            f'X-Frame-Options: SAMEORIGIN\\r\\n'
            f'X-Content-Type-Options: nosniff\\r\\n'
            f'Date: {now}\\r\\n'
            f'Content-Type: {content_type}\\r\\n'
            f'Content-Length: {len(body_bytes)}\\r\\n'
            f'Connection: close\\r\\n'
            f'\\r\\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'AtlassianHandler(domain={self.domain!r})'
