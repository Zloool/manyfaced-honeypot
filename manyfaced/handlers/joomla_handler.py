"""JoomlaHandler – honeypot handler for the Joomla! CMS.

Emulates a Joomla! 5.x installation to attract and study bots probing for:

- The administrator login panel (``/administrator/``)
- Front-end content (``/``, ``/index.php``)
- Common component / template / API / language paths
- The SP Page Builder media upload endpoint
  (``index.php?option=com_sppagebuilder``) — CVE-2026-48908
- Unauthenticated privilege escalation via the same builder — CVE-2026-56290

Credentials submitted to login / upload endpoints are captured into the
bot's :class:`BotProfile` to study credential-stuffing and exploit payloads.

This face is intentionally self-contained: ``DETECTED_ID`` is hardcoded here
and is NOT imported from ``manyfaced.common.status`` (kept consistent with the
issue scaffolding that adds a fresh face without touching shared status tables).
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


# Hardcoded detected-id for the Joomla face. Intentionally not imported from
# manyfaced.common.status to avoid touching shared status tables for this new face.
JOOMLA_DETECTED_ID = 1040


class JoomlaHandler(HTTPHandlerBase):
    """Honeypot handler that impersonates a Joomla! 5.x installation."""

    domain = 'joomla'
    DETECTED_ID = JOOMLA_DETECTED_ID

    # Joomla version advertised across responses (5.x line).
    JOOMLA_VERSION = '5.2.3'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Joomla-flavored HTTP response for the given request.

        Args:
            path: The URL path (query string already stripped & lower-cased by router).
            raw_request: The raw HTTP request string.
            bot_ip: The bot's IP address.
            headers: Request headers (or None).

        Returns:
            Tuple of (response_bytes, detected_flag).
        """
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

        # --- Credential capture on POST to login / upload endpoints -----------
        login_paths = ('/administrator', '/index.php')
        is_login_post = method == 'POST' and (
            'com_login' in path_lower
            or 'option=com_users' in path_lower
            or 'option=com_sppagebuilder' in path_lower
            or path_lower == '/administrator/index.php'
            or path_lower == '/administrator/'
            or path_lower in login_paths
        )
        if is_login_post:
            creds = self._extract_credentials(raw_request, headers or {})
            if creds:
                self.get_or_create_profile(bot_ip).capture_credentials(creds)
                # Encourage further probing with a "success" redirect.
                return self._build_http_response(
                    self._upload_success_body(),
                    path,
                    status='302 Found',
                    extra_headers={'Location': '/administrator/index.php'},
                ), self.DETECTED_ID

        # --- Route by path ----------------------------------------------------
        if path_lower.startswith('/administrator'):
            body = self._admin_login_page()
        elif 'option=com_sppagebuilder' in path_lower:
            body = self._sppagebuilder_upload_page()
        elif path_lower.startswith('/templates'):
            body = self._templates_page()
        elif path_lower.startswith('/components'):
            body = self._components_page()
        elif path_lower.startswith('/api'):
            body = self._api_page()
        elif path_lower.startswith('/language'):
            body = self._language_page()
        elif path_lower in ('/', '/index.php', '/index.php/'):
            body = self._front_page()
        else:
            # Unknown Joomla path — fall back to the front page.
            body = self._front_page()

        response = self._build_http_response(body, path)
        self._response_count += 1
        return response, self.DETECTED_ID

    # -- Page bodies ----------------------------------------------------------

    def _admin_login_page(self) -> str:
        """Render the Joomla administrator login page with a fake form."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head>
    <meta charset="utf-8">
    <title>Administration - My Joomla! Site</title>
    <link href="/media/system/css/login.css" rel="stylesheet">
</head>
<body class="com_login login">
    <div id="container">
        <div id="header">
            <h1>My Joomla! Site</h1>
            <span class="version">Joomla! {self.JOOMLA_VERSION}</span>
        </div>
        <div id="content">
            <h2>Log in</h2>
            <form action="/administrator/index.php" method="post" id="form-login">
                <fieldset>
                    <label for="mod-login-username">User Name</label>
                    <input name="username" id="mod-login-username" type="text" size="25" autofocus>
                    <label for="mod-login-password">Password</label>
                    <input name="password" id="mod-login-password" type="password" size="25">
                    <input type="hidden" name="option" value="com_login">
                    <input type="hidden" name="task" value="login">
                    <input type="hidden" name="{self._token_name()}" value="{self._token_value()}">
                </fieldset>
                <div id="form-login-submit">
                    <button class="btn btn-primary btn-block btn-large">Log in</button>
                </div>
            </form>
        </div>
        <div id="footer">
            <p>Powered by <a href="https://www.joomla.org">Joomla! {self.JOOMLA_VERSION}</a></p>
        </div>
    </div>
</body>
</html>"""

    def _front_page(self) -> str:
        """Render the Joomla front-end home page."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head>
    <meta charset="utf-8">
    <title>My Joomla! Site</title>
    <meta name="generator" content="Joomla! - Open Source Content Management">
</head>
<body class="site">
    <header>
        <h1><a href="/">My Joomla! Site</a></h1>
    </header>
    <main>
        <h2>Welcome to My Joomla! Site</h2>
        <p>This site is powered by Joomla! {self.JOOMLA_VERSION}.</p>
        <nav>
            <a href="/index.php">Home</a>
            <a href="/administrator/">Administrator</a>
            <a href="/components">Components</a>
            <a href="/templates">Templates</a>
            <a href="/api/index.php">API</a>
        </nav>
    </main>
    <footer>
        <p>Powered by <a href="https://www.joomla.org">Joomla! {self.JOOMLA_VERSION}</a></p>
    </footer>
</body>
</html>"""

    def _sppagebuilder_upload_page(self) -> str:
        """Render the SP Page Builder media upload endpoint response."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head><title>SP Page Builder - Media Upload</title></head>
<body>
    <div id="sp-page-builder" class="sppb-media">
        <h1>SP Page Builder {self.JOOMLA_VERSION}</h1>
        <form action="index.php?option=com_sppagebuilder&task=media.upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" id="sppb-media-upload">
            <input type="hidden" name="option" value="com_sppagebuilder">
            <input type="hidden" name="task" value="media.upload">
            <input type="hidden" name="{self._token_name()}" value="{self._token_value()}">
            <button type="submit">Upload</button>
        </form>
    </div>
</body>
</html>"""

    def _templates_page(self) -> str:
        """Render a response for the templates path."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head><title>Templates - My Joomla! Site</title></head>
<body>
    <h1>Joomla! Templates</h1>
    <p>Joomla! {self.JOOMLA_VERSION} template directory.</p>
    <ul>
        <li>/templates/cassiopeia/</li>
        <li>/templates/system/</li>
    </ul>
</body>
</html>"""

    def _components_page(self) -> str:
        """Render a response for the components path."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head><title>Components - My Joomla! Site</title></head>
<body>
    <h1>Joomla! Components</h1>
    <p>Joomla! {self.JOOMLA_VERSION} component directory.</p>
    <ul>
        <li>/components/com_content/</li>
        <li>/components/com_users/</li>
        <li>/components/com_sppagebuilder/</li>
    </ul>
</body>
</html>"""

    def _api_page(self) -> str:
        """Render a response for the API path."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head><title>API - My Joomla! Site</title></head>
<body>
    <h1>Joomla! Web Services API</h1>
    <p>Joomla! {self.JOOMLA_VERSION} REST API endpoint. Send a Bearer token.</p>
    <pre>{{"error":false,"api":"Joomla","version":"{self.JOOMLA_VERSION}"}}</pre>
</body>
</html>"""

    def _language_page(self) -> str:
        """Render a response for the language path."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head><title>Language - My Joomla! Site</title></head>
<body>
    <h1>Joomla! Language Files</h1>
    <p>Joomla! {self.JOOMLA_VERSION} language directory.</p>
    <ul>
        <li>/language/en-GB/</li>
        <li>/administrator/language/en-GB/</li>
    </ul>
</body>
</html>"""

    def _upload_success_body(self) -> str:
        """Body returned alongside a 302 after a successful credential capture."""
        return f"""\
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head><title>Redirecting...</title></head>
<body>
    <h1>Joomla! {self.JOOMLA_VERSION}</h1>
    <p>Redirecting to the administrator dashboard...</p>
</body>
</html>"""

    # -- Helpers --------------------------------------------------------------

    def _token_name(self) -> str:
        return f'{self._csrf_token()[:1].lower()}token'

    def _token_value(self) -> str:
        return self._csrf_token()

    @staticmethod
    def _csrf_token() -> str:
        return '1' + 'a2b3c4d5e6f7'  # deterministic fake token

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from the raw request line."""
        parts = raw_request.split()
        if parts:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        path: str,
        status: str = '200 OK',
        extra_headers: dict[str, str] | None = None,
    ) -> bytes:
        """Emit a valid HTTP/1.1 response byte string.

        Header block::

            HTTP/1.1 <status>
            Server: ...
            Content-Type: text/html; charset=utf-8
            Content-Length: N
            Connection: close

        followed by the body. ``Content-Length`` is computed from the UTF-8
        encoded body.
        """
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('utf-8')

        header_lines = [
            f'HTTP/1.1 {status}',
            'Server: Apache/2.4.58 (Debian)',
            'X-Powered-By: PHP/8.2.18',
            'X-Content-Type-Options: nosniff',
            f'Date: {now}',
            'Content-Type: text/html; charset=utf-8',
            f'Content-Length: {len(body_bytes)}',
            'Connection: close',
        ]
        if extra_headers:
            for key, value in extra_headers.items():
                header_lines.append(f'{key}: {value}')

        header_block = '\r\n'.join(header_lines) + '\r\n\r\n'
        return header_block.encode('utf-8') + body_bytes

    def __repr__(self) -> str:
        return f'JoomlaHandler(domain={self.domain!r})'
