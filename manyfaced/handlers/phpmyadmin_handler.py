"""PhpMyAdminHandler – handles phpMyAdmin-specific paths and interactions.

Provides realistic phpMyAdmin responses including:
- The phpMyAdmin login UI (/phpmyadmin, /phpMyAdmin, /pma, /index.php, /)
- A fake SQL endpoint (/sql.php) that echoes a realistic query result
- A fake environment disclosure for the /.env probe (/phpmyadmin/%2eenv)
- Captures login credentials from POST requests
- Returns a realistic "access denied" error page for failed logins

phpMyAdmin is one of the most heavily probed web DB admin tools on the
internet (alongside Adminer), targeted by credential-stuffing and exploit bots.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from urllib.parse import unquote

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import PHPMYADMIN_HTTP

logger = logging.getLogger(__name__)


class PhpMyAdminHandler(HTTPHandlerBase):
    """Handles phpMyAdmin honeypot responses."""

    domain = 'phpmyadmin'
    DETECTED_ID = PHPMYADMIN_HTTP
    VERSION = '5.2.1'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a phpMyAdmin response for the given request."""
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

        # Decode URL-encoded path segments (probes use %2e -> '.', %2f -> '/').
        decoded_path = unquote(path)

        # Handle login POST requests (credentials captured by base handler).
        if method == 'POST':
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                # Fake "access denied" response (encourages more attempts).
                response = self._login_failed_response()
                return response, detected

        # Route to the appropriate response body.
        path_lower = decoded_path.lower()

        if path_lower.endswith('/%2eenv') or path_lower.endswith('/.env'):
            body = self._env_disclosure()
            content_type = 'text/plain; charset=UTF-8'
        elif 'sql.php' in path_lower:
            body = self._sql_endpoint()
            content_type = 'text/html; charset=UTF-8'
        else:
            # Default: the phpMyAdmin login page.
            body = self._login_page()
            content_type = 'text/html; charset=UTF-8'

        return self._build_http_response(body, content_type), self.DETECTED_ID

    # ------------------------------------------------------------------
    # Response bodies
    # ------------------------------------------------------------------

    def _login_page(self) -> str:
        """Generate the phpMyAdmin login page (logo, title, login form)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>phpMyAdmin """ + self.VERSION + """ - Login</title>
    <link rel="stylesheet" type="text/css" href="phpmyadmin.css.php?nocache=1">
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <style>
        body { font-family: "Segoe UI", Tahoma, sans-serif; background: #f3f3f3; margin: 0; }
        #page_content { max-width: 420px; margin: 60px auto; background: #fff;
                        border: 1px solid #ddd; border-radius: 4px; padding: 24px; }
        h1 { font-size: 20px; color: #2c3e50; }
        .logo { text-align: center; margin-bottom: 12px; }
        .logo img { height: 48px; }
        label { display: block; margin: 10px 0 4px; color: #555; font-size: 13px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px;
                        border: 1px solid #ccc; border-radius: 3px; box-sizing: border-box; }
        input[type="submit"] { margin-top: 16px; width: 100%; padding: 9px;
                        background: #337ab7; color: #fff; border: 0; border-radius: 3px;
                        cursor: pointer; font-size: 14px; }
        .error { color: #a94442; background: #f2dede; border: 1px solid #ebccd1;
                        padding: 8px; border-radius: 3px; margin-top: 12px; font-size: 13px; }
        .server-info { color: #888; font-size: 12px; margin-top: 16px; text-align: center; }
    </style>
</head>
<body>
    <div id="page_content">
        <div class="logo">
            <img src="themes/dot.gif" alt="phpMyAdmin">
        </div>
        <h1>phpMyAdmin """ + self.VERSION + """</h1>
        <form method="post" action="index.php" name="login_form" id="login_form">
            <input type="hidden" name="token" value="3f9a1c7b2e4d5f60817293a4b5c6d7e8">
            <label for="input_username">Username:</label>
            <input type="text" name="pma_username" id="input_username" value="" autocomplete="off">
            <label for="input_password">Password:</label>
            <input type="password" name="pma_password" id="input_password" autocomplete="off">
            <label for="input_server">Server:</label>
            <select name="server" id="input_server">
                <option value="0" selected>localhost:3306</option>
            </select>
            <input type="submit" value="Log in" id="button_go">
        </form>
        <div class="server-info">
            Server: localhost via TCP/IP &middot; PHP 8.2.15 &middot; MySQL 8.0.36
        </div>
    </div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Return a fake 'access denied' login response (contains 'Error')."""
        body = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>phpMyAdmin """ + self.VERSION + """ - Error</title>
</head>
<body>
    <div id="page_content">
        <h1>phpMyAdmin """ + self.VERSION + """</h1>
        <div class="error">
            <strong>Error</strong>
            <p>#1045 - Access denied for user 'root'@'localhost' (using password: YES)</p>
        </div>
        <form method="post" action="index.php" name="login_form" id="login_form">
            <input type="hidden" name="token" value="3f9a1c7b2e4d5f60817293a4b5c6d7e8">
            <label for="input_username">Username:</label>
            <input type="text" name="pma_username" id="input_username" value="" autocomplete="off">
            <label for="input_password">Password:</label>
            <input type="password" name="pma_password" id="input_password" autocomplete="off">
            <input type="submit" value="Log in" id="button_go">
        </form>
    </div>
</body>
</html>"""
        return self._build_http_response(body, 'text/html; charset=UTF-8')

    def _sql_endpoint(self) -> str:
        """Fake phpMyAdmin SQL query endpoint response."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>phpMyAdmin """ + self.VERSION + """ - SQL</title>
</head>
<body>
    <h1>phpMyAdmin """ + self.VERSION + """</h1>
    <div id="sqlqueryresults">
        <table class="data">
            <caption>1 row(s) returned</caption>
            <thead><tr><th>id</th><th>name</th></tr></thead>
            <tbody><tr><td>1</td><td>localhost</td></tr></tbody>
        </table>
    </div>
    <p class="server-info">Server: localhost via TCP/IP &middot; MySQL 8.0.36</p>
</body>
</html>"""

    def _env_disclosure(self) -> str:
        """Fake environment / .env disclosure for the /.env probe."""
        return (
            "# phpMyAdmin environment configuration (fake)\n"
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            "PMA_VERSION=" + self.VERSION + "\n"
            "DB_HOST=127.0.0.1\n"
            "DB_PORT=3306\n"
            "DB_NAME=phpmyadmin\n"
            "DB_USER=root\n"
            "DB_PASSWORD=Sup3rSecret!PMA\n"
            "BLOWFISH_SECRET=4f1c8a9b2e7d6c5a4039281746553f1b\n"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        content_type: str = 'text/html; charset=UTF-8',
        status_code: int = 200,
        status_text: str = 'OK',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('iso-8859-1')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Date: {now}\r\n'
            f'Server: Apache/2.4.57 (Ubuntu)\r\n'
            f'X-Powered-By: PHP/8.2.15\r\n'
            f'Set-Cookie: phpMyAdmin=1abc2def3ghi4jkl5mno; path=/; HttpOnly\r\n'
            f'Expires: Thu, 19 Nov 1981 08:52:00 GMT\r\n'
            f'Cache-Control: no-store, no-cache, must-revalidate\r\n'
            f'Pragma: no-cache\r\n'
            f'X-Frame-Options: DENY\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'PhpMyAdminHandler(domain={self.domain!r})'
