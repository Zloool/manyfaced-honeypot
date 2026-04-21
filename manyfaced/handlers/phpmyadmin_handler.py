"""PhpMyAdminHandler – handles phpMyAdmin-specific paths and interactions.

Provides realistic phpMyAdmin responses including:
- Login page (/phpmyadmin/, /pma/, /mysql/)
- Database management pages
- Captures login credentials from POST requests
- Returns realistic error pages for unavailable endpoints
"""

from __future__ import annotations

import datetime
import logging
from typing import Any

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class PhpMyAdminHandler(HTTPHandlerBase):
    """phpMyAdmin honeypot handler."""

    domain = "phpmyadmin"
    PATH_PATTERNS = [
        "/phpmyadmin", "/phpmyadmin/", "/phpmyadmin/index.php",
        "/pma", "/pma/", "/pma/index.php",
        "/mysql", "/mysql/", "/mysql/index.php",
        "/db", "/db/", "/db/index.php",
        "/database", "/database/", "/database/index.php",
    ]
    DETECTED_ID = 1

    def matches_path(self, path: str) -> bool:
        """Check if this handler should handle the given path."""
        path_lower = path.lower().split("?")[0]
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

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
            "path": path,
            "method": self._extract_method(raw_request),
            "headers": dict(headers) if headers else {},
            "raw": raw_request,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        path_lower = path.lower()

        # Handle login POST requests
        if method == "POST" and ("index.php" in path_lower or path_lower.endswith("/")):
            credentials, response, detected = self.handle_login(path, raw_request, bot_ip, headers or {})
            if credentials:
                # Fake "access denied" response (encourages more attempts)
                response = self._login_denied_response()
                return response, detected

        # Route to appropriate response
        if "index.php" in path_lower or path_lower.endswith("/"):
            body = self._login_page()
        elif "export.php" in path_lower or "sql.php" in path_lower:
            body = self._error_page("endpoint")
        elif "server_status.php" in path_lower:
            body = self._error_page("endpoint")
        elif "db_structure.php" in path_lower or "db_sql.php" in path_lower:
            body = self._error_page("database")
        else:
            body = self._login_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

    def _login_page(self) -> str:
        """Generate a phpMyAdmin login page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>phpMyAdmin - Login</title>
    <link rel="stylesheet" href="themes/dot.css" type="text/css">
    <link rel="stylesheet" href="scripts/normalize.css" type="text/css">
</head>
<body class="index page-setup">
    <div id="pma_navigation">
        <div class="pma_navigation_header">
            <h2>phpMyAdmin 5.2.1</h2>
        </div>
    </div>
    <div id="pma_content">
        <div class="container">
            <h1>phpMyAdmin - Login</h1>
            <form method="post" action="index.php" name="login_form" id="loginForm" class="ajax">
                <fieldset class="dbinfo">
                    <legend>Login</legend>
                    <table>
                        <tr>
                            <td><label for="input_server">Server:</label></td>
                            <td>
                                <select name="server" id="input_server">
                                    <option value="0" selected>localhost</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td><label for="input_username">Username:</label></td>
                            <td><input type="text" name="pma_username" id="input_username" value="" autocomplete="off"></td>
                        </tr>
                        <tr>
                            <td><label for="input_password">Password:</label></td>
                            <td><input type="password" name="pma_password" id="input_password" autocomplete="off"></td>
                        </tr>
                        <tr>
                            <td colspan="2">
                                <input type="checkbox" name="is_js_required" value="1" id="is_js_required" checked disabled>
                                <label for="is_js_required">JavaScript is required for full functionality. Some features are disabled.</label>
                            </td>
                        </tr>
                    </table>
                    <input type="hidden" name="server" value="0">
                    <input type="hidden" name="token" value="a1b2c3d4e5f6g7h8i9j0">
                    <input type="submit" value="Go" id="button_go">
                </fieldset>
            </form>
            <div class="error">
                <p>Warning: mysqli extension is not loaded or not configured properly.</p>
                <p>Warning: The configuration file now needs a secret passphrase (blowfish_secret).</p>
            </div>
        </div>
    </div>
    <div id="pma_footer">
        <span class="version">phpMyAdmin 5.2.1</span>
        <span> | </span>
        <span>Server: localhost via TCP/IP</span>
        <span> | </span>
        <span>PHP Version: 8.2.15-1ubuntu2.11</span>
        <span> | </span>
        <span>MySQL Version: 8.0.36-0ubuntu0.22.04.1</span>
    </div>
</body>
</html>"""

    def _login_denied_response(self) -> bytes:
        """Return a fake login denied response."""
        body = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>phpMyAdmin - Error</title>
</head>
<body>
    <div id="pma_content">
        <div class="container">
            <h1>phpMyAdmin 5.2.1</h1>
            <div class="error">
                <p><strong> mysqli</strong></p>
                <p>Access denied for user 'root'@'localhost' (using password: YES)</p>
            </div>
            <form method="post" action="index.php" name="login_form" id="loginForm">
                <fieldset>
                    <legend>Login</legend>
                    <table>
                        <tr>
                            <td><label for="input_username">Username:</label></td>
                            <td><input type="text" name="pma_username" id="input_username" value="" autocomplete="off"></td>
                        </tr>
                        <tr>
                            <td><label for="input_password">Password:</label></td>
                            <td><input type="password" name="pma_password" id="input_password" autocomplete="off"></td>
                        </tr>
                    </table>
                    <input type="hidden" name="server" value="0">
                    <input type="submit" value="Go" id="button_go">
                </fieldset>
            </form>
            <p class="debug">Server: localhost via TCP/IP | PHP Version: 8.2.15-1ubuntu2.11 | MySQL Version: 8.0.36-0ubuntu0.22.04.1</p>
        </div>
    </div>
</body>
</html>"""
        return self._build_http_response(body, "/phpmyadmin/index.php")

    def _error_page(self, error_type: str = "general") -> str:
        """Generate a phpMyAdmin error page."""
        if error_type == "endpoint":
            return """\
<!DOCTYPE html>
<html>
<head><title>phpMyAdmin - Error</title></head>
<body>
    <div id="pma_content">
        <h2>phpMyAdmin 5.2.1</h2>
        <div class="error">
            <p>The requested endpoint is not available.</p>
            <p>Available endpoints:</p>
            <ul>
                <li><a href="index.php">Login</a></li>
                <li><a href="export.php">Export</a></li>
                <li><a href="sql.php">SQL Query</a></li>
                <li><a href="server_status.php">Server Status</a></li>
            </ul>
            <p class="debug">Server: localhost via TCP/IP | PHP Version: 8.2.15-1ubuntu2.11 | MySQL Version: 8.0.36-0ubuntu0.22.04.1</p>
        </div>
    </div>
</body>
</html>"""
        return """\
<!DOCTYPE html>
<html>
<head><title>phpMyAdmin - Error</title></head>
<body>
    <div id="pma_content">
        <h2>phpMyAdmin 5.2.1</h2>
        <div class="error">
            <p>An error has occurred:</p>
            <p>MySQL server has gone away</p>
            <p class="debug">Error: Connection refused (111)</p>
            <p class="debug">Server: localhost via TCP/IP | PHP Version: 8.2.15-1ubuntu2.11</p>
        </div>
    </div>
</body>
</html>"""

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _build_http_response(self, body: str, path: str, status: str = "200 OK") -> bytes:
        """Build a complete HTTP response."""
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: Apache/2.4.57 (Ubuntu)\r\n"
            f"X-Powered-By: PHP/8.2.15-1ubuntu2.11\r\n"
            f"Set-Cookie: phpMyAdmin=abc123def456; path=/\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return f"PhpMyAdminHandler(domain={self.domain!r})"
