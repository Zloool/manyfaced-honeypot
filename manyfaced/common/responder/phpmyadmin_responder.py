"""
phpMyAdmin responder module.

Generates realistic phpMyAdmin responses that encourage deeper exploitation.
Adapts responses based on the bot's behavior and escalation level.

Usage:
    from manyfaced.common.responder.phpmyadmin_responder import PhpMyAdminResponder

    responder = PhpMyAdminResponder(ai_responder=ai_responder)
    response_bytes, detected = responder.generate_response(
        path="/phpmyadmin/",
        raw_request="GET /phpmyadmin/ HTTP/1.1...",
        bot_ip="1.2.3.4",
    )
"""

from __future__ import annotations

import datetime

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.responder.responder_base import ResponderBase

logger = get_logger(__name__)


class PhpMyAdminResponder(ResponderBase):
    """phpMyAdmin honeypot responder.

    Generates realistic phpMyAdmin responses that:
    - Match the expected service type
    - Contain subtle vulnerability indicators
    - Encourage further probing
    - Adapt to the bot's behavior and escalation level
    """

    domain = "phpmyadmin"

    # Path patterns that this responder handles
    PATH_PATTERNS = [
        "/phpmyadmin", "/phpmyadmin/", "/phpmyadmin/index.php",
        "/pma", "/pma/", "/pma/index.php",
        "/mysql", "/mysql/", "/mysql/index.php",
        "/db", "/db/", "/db/index.php",
        "/database", "/database/", "/database/index.php",
    ]

    def __init__(self, ai_responder=None, enabled: bool = True):
        """Initialize the phpMyAdmin responder.

        Args:
            ai_responder: Optional AIResponder instance
            enabled: Whether this responder is active
        """
        super().__init__(ai_responder=ai_responder, enabled=enabled)

    def matches_path(self, path: str) -> bool:
        """Check if this responder should handle the given path."""
        path_lower = path.lower().split("?")[0]  # Remove query string
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict | None = None,
    ) -> tuple[bytes, int]:
        """Generate a phpMyAdmin response for the given request.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag)
        """
        if not self.enabled:
            return self._static_response(path), 1

        # Get or create bot profile
        profile = self.get_or_create_profile(bot_ip)

        # Record the request
        request_data = {
            "path": path,
            "method": self._extract_method(raw_request),
            "headers": dict(headers) if headers else {},
            "raw": raw_request,
            "timestamp": str(datetime.datetime.now(datetime.timezone.utc)),
        }
        profile.record_request(request_data)

        # Try AI-powered response first
        ai_result = self._try_ai_response(path, raw_request, bot_ip, headers)
        if ai_result is not None:
            response_text, detected = ai_result
            # Build full HTTP response
            response_bytes = self._build_http_response(response_text, path)
        else:
            # Fallback to static response
            response_bytes, detected = self._static_response(path), 1

        # Record the response
        response_data = {
            "status_code": 200,
            "body": response_bytes.decode("iso-8859-1", errors="replace")[:500],
            "content_type": "text/html; charset=UTF-8",
            "timestamp": str(datetime.datetime.now(datetime.timezone.utc)),
        }
        profile.record_response(response_data)
        self._response_count += 1

        return response_bytes, detected

    def get_response_template(self) -> str:
        """Return the response template for AI generation."""
        return """\
You are a vulnerable phpMyAdmin installation running version 4.0.10.2.
A bot from {bot_ip} has requested {path}.

Bot profile:
- Escalation level: {escalation_level} ({escalation_label})
- Detected behaviors: {detected_behaviors}
- Bot personality: {bot_personality}
- This is request #{request_count} from this bot
- This is response #{response_count} to this bot
- Previously explored paths: {explored_paths}

Generate a realistic phpMyAdmin response that:
1. Matches the version (4.0.10.2) and includes subtle version hints
2. Contains vulnerability indicators appropriate for the escalation level:
   - Level 0-1: Basic login page with version info
   - Level 2: Error message with database connection hints
   - Level 3: Debug output with server variables
   - Level 4+: Deep debug info, potential RCE indicators
3. Leaves hints of additional attack surfaces (e.g., "export.php", "sql.php")
4. Is technically accurate for HTTP/1.1 with proper headers

Return ONLY the response body (not HTTP headers). Keep it concise.
"""

    def _static_response(self, path: str) -> bytes:
        """Generate a static phpMyAdmin response."""
        # Determine response type based on path
        if "index.php" in path:
            body = self._login_page()
        elif "export.php" in path or "sql.php" in path:
            body = self._error_page("endpoint")
        else:
            body = self._login_page()

        return self._build_http_response(body, path)

    def _login_page(self) -> str:
        """Generate a phpMyAdmin login page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>phpMyAdmin - Login</title>
    <link rel="stylesheet" href="themes/dot.css" type="text/css">
</head>
<body>
    <div id="wrap">
        <div id="pma_navigation">
            <div class="pma_navigation_header">
                <h2>phpMyAdmin 4.0.10.2deb1</h2>
                <span class="version">4.0.10.2</span>
            </div>
        </div>
        <div id="pma_content">
            <form method="post" action="index.php" name="login_form" id="loginForm">
                <fieldset>
                    <legend>Login</legend>
                    <table>
                        <tr>
                            <td><label for="input_username">Username:</label></td>
                            <td><input type="text" name="pma_username" id="input_username"></td>
                        </tr>
                        <tr>
                            <td><label for="input_password">Password:</label></td>
                            <td><input type="password" name="pma_password" id="input_password"></td>
                        </tr>
                    </table>
                    <input type="hidden" name="server" value="1">
                    <input type="submit" value="Go" id="button_go">
                </fieldset>
            </form>
            <div class="error">
                <p>Warning: mysqli extension is not loaded or not configured properly.</p>
            </div>
        </div>
    </div>
</body>
</html>"""

    def _error_page(self, error_type: str = "general") -> str:
        """Generate a phpMyAdmin error page."""
        if error_type == "endpoint":
            return """\
<!DOCTYPE html>
<html>
<head><title>phpMyAdmin - Error</title></head>
<body>
    <div id="wrap">
        <h2>phpMyAdmin 4.0.10.2deb1</h2>
        <div class="error">
            <p>The requested endpoint is not available.</p>
            <p>Available endpoints:</p>
            <ul>
                <li><a href="index.php">Login</a></li>
                <li><a href="export.php">Export</a></li>
                <li><a href="sql.php">SQL Query</a></li>
                <li><a href="server_status.php">Server Status</a></li>
            </ul>
            <p class="debug">Server: localhost via TCP/IP | PHP Version: 5.5.9-1ubuntu4.14 | MySQL Version: 5.5.43-0ubuntu0.14.04.1</p>
        </div>
    </div>
</body>
</html>"""
        return """\
<!DOCTYPE html>
<html>
<head><title>phpMyAdmin - Error</title></head>
<body>
    <div id="wrap">
        <h2>phpMyAdmin 4.0.10.2deb1</h2>
        <div class="error">
            <p>An error has occurred:</p>
            <p>MySQL server has gone away</p>
            <p class="debug">Error: Connection refused (111)</p>
            <p class="debug">Server: localhost via TCP/IP | PHP Version: 5.5.9-1ubuntu4.14</p>
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

    def _build_http_response(self, body: str, path: str) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_type = "text/html; charset=UTF-8"

        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: Apache/2.4.7 (Ubuntu)\r\n"
            f"X-Powered-By: PHP/5.5.9-1ubuntu4.14\r\n"
            f"Set-Cookie: phpMyAdmin=abc123; path=/\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return f"PhpMyAdminResponder(domain={self.domain!r}, enabled={self.enabled})"
