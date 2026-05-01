"""
WordPress responder module.

Generates realistic WordPress responses that encourage deeper exploitation.
Adapts responses based on the bot's behavior and escalation level.

Usage:
    from manyfaced.common.responder.wordpress_responder import WordPressResponder

    responder = WordPressResponder(ai_responder=ai_responder)
    response_bytes, detected = responder.generate_response(
        path="/wp-login.php",
        raw_request="GET /wp-login.php HTTP/1.1...",
        bot_ip="1.2.3.4",
    )
"""

from __future__ import annotations

import datetime

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.responder.responder_base import ResponderBase

logger = get_logger(__name__)


class WordPressResponder(ResponderBase):
    """WordPress honeypot responder.

    Generates realistic WordPress responses that:
    - Match the expected service type
    - Contain subtle vulnerability indicators
    - Encourage further probing
    - Adapt to the bot's behavior and escalation level
    """

    domain = "wordpress"

    # Path patterns that this responder handles
    PATH_PATTERNS = [
        "/wp-login", "/wp-login.php",
        "/wp-admin", "/wp-admin/", "/wp-admin/admin-ajax.php",
        "/wp-content", "/wp-content/", "/wp-content/uploads",
        "/wp-includes", "/wp-includes/", "/wp-includes/xmlrpc.php",
        "/xmlrpc.php",
        "/wordpress", "/wordpress/", "/wordpress/wp-login.php",
        "/blog", "/blog/", "/blog/wp-login.php",
    ]

    def __init__(self, ai_responder=None, enabled: bool = True):
        """Initialize the WordPress responder.

        Args:
            ai_responder: Optional AIResponder instance
            enabled: Whether this responder is active
        """
        super().__init__(ai_responder=ai_responder, enabled=enabled)

    def matches_path(self, path: str) -> bool:
        """Check if this responder should handle the given path."""
        path_lower = path.lower().split("?")[0]
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict | None = None,
    ) -> tuple[bytes, int]:
        """Generate a WordPress response for the given request.

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
            response_bytes = self._build_http_response(response_text, path)
        else:
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
You are a vulnerable WordPress installation running version 4.2.0.
A bot from {bot_ip} has requested {path}.

Bot profile:
- Escalation level: {escalation_level} ({escalation_label})
- Detected behaviors: {detected_behaviors}
- Bot personality: {bot_personality}
- This is request #{request_count} from this bot
- This is response #{response_count} to this bot
- Previously explored paths: {explored_paths}

Generate a realistic WordPress response that:
1. Matches the version (4.2.0) and includes subtle version hints
2. Contains vulnerability indicators appropriate for the escalation level:
   - Level 0-1: Login page or default WordPress content
   - Level 2: Error message with debug info
   - Level 3: XML-RPC debug output
   - Level 4+: Deep debug info, potential plugin vulnerabilities
3. Leaves hints of additional attack surfaces (e.g., "xmlrpc.php", "wp-config.php.bak")
4. Is technically accurate for HTTP/1.1 with proper headers

Return ONLY the response body (not HTTP headers). Keep it concise.
"""

    def _static_response(self, path: str) -> bytes:
        """Generate a static WordPress response."""
        if "wp-login.php" in path:
            body = self._login_page()
        elif "xmlrpc.php" in path:
            body = self._xmlrpc_response()
        elif "wp-admin" in path:
            body = self._admin_redirect()
        elif "wp-content" in path:
            body = self._content_response()
        elif "wp-includes" in path:
            body = self._includes_response()
        else:
            body = self._login_page()

        return self._build_http_response(body, path)

    def _login_page(self) -> str:
        """Generate a WordPress login page."""
        return """\
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Log In &#8212; WordPress</title>
    <link rel="stylesheet" href="/wp-login.css" type="text/css" />
    <meta name="robots" content="noindex, nofollow" />
</head>
<body class="login login-action-login wp-core-ui locales-en login-language-en">
    <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
        <p>
            <label for="user_login">Username or Email Address<br />
            <input type="text" name="log" id="user_login" class="input" value="" size="20" /></label>
        </p>
        <p>
            <label for="user_pass">Password<br />
            <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label>
        </p>
        <p class="forgetmenot">
            <label for="rememberme">
            <input name="rememberme" type="checkbox" id="rememberme" value="forever" /> Remember Me</label>
        </p>
        <p class="submit">
            <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
            <input type="hidden" name="redirect_to" value="/wp-admin/" />
        </p>
    </form>
    <p id="backtoblog">
        <a href="/">&#8592; Back to WordPress</a>
    </p>
    <div class="clear"></div>
    <p class="version">WordPress 4.2.0</p>
</body>
</html>"""

    def _xmlrpc_response(self) -> str:
        """Generate an XML-RPC response."""
        return """\
<?xml version="1.0" encoding="UTF-8"?>
<SOAPEnvelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
<SOAPBody>
<SOAPFault>
<faultcode>SOAP-ENV:Client</faultcode>
<faultstring>XML-RPC server accepts POST requests only.</faultstring>
<faultactor></faultactor>
<detail>
<wp_error_code>0</wp_error_code>
<wp_error_string>XML-RPC server accepts POST requests only.</wp_error_string>
</detail>
</SOAPFault>
</SOAPBody>
</SOAPEnvelope>
<!-- WordPress 4.2.0 | xmlrpc.php | PHP 5.5.9-1ubuntu4.14 -->"""

    def _admin_redirect(self) -> str:
        """Generate an admin redirect response."""
        return """\
<!DOCTYPE html>
<html>
<head>
    <title>WordPress &#8212; Admin</title>
    <meta http-equiv="Refresh" content="0;url=/wp-login.php" />
</head>
<body>
    <p>You are being redirected to <a href="/wp-login.php">login page</a>.</p>
    <p>WordPress 4.2.0 | Server: Apache/2.4.7 (Ubuntu)</p>
</body>
</html>"""

    def _content_response(self) -> str:
        """Generate a wp-content response."""
        return """\
<!DOCTYPE html>
<html>
<head><title>WordPress Content</title></head>
<body>
    <h1>WordPress Content Directory</h1>
    <ul>
        <li><a href="/wp-content/themes/">themes/</a></li>
        <li><a href="/wp-content/plugins/">plugins/</a></li>
        <li><a href="/wp-content/uploads/">uploads/</a></li>
        <li><a href="/wp-content/debug.log">debug.log</a></li>
    </ul>
    <p>WordPress 4.2.0 | PHP 5.5.9-1ubuntu4.14</p>
</body>
</html>"""

    def _includes_response(self) -> str:
        """Generate a wp-includes response."""
        return """\
<!DOCTYPE html>
<html>
<head><title>WordPress Includes</title></head>
<body>
    <h1>WordPress Includes Directory</h1>
    <p>This directory contains core WordPress files.</p>
    <p>Warning: Direct access to this directory is not allowed.</p>
    <p class="debug">WordPress 4.2.0 | wp-includes/ | PHP 5.5.9-1ubuntu4.14</p>
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
        if "xmlrpc.php" in path:
            content_type = "text/xml; charset=UTF-8"

        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: Apache/2.4.7 (Ubuntu)\r\n"
            f"X-Powered-By: PHP/5.5.9-1ubuntu4.14\r\n"
            f"Link: <https://wp.me/>\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return f"WordPressResponder(domain={self.domain!r}, enabled={self.enabled})"
