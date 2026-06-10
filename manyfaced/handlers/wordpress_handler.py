"""WordPressHandler – handles WordPress-specific paths and interactions.

Provides realistic WordPress responses including:
- Login page (/wp-login.php)
- Admin pages (/wp-admin/)
- XML-RPC endpoint (/xmlrpc.php)
- Content directories (/wp-content/)
- Captures login credentials from POST requests
- Returns appropriate responses to exploit attempts
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import WORDPRESS_HTTP

logger = logging.getLogger(__name__)


class WordPressHandler(HTTPHandlerBase):
    """Handles WordPress honeypot responses."""

    domain = 'wordpress'
    DETECTED_ID = WORDPRESS_HTTP

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a WordPress response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        # Record the request
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

        # Handle login POST requests
        if method == 'POST' and 'wp-login' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                # Fake "login failed" response (encourages brute force)
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if 'wp-login' in path_lower:
            body = self._login_page()
        elif 'xmlrpc' in path_lower:
            if method == 'POST':
                body = self._xmlrpc_response()
            else:
                body = self._xmlrpc_get_response()
        elif 'wp-admin' in path_lower:
            body = self._admin_redirect()
        elif 'wp-content' in path_lower:
            body = self._content_response()
        elif 'wp-includes' in path_lower:
            body = self._includes_response()
        elif path_lower == '/' or path_lower == '/index.php':
            body = self._home_page()
        else:
            body = self._login_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

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
    <p class="version">WordPress 6.5.3</p>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Return a fake login failure response (encourages brute force)."""
        body = """\
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>WordPress &#8212; Error</title>
</head>
<body class="login">
    <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
    <div id="login_error">
        <strong>ERROR:</strong> Invalid username. <a href="/wp-login.php?action=lostpassword">Lost your password?</a>
    </div>
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
        <p>
            <label for="user_login">Username or Email Address<br />
            <input type="text" name="log" id="user_login" class="input" value="" size="20" /></label>
        </p>
        <p>
            <label for="user_pass">Password<br />
            <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label>
        </p>
        <p class="submit">
            <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
        </p>
    </form>
    <p class="version">WordPress 6.5.3</p>
</body>
</html>"""
        return self._build_http_response(body, '/wp-login.php')

    def _xmlrpc_response(self) -> str:
        """Generate an XML-RPC response for POST requests."""
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
<!-- WordPress 6.5.3 | xmlrpc.php | PHP 8.2.15 -->"""

    def _xmlrpc_get_response(self) -> str:
        """Generate an XML-RPC response for GET requests (405 Method Not Allowed)."""
        return """\
<?xml version="1.0" encoding="UTF-8"?>
<SOAPEnvelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
<SOAPBody>
<SOAPFault>
<faultcode>SOAP-ENV:Client</faultcode>
<faultstring>XML-RPC server accepts POST requests only.</faultstring>
</SOAPFault>
</SOAPBody>
</SOAPEnvelope>
<!-- WordPress 6.5.3 | xmlrpc.php | PHP 8.2.15 -->"""

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
    <p>WordPress 6.5.3 | Server: Apache/2.4.57 (Ubuntu)</p>
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
        <li><a href="/wp-content/backups/">backups/</a></li>
    </ul>
    <p>WordPress 6.5.3 | PHP 8.2.15-1ubuntu2.11</p>
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
    <p class="debug">WordPress 6.5.3 | wp-includes/ | PHP 8.2.15-1ubuntu2.11</p>
</body>
</html>"""

    def _home_page(self) -> str:
        """Generate a WordPress home page."""
        return """\
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="UTF-8" />
    <title>My WordPress Site &#8212; Just another WordPress site</title>
    <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
</head>
<body class="home">
    <header>
        <h1><a href="/">My WordPress Site</a></h1>
        <p>Just another WordPress site</p>
    </header>
    <main>
        <article>
            <h2>Welcome to WordPress</h2>
            <p>This is a WordPress installation. If you are seeing this page, it means the installation is complete.</p>
            <p><a href="/wp-admin/">Dashboard</a> | <a href="/wp-login.php">Login</a></p>
        </article>
    </main>
    <footer>
        <p>Powered by <a href="https://wordpress.org/">WordPress 6.5.3</a></p>
    </footer>
</body>
</html>"""

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(self, body: str, path: str, status: str = '200 OK') -> bytes:
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_type = 'text/html; charset=UTF-8'
        if 'xmlrpc' in path:
            content_type = 'text/xml; charset=UTF-8'

        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: Apache/2.4.57 (Ubuntu)\r\n'
            f'X-Powered-By: PHP/8.2.15-1ubuntu2.11\r\n'
            f'Link: <https://{path.split("/")[1] if "/" in path else "localhost"}>; rel="https://api.w.org/"\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'WordPressHandler(domain={self.domain!r})'
