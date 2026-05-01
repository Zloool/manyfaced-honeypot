"""cPanelHandler – handles cPanel/WHM specific paths and interactions.

Provides realistic cPanel responses including:
- cPanel login page (/cpanel/)
- WHM login page (/whm/)
- Webmail login (/webmail/)
- Captures login credentials from POST requests
- Returns realistic error pages
"""

from __future__ import annotations

import datetime
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class CPanelHandler(HTTPHandlerBase):
    """cPanel/WHM honeypot handler."""

    domain = "cpanel"
    PATH_PATTERNS = [
        "/cpanel",
        "/cpanel/",
        "/cpanel/hotlinkprotect",
        "/whm",
        "/whm/",
        "/whm/login",
        "/webmail",
        "/webmail/",
        "/webmail/login",
        "/mail",
        "/mail/",
        "/webdisk",
        "/webdisk/",
        "/cpsess",
        "/cpsess",
        "/setup1",
        "/setup1/",
        "/~",
        "/~",
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
        """Generate a cPanel response for the given request."""
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
        if method == "POST" and ("login" in path_lower or "cpsess" in path_lower):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if "whm" in path_lower or "/setup" in path_lower:
            body = self._whm_login_page()
        elif "webmail" in path_lower:
            body = self._webmail_login_page()
        elif "cpanel" in path_lower or path_lower.startswith("/"):
            body = self._cpanel_login_page()
        else:
            body = self._cpanel_login_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

    def _cpanel_login_page(self) -> str:
        """Generate the cPanel login page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cPanel - Login</title>
    <link rel="stylesheet" href="/cpanel/theme/default/css/login.css" />
</head>
<body class="login-page">
    <div class="login-container">
        <div class="login-box">
            <div class="login-header">
                <img src="/cpanel/theme/default/images/cpanel-logo.png" alt="cPanel Logo" />
                <h1>cPanel Login</h1>
            </div>
            <form action="/cpanel/hotlinkprotect" method="post" id="loginForm">
                <div class="form-group">
                    <label for="user">Username</label>
                    <input type="text" id="user" name="user" class="form-control" placeholder="Enter your username" required />
                </div>
                <div class="form-group">
                    <label for="pass">Password</label>
                    <input type="password" id="pass" name="pass" class="form-control" placeholder="Enter your password" required />
                </div>
                <div class="form-group">
                    <input type="checkbox" id="remember" name="remember" />
                    <label for="remember">Remember me</label>
                </div>
                <div class="form-group">
                    <button type="submit" class="btn btn-primary">Login</button>
                </div>
            </form>
            <div class="login-footer">
                <p>cPanel, Inc. | Version 120.0.6</p>
                <p><a href="/whm/">WHM Login</a> | <a href="/webmail/">Webmail</a></p>
            </div>
        </div>
    </div>
</body>
</html>"""

    def _whm_login_page(self) -> str:
        """Generate the WHM login page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WHM - cPanel & WHM Login</title>
    <link rel="stylesheet" href="/whm/theme/default/css/login.css" />
</head>
<body class="whm-login-page">
    <div class="login-container">
        <div class="login-box">
            <div class="login-header">
                <img src="/whm/theme/default/images/whm-logo.png" alt="WHM Logo" />
                <h1>WHM - cPanel & WHM Login</h1>
            </div>
            <form action="/whm/login" method="post" id="loginForm">
                <div class="form-group">
                    <label for="user">Username</label>
                    <input type="text" id="user" name="user" class="form-control" placeholder="root" value="root" />
                </div>
                <div class="form-group">
                    <label for="pass">Password</label>
                    <input type="password" id="pass" name="pass" class="form-control" placeholder="Enter your password" />
                </div>
                <div class="form-group">
                    <input type="checkbox" id="remember" name="remember" />
                    <label for="remember">Remember me</label>
                </div>
                <div class="form-group">
                    <button type="submit" class="btn btn-primary">Login</button>
                </div>
            </form>
            <div class="login-footer">
                <p>cPanel, Inc. | WHM Version 120.0.6</p>
                <p><a href="/cpanel/">cPanel Login</a> | <a href="/webmail/">Webmail</a></p>
            </div>
        </div>
    </div>
</body>
</html>"""

    def _webmail_login_page(self) -> str:
        """Generate the Webmail login page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Webmail - Login</title>
</head>
<body>
    <div class="login-container">
        <h1>Webmail Login</h1>
        <form action="/webmail/login" method="post">
            <div class="form-group">
                <label for="user">Email Address / Username</label>
                <input type="text" id="user" name="user" class="form-control" placeholder="user@yourdomain.com" />
            </div>
            <div class="form-group">
                <label for="pass">Password</label>
                <input type="password" id="pass" name="pass" class="form-control" placeholder="Enter your password" />
            </div>
            <div class="form-group">
                <label for="domain">Domain</label>
                <select id="domain" name="domain">
                    <option value="yourdomain.com">yourdomain.com</option>
                    <option value="example.com">example.com</option>
                    <option value="staging.example.com">staging.example.com</option>
                </select>
            </div>
            <div class="form-group">
                <button type="submit" class="btn btn-primary">Login</button>
            </div>
        </form>
        <p><a href="/cpanel/">cPanel</a> | <a href="/whm/">WHM</a></p>
    </div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Return a fake login failed response."""
        body = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Failed - cPanel</title>
</head>
<body class="login-page">
    <div class="login-container">
        <div class="login-box">
            <div class="login-header">
                <h1>cPanel Login</h1>
            </div>
            <div class="error-message">
                <p><strong>Login failed:</strong> Invalid username or password.</p>
                <p>Please try again or contact your hosting provider.</p>
            </div>
            <form action="/cpanel/hotlinkprotect" method="post" id="loginForm">
                <div class="form-group">
                    <label for="user">Username</label>
                    <input type="text" id="user" name="user" class="form-control" placeholder="Enter your username" />
                </div>
                <div class="form-group">
                    <label for="pass">Password</label>
                    <input type="password" id="pass" name="pass" class="form-control" placeholder="Enter your password" />
                </div>
                <div class="form-group">
                    <button type="submit" class="btn btn-primary">Login</button>
                </div>
            </form>
            <div class="login-footer">
                <p>cPanel, Inc. | Version 120.0.6</p>
            </div>
        </div>
    </div>
</body>
</html>"""
        return self._build_http_response(body, "/cpanel/")

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _build_http_response(
        self, body: str, path: str, status: str = "200 OK"
    ) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: cpsrvd/120.0.6\r\n"
            f"X-Frame-Options: SAMEORIGIN\r\n"
            f"X-Content-Type-Options: nosniff\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return f"CPanelHandler(domain={self.domain!r})"
