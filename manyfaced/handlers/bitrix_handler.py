"""BitrixHandler – handles Bitrix CMS specific paths and interactions.

Provides realistic Bitrix CMS responses including:
- Bitrix admin login page (/bitrix/admin/)
- Bitrix authorization page (/bitrix/)
- Captures login credentials from POST requests
- Returns realistic error pages

Bitrix (1C-Bitrix) is a popular Russian CMS widely targeted by bots.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class BitrixHandler(HTTPHandlerBase):
    """Bitrix CMS honeypot handler."""

    domain = 'bitrix'
    PATH_PATTERNS = [
        '/bitrix/',
        '/bitrix/',
        '/bitrix/admin/',
        '/bitrix/admin',
        '/bitrix/auth/',
        '/bitrix/auth',
        '/bitrix/components/',
        '/bitrix/components',
        '/bitrix/templates/',
        '/bitrix/templates',
        '/bitrix/modules/',
        '/bitrix/modules',
        '/bitrix/cache/',
        '/bitrix/cache',
        '/bitrix/panels/',
        '/bitrix/panels',
        '/bitrix/admin/popup.php',
        '/bitrix/admin/index.php',
        '/bitrix/auth/fr/?backurl=',
        '/bitrix/auth/fr/',
        '/bitrix/auth/',
        '/bitrix/404.php',
        '/bitrix/error.php',
        '/bitrix/setup/',
        '/bitrix/setup',
        '/bitrix/modules/main/include/',
        '/bitrix/modules/main/classes/',
        '/bitrix/modules/iblock/classes/',
        '/bitrix/modules/search/classes/',
        '/bitrix/modules/socialnetwork/',
        '/bitrix/modules/catalog/',
        '/bitrix/modules/iblock/',
        '/bitrix/modules/seo/',
        '/bitrix/modules/sale/',
        '/bitrix/modules/forum/',
        '/bitrix/modules/blog/',
    ]
    DETECTED_ID = 1

    def matches_path(self, path: str) -> bool:
        """Check if this handler should handle the given path."""
        path_lower = path.lower().split('?')[0]
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Bitrix response for the given request."""
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

        # Handle login POST requests
        if method == 'POST' and ('login' in path_lower or 'admin' in path_lower):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if '/admin/' in path_lower or '/admin' == path_lower:
            body = self._admin_login_page()
        elif '/auth/' in path_lower:
            body = self._auth_page()
        elif '/setup/' in path_lower:
            body = self._setup_page()
        else:
            body = self._bitrix_portal_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    def _admin_login_page(self) -> str:
        """Bitrix admin login page."""
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">
<title>Bitrix - Authorization</title>
<link rel="stylesheet" type="text/css" href="/bitrix/themes/.default/compatible.css">
<link rel="stylesheet" type="text/css" href="/bitrix/themes/.default/adminstyles.css">
<link rel="stylesheet" type="text/css" href="/bitrix/themes/.default/modules.css">
<link rel="stylesheet" type="text/css" href="/bitrix/js/main/core/css/core.css">
<script type="text/javascript" src="/bitrix/js/main/core/core.js"></script>
<script type="text/javascript" src="/bitrix/js/main/core/core_window.js"></script>
<script type="text/javascript">
var bPrivMode = false;
var bIsMobile = false;
</script>
</head>
<body class="bitrix-admin-page" style="background-color: #f5f5f5;">
<div id="login-block">
    <div class="login-container">
        <div class="login-logo">
            <a href="/"><img src="/bitrix/images/bitrix_logo.gif" alt="1C-Bitrix" width="150"></a>
        </div>
        <div class="login-form">
            <h2>Administrative Panel</h2>
            <form method="POST" action="/bitrix/admin/index.php" name="bAuthForm">
                <input type="hidden" name="Login" value="Y">
                <input type="hidden" name="Backurl" value="/">
                <input type="hidden" name="AUTH_FORM" value="Y">
                <input type="hidden" name="TYPE" value="AUTH">
                <div class="form-group">
                    <label for="UserLogin">Login</label>
                    <input type="text" name="USER_LOGIN" id="UserLogin" class="input-text" autocomplete="off">
                </div>
                <div class="form-group">
                    <label for="UserPassword">Password</label>
                    <input type="password" name="USER_PASSWORD" id="UserPassword" class="input-text">
                </div>
                <div class="form-group checkbox">
                    <input type="checkbox" name="USER_REMEMBER" id="UserRemember" value="Y">
                    <label for="UserRemember">Remember me</label>
                </div>
                <div class="form-actions">
                    <input type="submit" name="Login" value="Sign In" class="btn btn-primary">
                </div>
            </form>
            <div class="login-links">
                <a href="/bitrix/auth/forgot_password.php">Forgot password?</a>
                <a href="/bitrix/auth/register.php">Registration</a>
            </div>
        </div>
    </div>
    <div class="login-footer">
        <p>&copy; 2024 1C-Bitrix. All rights reserved.</p>
        <p>Version 22.5.0</p>
    </div>
</div>
</body>
</html>"""

    def _auth_page(self) -> str:
        """Bitrix auth redirect page."""
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">
<title>Bitrix - Authorization</title>
<style>
body { font-family: Arial, sans-serif; background: #f0f0f0; text-align: center; padding: 50px; }
.container { background: white; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #333; }
.form-group { margin-bottom: 15px; text-align: left; }
label { display: block; margin-bottom: 5px; color: #555; }
input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
input[type="submit"] { background: #007cba; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; }
input[type="submit"]:hover { background: #005a87; }
</style>
</head>
<body>
<div class="container">
    <h1>Bitrix Site Authorization</h1>
    <form method="POST" action="/bitrix/auth/">
        <div class="form-group">
            <label for="USER_LOGIN">Login</label>
            <input type="text" name="USER_LOGIN" id="USER_LOGIN">
        </div>
        <div class="form-group">
            <label for="USER_PASSWORD">Password</label>
            <input type="password" name="USER_PASSWORD" id="USER_PASSWORD">
        </div>
        <div class="form-group">
            <input type="checkbox" name="USER_REMEMBER" id="USER_REMEMBER" value="Y">
            <label for="USER_REMEMBER">Remember me</label>
        </div>
        <div class="form-group">
            <input type="submit" value="Sign In">
        </div>
    </form>
    <p><a href="/bitrix/auth/forgot_password.php">Forgot your password?</a></p>
</div>
</body>
</html>"""

    def _setup_page(self) -> str:
        """Bitrix setup/installation page."""
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">
<title>Bitrix - Installation</title>
<style>
body { font-family: Arial, sans-serif; background: #f5f5f5; }
.setup-container { max-width: 800px; margin: 0 auto; padding: 20px; }
h1 { color: #333; border-bottom: 2px solid #007cba; padding-bottom: 10px; }
.step { background: white; padding: 20px; margin: 10px 0; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.step h2 { color: #007cba; margin-top: 0; }
.check-pass { color: green; }
.check-fail { color: red; }
.btn { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
</style>
</head>
<body>
<div class="setup-container">
    <h1>1C-Bitrix: Site Management - Installation Wizard</h1>
    <div class="step">
        <h2>Step 1: Welcome</h2>
        <p>Welcome to the Bitrix installation wizard. This wizard will guide you through the installation process.</p>
        <p>Before installing, please make sure your server meets the minimum requirements:</p>
        <ul>
            <li class="check-pass">PHP version 7.4 or higher</li>
            <li class="check-pass">MySQL/MariaDB database</li>
            <li class="check-pass">GD extension enabled</li>
            <li class="check-pass">mbstring extension enabled</li>
            <li class="check-pass">XML extension enabled</li>
            <li class="check-pass">Directory permissions writable</li>
        </ul>
        <form method="POST" action="/bitrix/setup/">
            <input type="hidden" name="step" value="2">
            <input type="hidden" name="Install" value="Y">
            <input type="submit" class="btn" value="Continue Installation">
        </form>
    </div>
</div>
</body>
</html>"""

    def _bitrix_portal_page(self) -> str:
        """Bitrix portal/home page."""
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">
<title>Bitrix - Site</title>
<style>
body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
.header { background: #333; color: white; padding: 15px 30px; }
.header h1 { margin: 0; font-size: 20px; }
.nav { background: #007cba; padding: 10px 30px; }
.nav a { color: white; text-decoration: none; margin-right: 20px; }
.content { padding: 30px; min-height: 400px; }
.footer { background: #f5f5f5; padding: 20px 30px; text-align: center; color: #666; }
</style>
</head>
<body>
<div class="header">
    <h1>1C-Bitrix Content Management System</h1>
</div>
<div class="nav">
    <a href="/bitrix/admin/">Admin Panel</a>
    <a href="/bitrix/auth/">Login</a>
    <a href="/bitrix/setup/">Setup</a>
    <a href="/bitrix/tools/">Tools</a>
</div>
<div class="content">
    <h2>Welcome to Bitrix CMS</h2>
    <p>This site is powered by 1C-Bitrix - the leading content management system for enterprise websites.</p>
    <p>Bitrix provides comprehensive tools for website management, e-commerce, and digital marketing.</p>
    <h3>Features:</h3>
    <ul>
        <li>Content management and workflow</li>
        <li>E-commerce and online store</li>
        <li>Marketing automation</li>
        <li>CRM integration</li>
        <li>Multi-language support</li>
        <li>SEO optimization tools</li>
    </ul>
    <p><em>Note: This is a managed Bitrix CMS instance.</em></p>
</div>
<div class="footer">
    <p>&copy; 2024 1C-Bitrix. All rights reserved. | Version 22.5.0</p>
    <p><a href="/bitrix/admin/">Administrative Panel</a> | <a href="/bitrix/auth/">Login</a></p>
</div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Bitrix login failed response."""
        body = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">
<title>Bitrix - Authorization Error</title>
<link rel="stylesheet" type="text/css" href="/bitrix/themes/.default/adminstyles.css">
</head>
<body class="bitrix-admin-page">
<div class="login-container">
    <div class="error-message">
        <h3>Authorization Error</h3>
        <p>Invalid login or password. Please try again.</p>
        <p><a href="/bitrix/admin/">Return to login page</a></p>
    </div>
</div>
</body>
</html>"""
        return self._build_http_response(body, 200, 'OK')

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
        content_type: str = 'text/html; charset=windows-1251',
    ) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: bitrix/22.5.0\r\n'
            f'X-Powered-By: PHP/8.2.15\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'BitrixHandler(domain={self.domain!r})'
