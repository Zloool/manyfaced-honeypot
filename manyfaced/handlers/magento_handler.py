"""MagentoHandler – handles Magento (Adobe Commerce) CMS paths and interactions.

Provides realistic Magento storefront and admin responses including:
- Magento storefront / home page (/) with the Magento logo
- Admin login page (/admin, /index.php/admin)
- Customer account login page (/customer/account/login)
- Web Setup Wizard page (/setup)
- A fake .env disclosure trap for /magento/%2eenv (URL-decoded to /magento/.env)

Magento (Adobe Commerce) is a widely deployed e-commerce platform that is a
common target for bots (admin takeover, .env disclosure, brute force).

URL-encoded probe segments (%2e -> '.', %2f -> '/') are decoded before routing,
matching what a real Magento/nginx stack receives.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import MAGENTO_HTTP

logger = logging.getLogger(__name__)


class MagentoHandler(HTTPHandlerBase):
    """Magento (Adobe Commerce) honeypot handler."""

    domain = 'magento'
    DETECTED_ID = MAGENTO_HTTP
    VERSION = '2.4.6'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Magento response for the given request."""
        # Normalise path: strip query string and URL-decode %2e/%2f probes.
        clean_path = path.split('?', 1)[0]
        clean_path = unquote(clean_path)

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
        path_lower = clean_path.lower()

        # Capture credentials from any login-style POST (admin sign-in,
        # customer sign-in, or a generic login path).
        is_login_path = 'login' in path_lower or 'admin' in path_lower or 'account' in path_lower
        if method == 'POST' and is_login_path:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Route to appropriate response.
        if (
            '/magento/.env' == path_lower
            or '.env' in path_lower
            and path_lower.startswith('/magento')
        ):
            body = self._env_disclosure()
        elif '/admin' in path_lower or path_lower in (
            '/customer/account/login',
            '/index.php/admin',
        ):
            body = self._admin_login_page()
        elif path_lower == '/setup':
            body = self._setup_page()
        else:
            body = self._storefront_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------
    # Response builders
    # ------------------------------------------------------------------

    def _storefront_page(self) -> str:
        """Magento storefront / home page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home page - Magento Store</title>
<link rel="stylesheet" type="text/css" href="/static/frontend/Magento/luma/en_US/css/styles-m.css">
<script type="text/javascript" src="/static/frontend/Magento/luma/en_US/requirejs/require.js"></script>
</head>
<body class="cms-home page-layout-main">
<header class="page-header">
    <div class="header content">
        <a class="logo" href="/"><img src="/static/frontend/Magento/luma/en_US/images/logo.svg" alt="Magento" width="160" height="40"></a>
        <nav class="navigation">
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/women.html">Women</a></li>
                <li><a href="/men.html">Men</a></li>
                <li><a href="/customer/account/login">Sign In</a></li>
                <li><a href="/admin">Admin</a></li>
            </ul>
        </nav>
    </div>
</header>
<main id="maincontent" class="page-main">
    <div class="column main">
        <h1>Welcome to Magento Store</h1>
        <p>Powered by Magento &mdash; the leading open-source e-commerce platform.</p>
        <p>Magento Open Source 2.4.6</p>
    </div>
</main>
<footer class="page-footer">
    <div class="footer content">
        <p>&copy; 2024 Magento Store. All rights reserved.</p>
        <p>Powered by <a href="https://magento.com">Magento</a> 2.4.6</p>
    </div>
</footer>
</body>
</html>"""

    def _admin_login_page(self) -> str:
        """Magento admin login page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Admin Sign In - Magento Admin</title>
<link rel="stylesheet" type="text/css" href="/static/adminhtml/Magento/backend/en_US/css/styles.css">
</head>
<body class="admin-login-page">
<div class="login-box">
    <div class="login-logo">
        <img src="/static/adminhtml/Magento/backend/en_US/images/magento-logo.svg" alt="Magento" width="200" height="50">
    </div>
    <div class="login-form">
        <h1>Admin Sign In</h1>
        <form method="POST" action="/admin" id="login-form">
            <input name="form_key" type="hidden" value="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6">
            <fieldset>
                <div class="admin__field">
                    <label for="username" class="admin__field-label"><span>Username</span></label>
                    <div class="admin__field-control">
                        <input id="username" name="login[username]" type="text" autocomplete="off" class="admin__control-text">
                    </div>
                </div>
                <div class="admin__field">
                    <label for="login" class="admin__field-label"><span>Password</span></label>
                    <div class="admin__field-control">
                        <input id="login" name="login[password]" type="password" autocomplete="off" class="admin__control-text">
                    </div>
                </div>
                <div class="admin__field">
                    <div class="admin__field-control">
                        <button type="submit" class="action-login action-primary">Sign in</button>
                    </div>
                </div>
            </fieldset>
        </form>
        <div class="admin-login-footer">
            <p>Magento Open Source 2.4.6</p>
        </div>
    </div>
</div>
</body>
</html>"""

    def _setup_page(self) -> str:
        """Magento Web Setup Wizard / installation page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Magento Setup</title>
<link rel="stylesheet" type="text/css" href="/setup/static/style.css">
</head>
<body class="setup-page">
<div class="setup-container">
    <h1>Magento Setup</h1>
    <h2>Web Setup Wizard</h2>
    <div class="step">
        <h3>Step 1: Welcome</h3>
        <p>Welcome to the Magento Installation Wizard. This wizard will guide you through the installation process.</p>
        <ul>
            <li class="check-pass">PHP version 8.2 or higher</li>
            <li class="check-pass">MySQL/MariaDB database</li>
            <li class="check-pass">Elasticsearch service</li>
            <li class="check-pass">Directory permissions writable</li>
        </ul>
        <form method="POST" action="/setup">
            <input type="hidden" name="step" value="2">
            <input type="submit" value="Continue">
        </form>
    </div>
    <p>Magento Open Source 2.4.6</p>
</div>
</body>
</html>"""

    def _env_disclosure(self) -> str:
        """Fake .env disclosure for /magento/%2eenv probes."""
        return """APP_NAME=magento
APP_ENV=production
APP_DEBUG=false
APP_URL=https://shop.example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=magento
DB_USERNAME=magento_user
DB_PASSWORD=magento_db_pass_2024

ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=AdminPass!2024

ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200

MAIL_MAILER=smtp
MAIL_HOST=mail.example.com
MAIL_USERNAME=noreply@example.com
MAIL_PASSWORD=mail_secret_9x2

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=redis_secret_magento

AWS_ACCESS_KEY_ID=AKIA_MAGENTO_EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI_MAGENTO_KEY
"""

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = (
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<title>Magento Admin - Login Error</title></head><body>'
            '<div class="messages"><div class="message-error">'
            '<p>Error: Invalid username or password. Please try again.</p>'
            '</div></div></body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    def _extract_credentials(
        self,
        raw_request: str,
        headers: dict[str, str],
    ) -> dict[str, str] | None:
        """Extract credentials, including Magento's array-style login fields.

        Magento admin/customer sign-in submits ``login[username]`` and
        ``login[password]`` (and ``login[enterprise][username]`` on the
        B2B/enterprise theme).  The shared extractor only matches flat field
        names, so we fall back to parsing the Magento shape first.
        """
        # Split headers from body.
        split = raw_request.split('\r\n\r\n', 1)
        if len(split) < 2:
            return super()._extract_credentials(raw_request, headers)
        body = split[1]

        from urllib.parse import unquote_plus  # noqa: PLC0415

        decoded = unquote_plus(body)

        def _field(field: str) -> str | None:
            prefix = field + '='
            if prefix in decoded:
                return decoded.split(prefix, 1)[1].split('&', 1)[0] or None
            return None

        username = (
            _field('login[username]')
            or _field('login[enterprise][username]')
            or _field('username')
            or _field('user')
        )
        password = (
            _field('login[password]')
            or _field('login[enterprise][password]')
            or _field('password')
            or _field('pass')
        )

        if username or password:
            result: dict[str, str] = {}
            if username:
                result['username'] = username
            if password:
                result['password'] = password
            return result

        return super()._extract_credentials(raw_request, headers)

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
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Magento/{self.VERSION}\r\n'
            f'X-Powered-By: PHP/8.2.15\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'MagentoHandler(domain={self.domain!r})'
