"""DrupalHandler – handles Drupal CMS specific paths and interactions.

Provides realistic Drupal responses including:
- Login page (/user/login)
- Admin pages (/admin)
- Content paths (/node/, /user/)
- Captures login credentials from POST requests
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import DRUPAL_HTTP

logger = logging.getLogger(__name__)


class DrupalHandler(HTTPHandlerBase):
    """Drupal CMS honeypot handler."""

    domain = 'drupal'
    DETECTED_ID = DRUPAL_HTTP

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Drupal response for the given request."""
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
        if method == 'POST' and 'user/login' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if 'user/login' in path_lower:
            body = self._login_page()
        elif 'user/register' in path_lower:
            body = self._register_page()
        elif 'admin' in path_lower:
            body = self._admin_page()
        elif 'xmlrpc' in path_lower:
            body = self._xmlrpc_response()
        elif 'sites/default' in path_lower:
            body = self._sites_default()
        elif 'node' in path_lower:
            body = self._node_page()
        elif path_lower == '/' or path_lower == '/index.php':
            body = self._home_page()
        else:
            body = self._login_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

    def _login_page(self) -> str:
        """Generate a Drupal login page."""
        return """\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>Log in | My Drupal Site</title>
    <link rel="stylesheet" href="/core/assets/styles.css" />
</head>
<body class="path-user login">
    <div class="page">
        <header>
            <h1><a href="/">My Drupal Site</a></h1>
        </header>
        <main>
            <h1>Log in</h1>
            <form action="/user/login" method="post" accept-charset="UTF-8">
                <div class="form-item">
                    <label for="edit-name">Username <span class="required">*</span></label>
                    <input type="text" id="edit-name" name="name" value="" size="60" maxlength="60" class="form-text required" />
                </div>
                <div class="form-item">
                    <label for="edit-pass">Password <span class="required">*</span></label>
                    <input type="password" id="edit-pass" name="pass" size="60" maxlength="128" class="form-text required" />
                </div>
                <div class="form-item">
                    <input type="checkbox" id="edit-stay" name="stay" value="1" />
                    <label for="edit-stay">Stay logged in</label>
                </div>
                <input type="hidden" name="form_build_id" value="form-abc123" />
                <input type="hidden" name="form_id" value="user_login_form" />
                <input type="hidden" name="_csrf_token" value="d4e5f6g7h8i9j0k1l2m3" />
                <div class="form-actions">
                    <input type="submit" id="edit-submit" value="Log in" class="button button--primary" />
                </div>
            </form>
            <p><a href="/user/register">Create new account</a></p>
            <p><a href="/user/password">Request new password</a></p>
        </main>
        <footer>
            <p>Powered by <a href="https://www.drupal.org/">Drupal 10.2.4</a></p>
        </footer>
    </div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Return a fake login failed response."""
        body = """\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>My Drupal Site | Log in</title>
</head>
<body class="path-user login">
    <div class="page">
        <main>
            <h1>Log in</h1>
            <div class="messages messages--error">
                <p>Incorrect username or password.</p>
                <p><a href="/user/password">Forgot your username or password?</a></p>
            </div>
            <form action="/user/login" method="post" accept-charset="UTF-8">
                <div class="form-item">
                    <label for="edit-name">Username <span class="required">*</span></label>
                    <input type="text" id="edit-name" name="name" value="" size="60" maxlength="60" class="form-text required" />
                </div>
                <div class="form-item">
                    <label for="edit-pass">Password <span class="required">*</span></label>
                    <input type="password" id="edit-pass" name="pass" size="60" maxlength="128" class="form-text required" />
                </div>
                <input type="hidden" name="form_build_id" value="form-abc123" />
                <input type="hidden" name="form_id" value="user_login_form" />
                <input type="hidden" name="_csrf_token" value="d4e5f6g7h8i9j0k1l2m3" />
                <div class="form-actions">
                    <input type="submit" id="edit-submit" value="Log in" class="button button--primary" />
                </div>
            </form>
        </main>
    </div>
</body>
</html>"""
        return self._build_http_response(body, '/user/login')

    def _register_page(self) -> str:
        """Generate a Drupal registration page."""
        return """\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>Create new account | My Drupal Site</title>
</head>
<body class="path-user/register">
    <div class="page">
        <main>
            <h1>Create new account</h1>
            <form action="/user/register" method="post" accept-charset="UTF-8">
                <div class="form-item">
                    <label for="edit-name">Username <span class="required">*</span></label>
                    <input type="text" id="edit-name" name="name" value="" size="60" maxlength="60" class="form-text required" />
                </div>
                <div class="form-item">
                    <label for="edit-mail">E-mail address <span class="required">*</span></label>
                    <input type="email" id="edit-mail" name="mail" value="" size="60" maxlength="254" class="form-email required" />
                </div>
                <div class="form-item">
                    <label for="edit-pass-pass-1">Password <span class="required">*</span></label>
                    <input type="password" id="edit-pass-pass-1" name="pass[pass1]" size="60" maxlength="128" class="form-password required" />
                </div>
                <div class="form-item">
                    <label for="edit-pass-pass-2">Confirm password <span class="required">*</span></label>
                    <input type="password" id="edit-pass-pass-2" name="pass[pass2]" size="60" maxlength="128" class="form-password required" />
                </div>
                <input type="hidden" name="form_build_id" value="form-def456" />
                <input type="hidden" name="form_id" value="user_register_form" />
                <input type="hidden" name="_csrf_token" value="n3o4p5q6r7s8t9u0v1w2" />
                <div class="form-actions">
                    <input type="submit" id="edit-submit" value="Create new account" class="button button--primary" />
                </div>
            </form>
            <p><a href="/user/login">Already have an account? Log in.</a></p>
        </main>
    </div>
</body>
</html>"""

    def _admin_page(self) -> str:
        """Generate a Drupal admin page."""
        return """\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>Administration | My Drupal Site</title>
</head>
<body class="path-admin">
    <div class="page">
        <main>
            <h1>Administration</h1>
            <h2>Structure</h2>
            <ul>
                <li><a href="/admin/structure">Content types</a></li>
                <li><a href="/admin/structure/views">Views</a></li>
                <li><a href="/admin/structure/block">Blocks</a></li>
                <li><a href="/admin/structure/menu">Menus</a></li>
                <li><a href="/admin/structure/taxonomy">Taxonomy</a></li>
            </ul>
            <h2>People</h2>
            <ul>
                <li><a href="/admin/people">Users</a></li>
                <li><a href="/admin/people/permissions">Permissions</a></li>
                <li><a href="/admin/people/register">Registration settings</a></li>
            </ul>
            <h2>Configuration</h2>
            <ul>
                <li><a href="/admin/config">System</a></li>
                <li><a href="/admin/config/system/site-information">Site information</a></li>
                <li><a href="/admin/config/system/cron">Cron settings</a></li>
                <li><a href="/admin/config/system/mail">Mail settings</a></li>
            </ul>
            <h2>Extend</h2>
            <ul>
                <li><a href="/admin/modules">Install new module</a></li>
                <li><a href="/admin/themes">Install new theme</a></li>
            </ul>
            <div class="info">
                <p>Drupal 10.2.4 | PHP 8.2.15 | MySQL 8.0.36</p>
                <p>Database: drupal_db @ localhost</p>
            </div>
        </main>
    </div>
</body>
</html>"""

    def _xmlrpc_response(self) -> str:
        """Generate an XML-RPC response."""
        return """\
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
<fault>
<value><struct>
<member><name>faultCode</name><value><int>4</int></value></member>
<member><name>faultString</name><value><string>XML-RPC server accepts POST requests only.</string></value></member>
</struct></value>
</fault>
</methodResponse>
<!-- Drupal 10.2.4 | xmlrpc.php -->"""

    def _sites_default(self) -> str:
        """Generate a sites/default page."""
        return """\
<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
    <h1>Access Denied</h1>
    <p>You do not have access to this directory.</p>
    <div class="debug">
        <p>Drupal 10.2.4</p>
        <p>Base path: /sites/default</p>
        <p>Configuration files:</p>
        <ul>
            <li>/sites/default/settings.php</li>
            <li>/sites/default/services.yml</li>
            <li>/sites/default/services.yml</li>
        </ul>
        <p>Database credentials in settings.php:</p>
        <pre>
$databases['default']['default'] = [
  'database' => 'drupal_db',
  'username' => 'drupal_user',
  'password' => 'DrupalP@ss2026',
  'host' => 'localhost',
  'port' => '3306',
  'namespace' => 'Drupal\\Core\\Database\\Driver\\mysql',
  'driver' => 'mysql',
];
        </pre>
    </div>
</body>
</html>"""

    def _node_page(self) -> str:
        """Generate a node page."""
        return """\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>Welcome to Drupal | My Drupal Site</title>
</head>
<body>
    <div class="page">
        <main>
            <article>
                <h1>Welcome to Drupal</h1>
                <p>This is a Drupal 10.2.4 installation. If you are seeing this page, the installation is complete.</p>
                <h2>Getting Started</h2>
                <ul>
                    <li><a href="/admin/config/system/site-information">Configure site information</a></li>
                    <li><a href="/admin/config/system/site-maintenance">Enable maintenance mode</a></li>
                    <li><a href="/admin/people">Manage users</a></li>
                    <li><a href="/admin/modules">Install modules</a></li>
                </ul>
                <h2>Resources</h2>
                <ul>
                    <li><a href="https://www.drupal.org/documentation">Documentation</a></li>
                    <li><a href="https://www.drupal.org/community">Community</a></li>
                    <li><a href="https://www.drupal.org/project/modules">Modules</a></li>
                </ul>
            </article>
        </main>
    </div>
</body>
</html>"""

    def _home_page(self) -> str:
        """Generate the home page."""
        return """\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>My Drupal Site</title>
</head>
<body>
    <header>
        <h1><a href="/">My Drupal Site</a></h1>
        <nav>
            <a href="/user/login">Log in</a>
            <a href="/user/register">Register</a>
        </nav>
    </header>
    <main>
        <h2>Welcome</h2>
        <p>This is a Drupal 10.2.4 site.</p>
    </main>
    <footer>
        <p>Powered by <a href="https://www.drupal.org/">Drupal 10.2.4</a></p>
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

        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: Apache/2.4.57 (Ubuntu)\r\n'
            f'X-Powered-By: PHP/8.2.15-1ubuntu2.11\r\n'
            f'X-Drupal-Cache: HIT\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: text/html; charset=UTF-8\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'DrupalHandler(domain={self.domain!r})'
