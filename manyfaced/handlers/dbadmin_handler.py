"""DBAdminHandler - generic DB admin face (Adminer / phpMyAdmin / SQL Buddy / myAdmin).

Emulates a generic SQL database administration login UI and a fake `.env`
disclosure endpoint, matching the production probe paths documented in issue
#292. Realistic responses are served for the common admin-panel probe paths
used by bots scanning for exposed database managers.

Probe paths covered (the handler decodes %2e -> '.' and %2f -> '/' so encoded
variants such as /db/%2eenv resolve to /db/.env):
  /adminer  /adminer.php  /sqlbuddy  /myadmin  /dbadmin  /phpmyadmin  /db/%2eenv
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import DBADMIN_HTTP

logger = logging.getLogger(__name__)


class DBAdminHandler(HTTPHandlerBase):
    """Generic database-admin honeypot handler (Adminer / phpMyAdmin style)."""

    domain = 'dbadmin'
    DETECTED_ID = DBADMIN_HTTP
    VERSION = '4.8.1'

    # Brand labels keyed by the probe path that triggered them.
    _BRANDS = {
        'adminer': 'Adminer',
        'adminer.php': 'Adminer',
        'phpmyadmin': 'phpMyAdmin',
        'sqlbuddy': 'SQL Buddy',
        'myadmin': 'myAdmin',
        'dbadmin': 'Database',
    }

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a DB-admin response for the given request."""
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
        # Strip query string and decode common URL encodings that bots use to
        # slip past naive matchers (%2e -> '.', %2f -> '/').
        decoded = self._decode_path(path)

        # Fake .env disclosure (e.g. /db/%2eenv -> /db/.env).
        if decoded.endswith('.env') or '/.env' in decoded:
            return self._build_http_response(self._env_page(), 200, 'OK'), self.DETECTED_ID

        # Handle login POST requests.
        if method == 'POST' and self._is_login_path(decoded):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Default: DB admin login page.
        brand = self._brand_for_path(decoded)
        body = self._login_page(brand)
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _decode_path(path: str) -> str:
        """Strip query string and decode %2e/%2f (and case variants)."""
        clean = path.split('?', 1)[0]
        # Repeatedly decode so double-encoded (%252e) variants also resolve.
        prev = None
        while prev != clean:
            prev = clean
            clean = (
                clean.replace('%2e', '.')
                .replace('%2E', '.')
                .replace('%2f', '/')
                .replace('%2F', '/')
            )
        return clean

    @staticmethod
    def _is_login_path(decoded_path: str) -> bool:
        low = decoded_path.lower()
        return any(
            kw in low for kw in ('login', 'auth', 'index.php', 'dbadmin', 'myadmin', 'adminer')
        )

    def _brand_for_path(self, decoded_path: str) -> str:
        low = decoded_path.lower().strip('/')
        if low in self._BRANDS:
            return self._BRANDS[low]
        if low.startswith('db/'):
            return 'Database'
        return 'Adminer'

    # ------------------------------------------------------------- responses
    def _login_page(self, brand: str = 'Adminer') -> str:
        """DB admin login page impersonating the requested brand."""
        {
            'Adminer': f'Adminer/{self.VERSION}',
            'phpMyAdmin': 'phpMyAdmin/5.2.1',
            'SQL Buddy': 'SQLBuddy/1.3.3',
            'myAdmin': 'myAdmin/1.0',
            'Database': 'Apache/2.4.41 (Ubuntu)',
        }.get(brand, f'Adminer/{self.VERSION}')

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{brand}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 40px 0; color: #222; }}
.container {{ max-width: 420px; margin: 0 auto; background: #fff; border: 1px solid #e1e4e8; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
.logo {{ text-align: center; padding: 28px 20px 10px; font-size: 26px; font-weight: 700; color: #2c3e50; }}
.logo small {{ display: block; font-size: 12px; font-weight: 400; color: #888; margin-top: 4px; }}
form {{ padding: 10px 28px 28px; }}
.field {{ margin-bottom: 14px; }}
label {{ display: block; font-size: 13px; margin-bottom: 5px; color: #555; }}
input[type=text], input[type=password], select {{ width: 100%; padding: 9px 10px; border: 1px solid #ccd1d9; border-radius: 4px; font-size: 14px; }}
.btn {{ width: 100%; padding: 10px; border: 0; border-radius: 4px; background: #337ab7; color: #fff; font-size: 15px; cursor: pointer; }}
.btn:hover {{ background: #286090; }}
.foot {{ text-align: center; font-size: 11px; color: #aaa; padding: 0 20px 20px; }}
</style>
</head>
<body>
<div class="container">
  <div class="logo">{brand}<small>Database Management</small></div>
  <form method="POST" action="/{self._login_action()}">
    <div class="field">
      <label for="auth[driver]">System</label>
      <select name="auth[driver]" id="auth[driver]">
        <option value="server">MySQL</option>
        <option value="sqlite">SQLite</option>
        <option value="pgsql">PostgreSQL</option>
      </select>
    </div>
    <div class="field">
      <label for="auth[server]">Server</label>
      <input type="text" name="auth[server]" id="auth[server]" value="localhost" autocomplete="off">
    </div>
    <div class="field">
      <label for="username">Username</label>
      <input type="text" name="username" id="username" autocomplete="off">
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input type="password" name="password" id="password">
    </div>
    <div class="field">
      <input type="submit" class="btn" value="Login">
    </div>
  </form>
  <div class="foot">{brand} &middot; Powered by PHP &middot; (c) 2024</div>
</div>
</body>
</html>"""

    def _login_action(self) -> str:
        """Login form action target (kept on the db-admin domain)."""
        return 'dbadmin'

    def _env_page(self) -> str:
        """Fake .env disclosure (DB credentials-style file)."""
        return (
            '# Environment configuration (leaked)\n'
            'APP_ENV=production\n'
            'APP_DEBUG=false\n'
            'APP_KEY=base64:Z3VsbHmV3JlYWxseW5vdGFyZWFsa2V5\n'
            'DB_CONNECTION=mysql\n'
            'DB_HOST=127.0.0.1\n'
            'DB_PORT=3306\n'
            'DB_DATABASE=app_prod\n'
            'DB_USERNAME=admin\n'
            'DB_PASSWORD=S3cr3tP@ssw0rd!\n'
            'REDIS_HOST=127.0.0.1\n'
            'REDIS_PASSWORD=null\n'
            'MAIL_HOST=smtp.localhost\n'
            'MAIL_USERNAME=noreply@example.com\n'
            'MAIL_PASSWORD=mailpass123\n'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            '<title>Authorization Error</title></head><body>'
            '<h3>Authorization Error</h3>'
            '<p>Invalid credentials. Please try again.</p>'
            '<p><a href="/dbadmin">Return to login</a></p>'
            '</body></html>'
        )
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
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Adminer/{self.VERSION}\r\n'
            f'X-Powered-By: PHP/8.2.15\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'DBAdminHandler(domain={self.domain!r})'
