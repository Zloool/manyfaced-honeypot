"""EnvDiscHandler - fakes .env / config-file disclosure endpoints.

Emulates the common .env / configuration-file disclosure paths that
automated scanners probe for (issue #272).  Returns a clearly-fake
``.env`` dump (marked HONEYPOT) for ``/.env`` / ``/config.env`` and a
realistic HTML configuration page for ``/configuration``.

This face only *owns* three files; the detected-id constant
``ENV_DISC_HTTP`` lives in ``manyfaced.common.status`` (a shared file).
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import urllib.parse

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import ENV_DISC_HTTP

logger = logging.getLogger(__name__)


class EnvDiscHandler(HTTPHandlerBase):
    """Env / config disclosure honeypot handler."""

    domain = 'env_disc'
    DETECTED_ID = ENV_DISC_HTTP
    VERSION = '1.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an Env/config-disclosure response for the request."""
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
        # Decode URL-encoded path segments scanned bots use (%2e -> '.',
        # %2f -> '/'). The router normally receives the decoded path; we
        # also decode defensively for direct handler invocation.
        decoded = self._decode_path(path)
        decoded_lower = decoded.lower()

        # Capture login/submit attempts, then always answer "Error" so the
        # bot keeps probing instead of believing it succeeded.
        if method == 'POST':
            self.handle_login(path, raw_request, bot_ip, headers or {})
            return self._login_failed_response(), self.DETECTED_ID

        # Fake .env disclosure for env-file probes.
        if decoded_lower in ('/.env', '/config.env', '/.env.example') or decoded_lower.endswith('/.env'):
            body = self._env_file()
            return (
                self._build_http_response(body, 200, 'OK', 'text/plain; charset=utf-8'),
                self.DETECTED_ID,
            )

        # Everything else under /env, /configuration, /api -> config page.
        body = self._config_page()
        return (
            self._build_http_response(body, 200, 'OK', 'text/html; charset=utf-8'),
            self.DETECTED_ID,
        )

    # -- response builders --------------------------------------------------

    def _env_file(self) -> str:
        """Fake but clearly-honeypot .env disclosure."""
        return (
            '# HONEYPOT DISCLOSURE - THIS IS A DECOY CONFIGURATION\n'
            '# No real credentials are present. All values are fabricated.\n'
            'APP_NAME=Laravel\n'
            'APP_ENV=production\n'
            'APP_DEBUG=false\n'
            'APP_URL=https://example.com\n'
            'APP_KEY=base64:HONEYPOT_FAKE_APP_KEY_000000000000000000000000=\n'
            '\n'
            'DB_CONNECTION=mysql\n'
            'DB_HOST=127.0.0.1\n'
            'DB_PORT=3306\n'
            'DB_DATABASE=honeypot_fake_db\n'
            'DB_USERNAME=admin\n'
            'DB_PASSWORD=HONEYPOT_FAKE_DB_PASSWORD_12345\n'
            '\n'
            'CACHE_DRIVER=file\n'
            'QUEUE_CONNECTION=sync\n'
            'SESSION_DRIVER=file\n'
            '\n'
            'AWS_ACCESS_KEY_ID=AKIAHONEYPOTFAKEEXAMPLE\n'
            'AWS_SECRET_ACCESS_KEY=HONEYPOTfakesecretkeyexample0000000000000000\n'
            'AWS_DEFAULT_REGION=us-east-1\n'
            '\n'
            'MAIL_MAILER=smtp\n'
            'MAIL_HOST=mail.example.com\n'
            'MAIL_USERNAME=noreply@example.com\n'
            'MAIL_PASSWORD=HONEYPOT_FAKE_MAIL_PASSWORD\n'
            '\n'
            'REDIS_HOST=127.0.0.1\n'
            'REDIS_PASSWORD=HONEYPOT_FAKE_REDIS_PASSWORD\n'
            'REDIS_PORT=6379\n'
        )

    def _config_page(self) -> str:
        """HTML configuration / environment management page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Environment Configuration</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; margin: 0; background: #f4f6f8; color: #222; }
.header { background: #2c3e50; color: #fff; padding: 16px 24px; }
.header h1 { margin: 0; font-size: 20px; }
.container { max-width: 880px; margin: 24px auto; background: #fff; padding: 24px; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
h2 { color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 8px; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 14px; }
th { background: #f4f6f8; color: #555; }
.form-group { margin: 16px 0; }
label { display: block; margin-bottom: 6px; color: #555; }
input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
.btn { background: #2c3e50; color: #fff; border: none; padding: 10px 18px; border-radius: 4px; cursor: pointer; }
.footer { text-align: center; color: #999; padding: 20px; font-size: 12px; }
</style>
</head>
<body>
<div class="header"><h1>Environment Configuration Panel</h1></div>
<div class="container">
    <h2>Current Environment</h2>
    <table>
        <tr><th>Key</th><th>Value</th></tr>
        <tr><td>APP_ENV</td><td>production</td></tr>
        <tr><td>APP_DEBUG</td><td>false</td></tr>
        <tr><td>DB_CONNECTION</td><td>mysql</td></tr>
        <tr><td>CACHE_DRIVER</td><td>file</td></tr>
        <tr><td>QUEUE_CONNECTION</td><td>sync</td></tr>
    </table>
    <h2>Update Credentials</h2>
    <form method="POST" action="/env/login">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" autocomplete="off">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" id="password">
        </div>
        <div class="form-group">
            <input type="submit" class="btn" value="Save Configuration">
        </div>
    </form>
</div>
<div class="footer">&copy; 2024 Example Corp. All rights reserved.</div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Generic "Error" response for login/submit probes."""
        body = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<h3>Error</h3>
<p>Invalid configuration or authentication failed. Please try again.</p>
</body>
</html>"""
        return self._build_http_response(body, 200, 'OK', 'text/html; charset=utf-8')

    # -- helpers ------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """URL-decode %2e -> '.', %2f -> '/' and other percent encodings."""
        try:
            return urllib.parse.unquote(path)
        except Exception:
            return path

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
        content_type: str = 'text/plain; charset=utf-8',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('iso-8859-1', errors='replace')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: nginx/1.24.0\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'\r\n'
        ).encode('iso-8859-1') + body_bytes
        return response

    def __repr__(self) -> str:
        return f'EnvDiscHandler(domain={self.domain!r})'
