"""LaravelHandler – handles Laravel framework specific paths and interactions.

Provides realistic Laravel (PHP framework) responses including:
- A Laravel "Illuminate" error/debug page (app debug mode)
- The Ignition debug handler (/_ignition/) pages
- Emulated .env / log file disclosure under common probe paths
- Captures login credentials from POST requests to login paths

Laravel is a widely deployed PHP framework; its debug surfaces (Ignition, the
.env file, and storage logs) are high-value targets for attackers harvesting
secrets. This face emulates those surfaces to attract and study probes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import urllib.parse

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import LARAVEL_HTTP

logger = logging.getLogger(__name__)


class LaravelHandler(HTTPHandlerBase):
    """Laravel honeypot handler (issue #286)."""

    domain = 'laravel'
    DETECTED_ID = LARAVEL_HTTP
    VERSION = '10.48.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Laravel response for the given request."""
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

        # Decode path-encoded traversal/probe tricks (%2e -> '.', %2f -> '/').
        decoded = self._decode_path(path_lower)

        # Handle login POST requests (named login/authenticate paths).
        if method == 'POST' and any(
            kw in path_lower for kw in ['login', 'auth', 'session']
        ):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Ignition debug handler endpoints.
        if '/_ignition/' in decoded or decoded == '/_ignition':
            body = self._ignition_page(method, decoded)
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # .env file disclosure probes.
        if '.env' in decoded or 'info.php' in decoded or 'laravel.log' in decoded:
            body = self._env_disclosure_page(decoded)
            return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

        # Default Laravel application / error page.
        body = self._laravel_error_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------ #
    # Response bodies
    # ------------------------------------------------------------------ #

    def _laravel_error_page(self) -> str:
        """Laravel 'Illuminate' debug error page (APP_DEBUG=true look)."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Whoops! There was an error.</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f7f7f7; color: #2d2d2d; margin: 0; padding: 40px; }}
        h1 {{ font-size: 22px; }}
        .container {{ max-width: 860px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Whoops! There was an error.</h1>
        <p>This page is served by <strong>Laravel {self.VERSION}</strong> using the
        <em>Illuminate</em> components.</p>
        <p>The application is running in <code>local</code> environment with debug
        enabled. Report this issue to the application administrator.</p>
        <hr>
        <p>Powered by <strong>Laravel</strong> &mdash; The PHP Framework for Web Artisans.</p>
    </div>
</body>
</html>"""

    def _ignition_page(self, method: str, path_lower: str) -> str:
        """Ignition debug handler page (/_ignition/*)."""
        if method == 'POST' and 'execute-solution' in path_lower:
            # Ignition "execute-solution" endpoint — return a JSON-style debug ack.
            return (
                '{"message":"The solution was executed successfully.",'
                '"solutions":[],"status":"ok"}'
            )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Ignition &mdash; Laravel Error Page</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }}
        h1 {{ font-size: 20px; color: #38bdf8; }}
        .container {{ max-width: 760px; margin: 0 auto; }}
        code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; color: #fbbf24; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Ignition</h1>
        <p>Laravel's error page and debugging toolkit. This instance is running
        <strong>Laravel {self.VERSION}</strong> with Ignition in debug mode.</p>
        <p>Available endpoints:</p>
        <ul>
            <li><code>POST /_ignition/execute-solution</code></li>
            <li><code>GET /_ignition</code></li>
            <li><code>GET /_ignition/health-check</code></li>
        </ul>
        <p>An exception occurred while rendering the page. Please check the
        application logs for more details.</p>
    </div>
</body>
</html>"""

    def _env_disclosure_page(self, path_lower: str) -> str:
        """Emulated .env / phpinfo / log disclosure content."""
        if 'info.php' in path_lower:
            return f"""<!DOCTYPE html>
<html><head><title>phpinfo()</title></head>
<body>
<h1>PHP Version 8.2.15</h1>
<p>Server API: FPM/FastCGI &mdash; Laravel {self.VERSION}</p>
<table><tr><td class="e">APP_ENV</td><td class="v">local</td></tr>
<tr><td class="e">APP_DEBUG</td><td class="v">true</td></tr>
<tr><td class="e">APP_KEY</td><td class="v">base64:REPLACE_ME_APP_KEY_HERE==</td></tr>
</table>
</body></html>"""
        if 'laravel.log' in path_lower:
            return (
                "[2026-07-08 12:00:01] local.ERROR: RuntimeException: "
                "Unable to boot Laravel application. in Laravel " + self.VERSION + "\n"
                "[2026-07-08 12:00:02] local.DEBUG: Session started for Laravel app\n"
            )
        # .env disclosure
        return (
            "APP_NAME=Laravel\n"
            "APP_ENV=local\nAPP_KEY=base64:REPLACE_ME_APP_KEY_HERE==\n"
            "APP_DEBUG=true\nAPP_URL=http://localhost\n\n"
            "LOG_CHANNEL=stack\nLOG_DEPRECATIONS_CHANNEL=null\nLOG_LEVEL=debug\n\n"
            "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n"
            "DB_DATABASE=laravel\nDB_USERNAME=root\nDB_PASSWORD=\n\n"
            "BROADCAST_DRIVER=log\nCACHE_DRIVER=file\nQUEUE_CONNECTION=sync\n"
            "SESSION_DRIVER=file\nSESSION_LIFETIME=120\n\n"
            "REDIS_HOST=127.0.0.1\nREDIS_PASSWORD=null\nREDIS_PORT=6379\n\n"
            "MAIL_MAILER=smtp\nMAIL_HOST=mailpit\nMAIL_PORT=1025\n\n"
            "AWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\n\n"
            "Laravel " + self.VERSION + "\n"
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = (
            '<html><head><title>Error</title></head><body>'
            '<h3>Error</h3>'
            '<p>These credentials do not match our records.</p>'
            '<p><a href="/login">Try again</a></p>'
            '</body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _decode_path(path: str) -> str:
        """Decode %2e -> '.', %2f -> '/', and other URL encodings."""
        try:
            decoded = urllib.parse.unquote(path)
        except Exception:
            decoded = path
        # Belt-and-suspenders for double-encoded or plus forms.
        decoded = decoded.replace('%2e', '.').replace('%2f', '/')
        return decoded

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
        """Build a complete HTTP response (iso-8859-1 bytes)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Laravel/{self.VERSION}\r\n'
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
        return f'LaravelHandler(domain={self.domain!r})'
