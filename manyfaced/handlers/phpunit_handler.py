"""PhpUnitHandler - emulates a PHPUnit testing UI and surfaces the
eval-stdin RCE probe vector (CVE-2017-9841) for honeypot capture.

PHPUnit ships a legacy endpoint at::

    /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php

which does ``eval(file_get_contents('php://input'))`` on any request.
Attackers probe this path to achieve unauthenticated remote code
execution.  This handler deliberately emulates the PHPUnit testing
UI AND returns a realistic "Error" payload for the eval-stdin probe so
the request is captured and flagged as an attack.

Covered production probe paths (after %2e -> '.', %2f -> '/' decoding)::

    /phpunit
    /phpunit/phpunit
    /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
    /phpunit/scratch.php
    /phpunit/%2eenv
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote

import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

# The constant is expected to be defined in manyfaced.common.status.  If a
# merged PR has not added it yet, fall back to the next free HTTP detected-id
# (DBADMIN_HTTP == 1033 -> 1034) so the handler stays importable.  status.py is
# a shared file and must NOT be edited here.
try:  # pragma: no cover - exercised by import resolution
    from manyfaced.common.status import PHPUNIT_HTTP
except Exception:  # noqa: BLE001 - defensive fallback
    PHPUNIT_HTTP = 1034

logger = logging.getLogger(__name__)


class PhpUnitHandler(HTTPHandlerBase):
    """PHPUnit honeypot handler (issue #273)."""

    domain = 'phpunit'
    DETECTED_ID = PHPUNIT_HTTP
    VERSION = '11.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a PHPUnit response for the given request.

        Returns ``(response_bytes, detected_flag)``.
        """
        profile = self.get_or_create_profile(bot_ip)

        method = self._extract_method(raw_request)
        decoded_path = unquote(path)

        request_data = {
            'path': decoded_path,
            'method': method,
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        # --- eval-stdin.php RCE probe (CVE-2017-9841) ----------------------
        # This is the high-value detection: an attacker hitting the eval-stdin
        # endpoint is attempting unauthenticated RCE.  Flag it and echo a
        # realistic PHP "Error" execution result so the probe is captured.
        if 'eval-stdin.php' in decoded_path:
            request_data['attack'] = True
            request_data['cve'] = 'CVE-2017-9841'
            request_data['vector'] = 'phpunit_eval_stdin_rce'
            profile.record_request(request_data)
            return self._build_http_response(
                self._eval_stdin_response(), 200, 'OK'
            ), self.DETECTED_ID

        # --- PHPUnit test-runner UI ---------------------------------------
        # Serves a believable PHPUnit 11 UI for the canonical probe paths.
        if decoded_path == '/phpunit' or decoded_path.startswith('/phpunit/'):
            return self._build_http_response(self._phpunit_ui(), 200, 'OK'), self.DETECTED_ID

        # --- vendor/phpunit asset / library probing -----------------------
        if decoded_path.startswith('/vendor/phpunit'):
            return self._build_http_response(self._phpunit_ui(), 200, 'OK'), self.DETECTED_ID

        # Default: still serve the PHPUnit UI (covers scratch.php etc.)
        return self._build_http_response(self._phpunit_ui(), 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------
    # Response bodies
    # ------------------------------------------------------------------

    def _phpunit_ui(self) -> str:
        """Realistic PHPUnit 11 test-runner HTML UI."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PHPUnit {self.VERSION}</title>
<meta name="generator" content="PHPUnit {self.VERSION}">
<style>
body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; background: #1c1c1c; color: #eee; }}
.header {{ background: #1c1c1c; border-bottom: 4px solid #ff4713; padding: 20px 30px; }}
.header h1 {{ margin: 0; font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }}
.header h1 .v {{ color: #ff4713; }}
.banner {{ background: #ff4713; color: #fff; padding: 8px 30px; font-size: 13px; }}
.content {{ padding: 30px; }}
.code {{ background: #000; color: #0f0; padding: 15px; border-radius: 4px; font-family: "Courier New", monospace; font-size: 13px; }}
.footer {{ padding: 20px 30px; color: #888; font-size: 12px; border-top: 1px solid #333; }}
</style>
</head>
<body>
<div class="header">
    <h1>PHPUnit <span class="v">{self.VERSION}</span></h1>
</div>
<div class="banner">
    PHPUnit {self.VERSION} by Sebastian Bergmann and contributors.
</div>
<div class="content">
    <p>The PHP Unit Testing framework.</p>
    <div class="code">
$ vendor/bin/phpunit<br>
PHPUnit {self.VERSION}.0 by Sebastian Bergmann and contributors.<br>
<br>
Testing .<br>
OK (1 test, 1 assertion)
    </div>
    <p>Run your test suite with <code>vendor/bin/phpunit</code>.</p>
</div>
<div class="footer">
    &copy; Sebastian Bergmann - PHPUnit {self.VERSION}
</div>
</body>
</html>"""

    def _eval_stdin_response(self) -> str:
        """Mimic the PHP error emitted when eval-stdin.php executes untrusted
        POST body input (the CVE-2017-9841 RCE vector).  Contains ``Error``
        so probes can be trivially fingerprinted/captured."""
        return (
            '<br>\n'
            '<b>Fatal error</b>:  Uncaught Error: Call to undefined function '
            "in eval()'d code:1<br>\n"
            'Stack trace:<br>\n'
            '#0 /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php(1): eval()<br>\n'
            '#1 {main}<br>\n'
            "  thrown in <b>eval()'d code</b> on line 1<br>\n"
        )

    def _login_failed_response(self) -> bytes:
        """PHPUnit has no login flow; kept for API symmetry with base class."""
        body = self._phpunit_ui()
        return self._build_http_response(body, 200, 'OK')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: nginx/1.24.0\r\n'
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
        return f'PhpUnitHandler(domain={self.domain!r})'
