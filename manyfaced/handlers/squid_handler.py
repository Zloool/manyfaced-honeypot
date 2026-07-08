"""SquidHandler — emulates the Squid cache manager (cachemgr) HTTP interface.

Squid's ``cachemgr.cgi`` / ``squid-internal-mgr`` endpoints are a well known
attack surface: bots probe them to enumerate proxy internals (``info``,
``menu``, ``mgr/info``). This handler serves the HTML cache-manager page for
the manager root and a plain-text ``info`` report for the info action, mirroring
the responses a real Squid 6.x instance returns on those paths.

See issue #289.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import SQUID_HTTP

logger = logging.getLogger(__name__)


class SquidHandler(HTTPHandlerBase):
    """Squid cache-manager honeypot handler."""

    domain = 'squid'
    DETECTED_ID = SQUID_HTTP
    VERSION = '6.9'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Squid cachemgr response for the given request."""
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
        # Decode common URL-encoded path probes (%2e -> '.', %2f -> '/').
        decoded_path = self._decode_path(path)
        path_lower = decoded_path.lower()

        # The cachemgr CGI accepts login credentials (basic-auth style probing).
        if method == 'POST' or 'login' in path_lower or 'auth' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Plain-text info report for the info action.
        if path_lower.endswith('/info') or '/mgr/info' in path_lower:
            body = self._cachemgr_info()
            return (
                self._build_http_response(
                    body, 200, 'OK', content_type='text/plain; charset=UTF-8'
                ),
                self.DETECTED_ID,
            )

        # HTML cache-manager page for the manager root / menu / cgi.
        body = self._cachemgr_page(decoded_path)
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # -- response bodies ----------------------------------------------------

    def _cachemgr_page(self, path: str = '') -> str:
        """HTML Squid cache-manager page (mirrors cachemgr.cgi output)."""
        action = ''
        if '?' in path:
            action = path.split('?', 1)[1]
        action = action or 'menu'
        return f"""<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Squid Object Cache: Cache Manager</title>
</head>
<body bgcolor="#ffffff">
<h1>Squid Object Cache</h1>
<hr>
<h2>Cache Manager</h2>
<p>This is the Squid cachemgr.cgi interface. Use it to query the running
Squid proxy process for runtime statistics and configuration.</p>
<form method="GET" action="/squid-internal-mgr/{action}">
<table>
<tr><td>Cache Host:</td><td><input name="host" value="localhost:3128"></td></tr>
<tr><td>Manager name:</td><td><input name="mgr_name" value="{action}"></td></tr>
</table>
</form>
<hr>
<p>cachemgr.cgi is a CGi interface for querying the Squid proxy process.</p>
<ul>
<li><a href="/squid-internal-mgr/menu">menu</a></li>
<li><a href="/squid-internal-mgr/info">info</a></li>
<li><a href="/squid-internal-mgr/parameters">parameters</a></li>
<li><a href="/squid-internal-mgr/objects">objects</a></li>
</ul>
<hr>
<address>Squid {self.VERSION}</address>
</body>
</html>"""

    def _cachemgr_info(self) -> str:
        """Plain-text cachemgr 'info' report (mirrors 'GET info' output)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        return (
            f'Squid Object Cache: Version {self.VERSION}\n'
            f'Start Time:\t{now}\n'
            f'Current Time:\t{now}\n'
            'Connection information for squid:\n'
            '\tNumber of clients accessing cache:\t14\n'
            '\tNumber of HTTP requests received:\t23841\n'
            '\tNumber of ICP messages received:\t0\n'
            '\tNumber of ICP messages sent:\t0\n'
            '\tNumber of ICP messages queued:\t0\n'
            '\tNumber of HTTP requests received:\t23841\n'
            'Cache information for squid:\n'
            '\tHits as % of all requests:\t12.34\n'
            '\tHits as % of bytes sent:\t34.56\n'
            '\tMemory hits as % of hit requests:\t55.12\n'
            '\tDisk hits as % of hit requests:\t23.44\n'
            '\tStorage Swap size:\t1048576 KB\n'
            '\tStorage Mem size:\t262144 KB\n'
            '\tMean Object Size:\t13.42 KB\n'
            'File descriptor usage for squid:\n'
            '\tMaximum number of file descriptors:\t16384\n'
            '\tLargest file desc currently in use:\t42\n'
            '\tNumber of file desc currently in use:\t18\n'
            'Internal Data Structures:\n'
            '\tNumber of objects:\t1832\n'
            '\tMaximum Swap Size:\t10485760 KB\n'
        )

    def _login_failed_response(self) -> bytes:
        """Cachemgr login failed response — echoes 'Error' for probing bots."""
        body = '<html><body><h3>Authorization Error</h3><p>Invalid credentials.</p></body></html>'
        return self._build_http_response(body, 200, 'OK')

    # -- helpers ------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Decode common URL-encoded path probes (%2e -> '.', %2f -> '/')."""
        if '%' not in path:
            return path
        try:
            from urllib.parse import unquote

            return unquote(path)
        except Exception:  # pragma: no cover — unquote never raises here
            return path.replace('%2e', '.').replace('%2f', '/')

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
        """Build a complete HTTP response (encoded iso-8859-1)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: squid/{self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'SquidHandler(domain={self.domain!r})'
