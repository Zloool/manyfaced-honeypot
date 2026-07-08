"""HNAPHandler - scaffold stub for issue #288.

TODO: replace the placeholder page with a realistic HNAP impersonation
matching the production probe paths in the issue. Keep the class shape, the
DETECTED_ID constant, and the generate_response() signature intact.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import HNAP_HTTP

logger = logging.getLogger(__name__)


class HNAPHandler(HTTPHandlerBase):
    """HNAP honeypot handler (scaffold)."""

    domain = 'hnap'
    DETECTED_ID = HNAP_HTTP
    VERSION = '1.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a HNAP response for the given request."""
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

        if method == 'POST' and any(kw in path_lower for kw in ['login', 'auth']):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        body = self._main_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    def _main_page(self) -> str:
        """HNAP placeholder page (scaffold)."""
        return (
            '<!DOCTYPE html><html><head><title>HNAP</title></head>'
            f'<body><h1>HNAP</h1>'
            f'<p>Service: HNAP 1.0</p>'
            '</body></html>'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = (
            '<html><body><h3>Authorization Error</h3>'
            '<p>Invalid credentials.</p></body></html>'
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
            f'Server: HNAP/{self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'HNAPHandler(domain={self.domain!r})'
