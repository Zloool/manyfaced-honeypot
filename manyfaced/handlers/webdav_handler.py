"""WebDAVHandler – handles WebDAV specific paths and interactions.

Provides realistic WebDAV responses including directory listings, PROPFIND XML,
PUT/POST file upload attempts, and credential capture from Basic Auth headers.

Response content is delegated to webdav_responses module; HTTP response building
is inherited from base_handler.HTTPHandlerBase.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import WEBDAV_HTTP
from manyfaced.handlers.webdav_responses import (
    directory_listing as _directory_listing,
    forbidden_response as _forbidden_response,
    login_failed_response as _login_failed_response,
    propfind_response as _propfind_response,
    webdav_login_page as _webdav_login_page,
    webdav_portal_page as _webdav_portal_page,
)

logger = __import__('logging').getLogger(__name__)


class WebDAVHandler(HTTPHandlerBase):
    """WebDAV honeypot handler."""

    domain = 'webdav'
    DETECTED_ID = WEBDAV_HTTP

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a WebDAV response for the given request."""
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
        headers_dict = dict(headers) if headers else {}

        # Extract Basic Auth credentials if present
        auth_header = headers_dict.get('Authorization', '')
        if auth_header.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8', errors='replace')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    profile.capture_credentials({'username': username, 'password': password})
            except Exception:
                logger.debug('Failed to parse WebDAV Basic Auth header')

        # Handle PROPFIND requests (WebDAV directory listing)
        if method == 'PROPFIND':
            body = _propfind_response(path)
            return self._build_http_response(
                body,
                207,
                'Multi-Status',
                {'Content-Type': 'application/xml; charset=utf-8', 'DAV': '1, 2'},
            ), self.DETECTED_ID

        # Handle OPTIONS requests (WebDAV capabilities probe)
        if method == 'OPTIONS':
            return self._options_response()

        # Handle MKCOL requests (create directory)
        if method == 'MKCOL':
            return self._build_http_response(b'', 201, 'Created'), self.DETECTED_ID

        # Handle DELETE requests
        if method == 'DELETE':
            return self._build_http_response(b'', 204, 'No Content'), self.DETECTED_ID

        # Handle PUT requests (file upload attempt)
        if method == 'PUT':
            profile.record_request(
                {
                    'path': path,
                    'method': method,
                    'headers': headers_dict,
                    'raw': raw_request[:5000] + (' [truncated]' if len(raw_request) > 5000 else ''),
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }
            )
            profile.escalation_label = 'file_upload_attempt'
            return self._build_http_response(
                b'',
                201,
                'Created',
                {'Content-Type': 'text/html; charset=utf-8'},
            ), self.DETECTED_ID

        # Handle POST requests (upload, login, etc.)
        if method == 'POST':
            if 'login' in path_lower or 'auth' in path_lower:
                credentials, response, detected = self.handle_login(
                    path, raw_request, bot_ip, headers_dict
                )
                if credentials:
                    return self._login_failed_response()
            content_type = headers_dict.get('Content-Type', '')
            if 'multipart/form-data' in content_type or 'application/octet-stream' in content_type:
                profile.record_request(
                    {
                        'path': path,
                        'method': method,
                        'headers': headers_dict,
                        'raw': raw_request[:5000]
                        + (' [truncated]' if len(raw_request) > 5000 else ''),
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    }
                )
                profile.escalation_label = 'file_upload_attempt'
                return self._build_http_response(
                    b'',
                    201,
                    'Created',
                    {'Content-Type': 'text/html; charset=utf-8'},
                ), self.DETECTED_ID

        # Handle GET requests (directory listing)
        if method == 'GET':
            if '/server.php' in path_lower or '/index.php' in path_lower:
                body = _webdav_portal_page()
            elif '/.htaccess' in path_lower or '/.htpasswd' in path_lower:
                return self._forbidden_response()
            elif '/config.php' in path_lower or '/setup.php' in path_lower:
                return self._forbidden_response()
            elif '/admin/' in path_lower or '/login/' in path_lower or '/auth/' in path_lower:
                body = _webdav_login_page()
            else:
                body = _directory_listing(path)

            return self._build_http_response(
                body,
                200,
                'OK',
                {'Content-Type': 'text/html; charset=utf-8', 'DAV': '1, 2'},
            ), self.DETECTED_ID

        # Handle other WebDAV methods
        if method in ('HEAD', 'PATCH', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'):
            profile.escalation_label = f'webdav_{method.lower()}_attempt'
            return self._build_http_response(b'', 200, 'OK'), self.DETECTED_ID

        # Default: 405 Method Not Allowed
        return self._build_http_response(
            b'',
            405,
            'Method Not Allowed',
            {'Allow': 'GET, HEAD, POST, OPTIONS, PROPFIND, MKCOL, PUT, DELETE, MOVE, COPY'},
        ), self.DETECTED_ID

    def _options_response(self) -> tuple[bytes, int]:
        """Generate WebDAV OPTIONS response (capabilities probe)."""
        return self._build_http_response(
            b'',
            200,
            'OK',
            {
                'DAV': '1, 2',
                'MS-Author-Via': 'DAV',
                'Allow': 'GET, HEAD, POST, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, PUT, DELETE',
            },
        ), self.DETECTED_ID

    def _login_failed_response(self) -> tuple[bytes, int]:
        """WebDAV login failed response."""
        body = _login_failed_response()
        return self._build_http_response(body, 401, 'Unauthorized'), self.DETECTED_ID

    def _forbidden_response(self) -> tuple[bytes, int]:
        """Return 403 Forbidden for sensitive files."""
        body = _forbidden_response()
        return self._build_http_response(body, 403, 'Forbidden'), self.DETECTED_ID

    @staticmethod
    def _extract_method(raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str | bytes,
        status_code: int = 200,
        status_text: str = 'OK',
        headers: dict | None = None,
    ) -> bytes:
        """Build a complete HTTP response."""
        if isinstance(body, str):
            body_bytes = body.encode('utf-8')
        else:
            body_bytes = body

        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        # Calculate body length for Content-Length header
        if isinstance(body_bytes, str):
            body_len = len(body_bytes.encode('iso-8859-1'))
        else:
            body_len = len(body_bytes)

        resp_headers = {
            'Server': 'Apache/2.4.57 (Ubuntu)',
            'Date': now,
            'Connection': 'close',
            'Content-Length': str(body_len),
        }
        if headers:
            resp_headers.update(headers)

        header_lines = []
        for key, value in resp_headers.items():
            header_lines.append(f'{key}: {value}')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            + '\r\n'.join(header_lines)
            + '\r\n'
            + '\r\n'
        )

        return response.encode('iso-8859-1') + body_bytes

    def __repr__(self) -> str:
        return f'WebDAVHandler(domain={self.domain!r})'
