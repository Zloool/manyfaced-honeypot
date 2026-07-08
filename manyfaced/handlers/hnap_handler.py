"""HNAPHandler - Home Network Administration Protocol honeypot face (issue #288).

Emulates the HNAP (Home Network Administration Protocol) XML control protocol
used by consumer routers (D-Link, Cisco/Linksys, etc.). Real-world bots and
exploit kits probe for the HNAP1 endpoint to fingerprint router models and to
drive the ``Login`` SOAP action for credential stuffing / RCE chains.

This handler returns a realistic HNAP XML document (root ``<HNAP>``,
``SOAPACTION``/module/control URLs) for the known probe paths and a generic
router login HTML page for the site root. Login POSTs are captured and answered
with an error response to encourage further probing.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from urllib.parse import unquote

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import HNAP_HTTP

logger = logging.getLogger(__name__)


class HNAPHandler(HTTPHandlerBase):
    """HNAP (Home Network Administration Protocol) honeypot handler."""

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
        """Generate an HNAP response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {
            'path': path,
            'method': self._extract_method(raw_request),
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        # Decode percent-encoded probes (%2e -> '.', %2f -> '/').
        path = self._decode_path(path)
        method = self._extract_method(raw_request)
        path_lower = path.lower()
        headers = headers or {}

        # Login / control POST (SOAP Login action or a credential path).
        if method == 'POST' and self._is_login(path_lower, raw_request, headers):
            self.handle_login(path, raw_request, bot_ip, headers)
            return self._login_failed_response(), self.DETECTED_ID

        # Site root: generic router login HTML.
        if path == '/':
            body = self._router_login_page()
            return (
                self._build_http_response(
                    body, 200, 'OK', 'text/html; charset=UTF-8'
                ),
                self.DETECTED_ID,
            )

        # Everything routed here is a HNAP probe -> XML control response.
        body = self._hnap_xml()
        return (
            self._build_http_response(
                body,
                200,
                'OK',
                'text/xml; charset=utf-8',
                soap_action='http://purenetworks.com/HNAP1/GetDeviceSettings',
            ),
            self.DETECTED_ID,
        )

    # ------------------------------------------------------------------ #
    # HNAP content builders
    # ------------------------------------------------------------------ #

    def _hnap_xml(self) -> str:
        """Return a realistic HNAP device-settings XML document.

        Root ``<HNAP>`` element with ``SOAPACTION`` hints and module/control
        URLs, matching the shape bots expect from a consumer router.
        """
        return (
            '<?xml version="1.0" encoding="utf-8"?>\r\n'
            '<HNAP xmlns="http://purenetworks.com/HNAP1/">\r\n'
            '  <Response>\r\n'
            '    <GetDeviceSettingsResult>OK</GetDeviceSettingsResult>\r\n'
            '    <Type>Gateway</Type>\r\n'
            '    <ModelName>DIR-825</ModelName>\r\n'
            '    <VendorName>D-Link</VendorName>\r\n'
            '    <FirmwareVersion>2.03NA</FirmwareVersion>\r\n'
            '    <DeviceName>Home Router</DeviceName>\r\n'
            '    <SOAPACTION>Login</SOAPACTION>\r\n'
            '    <ControlURL>/HNAP1</ControlURL>\r\n'
            '    <EventsURL>/HNAP1</EventsURL>\r\n'
            '    <ModuleList>\r\n'
            '      <Module>Control</Module>\r\n'
            '      <Module>WAN</Module>\r\n'
            '      <Module>LAN</Module>\r\n'
            '      <Module>WLAN</Module>\r\n'
            '    </ModuleList>\r\n'
            '  </Response>\r\n'
            '</HNAP>'
        )

    def _router_login_page(self) -> str:
        """Generic router administration login page for the site root."""
        return (
            '<!DOCTYPE html><html><head><title>Router Login</title></head>'
            '<body><h1>Router Administration</h1>'
            '<form method="POST" action="/HNAP1">'
            '<label>Username</label>'
            '<input type="text" name="Username"><br>'
            '<label>Password</label>'
            '<input type="password" name="LoginPassword"><br>'
            '<input type="submit" value="Log In">'
            '</form></body></html>'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response (HNAP XML) - encourages further probing."""
        body = (
            '<?xml version="1.0" encoding="utf-8"?>\r\n'
            '<HNAP1 xmlns="http://purenetworks.com/HNAP1/">\r\n'
            '  <LoginResponse>\r\n'
            '    <LoginResult>Error</LoginResult>\r\n'
            '    <Message>Invalid credentials</Message>\r\n'
            '  </LoginResponse>\r\n'
            '</HNAP1>'
        )
        return self._build_http_response(
            body,
            200,
            'OK',
            'text/xml; charset=utf-8',
            soap_action='http://purenetworks.com/HNAP1/Login',
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _decode_path(path: str) -> str:
        """Decode percent-encoded path segments (%2e -> '.', %2f -> '/')."""
        return unquote(path)

    @staticmethod
    def _is_login(
        path_lower: str,
        raw_request: str,
        headers: dict[str, str],
    ) -> bool:
        """Decide whether a POST targets the HNAP Login control action."""
        if 'login' in path_lower or 'auth' in path_lower:
            return True
        soap = (headers.get('SOAPACTION') or headers.get('SOAPAction') or '').lower()
        if 'login' in soap:
            return True
        # Body-level HNAP Login envelope.
        return '<login' in raw_request.lower()

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
        soap_action: str | None = None,
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('iso-8859-1')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: HNAP/{self.VERSION}\r\n'
            f'Date: {now}\r\n'
        )
        if soap_action:
            response += f'SOAPACTION: {soap_action}\r\n'
        response += (
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'HNAPHandler(domain={self.domain!r})'
