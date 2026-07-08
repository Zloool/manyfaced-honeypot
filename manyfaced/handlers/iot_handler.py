"""IoTHandler - emulates a generic IoT / consumer router web admin.

Provides realistic responses for the paths that real-world bot probes hit on
exposed routers and IoT gateways:

- Router admin login page for ``/``, ``/admin``, ``/login`` and ``/index.html``
- A UPnP/SOAP control endpoint under ``/upnp/`` (e.g. ``/upnp/control``)
- Generic CGI-bin responses under ``/cgi-bin/``
- A fake device "environment" disclosure for ``/IoT/%2eenv`` style probes
  (URL-encoded dots/slashes are normalised before dispatch)

Credentials submitted via POST to login/auth paths are captured and a generic
"Authorization Error" page is returned to keep the bot engaged.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import IOT_HTTP

logger = logging.getLogger(__name__)


class IoTHandler(HTTPHandlerBase):
    """Generic IoT / router web admin honeypot handler."""

    domain = 'iot'
    DETECTED_ID = IOT_HTTP
    VERSION = '1.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an IoT/router response for the given request."""
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

        # Normalise URL-encoded path separators that bots use to evade filters.
        norm_path = self._normalise_path(path)
        path_lower = norm_path.lower()

        # Capture credentials from any login/auth POST and bounce the bot.
        if method == 'POST' and ('login' in path_lower or 'auth' in path_lower):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # --- Response selection -------------------------------------------
        if '/upnp/' in path_lower:
            body = self._upnp_soap_response(norm_path)
            content_type = 'text/xml; charset="utf-8"'
        elif '/cgi-bin/' in path_lower:
            body = self._cgi_response(norm_path)
            content_type = 'text/html; charset=UTF-8'
        elif '/iot/' in path_lower:
            body = self._iot_env_response(norm_path)
            content_type = 'text/plain; charset=UTF-8'
        else:
            # ''/admin'/login'/index.html and everything else -> admin login
            body = self._admin_login_page()
            content_type = 'text/html; charset=UTF-8'

        return (
            self._build_http_response(body, 200, 'OK', content_type),
            self.DETECTED_ID,
        )

    # -- Page builders ----------------------------------------------------

    def _admin_login_page(self) -> str:
        """Router admin login page with a Router/IoT logo and login form."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Router - Administration</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; background: #eef2f7; margin: 0; }
.wrap { max-width: 380px; margin: 80px auto; background: #fff; border-radius: 8px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.15); overflow: hidden; }
.logo { background: #1f6feb; color: #fff; padding: 24px; text-align: center;
        font-size: 24px; font-weight: bold; letter-spacing: 1px; }
.form { padding: 24px; }
.form h2 { margin: 0 0 16px; font-size: 16px; color: #333; }
.row { margin-bottom: 12px; }
.row label { display: block; font-size: 13px; color: #555; margin-bottom: 4px; }
.row input { width: 100%; padding: 9px; border: 1px solid #ccc; border-radius: 4px;
             box-sizing: border-box; }
.btn { width: 100%; padding: 10px; background: #1f6feb; color: #fff; border: none;
       border-radius: 4px; font-size: 14px; cursor: pointer; }
.foot { padding: 12px 24px; font-size: 12px; color: #999; text-align: center;
        border-top: 1px solid #eee; }
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">Router</div>
  <div class="form">
    <h2>IoT Router Administration</h2>
    <form method="POST" action="/login">
      <div class="row">
        <label for="user">Username</label>
        <input type="text" id="user" name="user" autocomplete="off">
      </div>
      <div class="row">
        <label for="pass">Password</label>
        <input type="password" id="pass" name="pass">
      </div>
      <button type="submit" class="btn">Log In</button>
    </form>
  </div>
  <div class="foot">&copy; 2024 Router IoT Gateway &middot; Firmware v1.0</div>
</div>
</body>
</html>"""

    def _upnp_soap_response(self, path: str) -> str:
        """UPnP/SOAP control response.

        Mimics a typical InternetGatewayDevice SOAP service so UPnP probes get a
        plausible envelope back.
        """
        service = 'urn:schemas-upnp-org:service:WANIPConnection:1'
        action = 'GetExternalIPAddress'
        return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action}Response xmlns:u="{service}">
      <NewExternalIPAddress>192.168.0.1</NewExternalIPAddress>
      <NewUpTime>342195</NewUpTime>
      <NewConnectionStatus>Connected</NewConnectionStatus>
    </u:{action}Response>
  </s:Body>
</s:Envelope>"""

    def _cgi_response(self, path: str) -> str:
        """Generic CGI-bin response for router cgi probes."""
        return """<!DOCTYPE html>
<html><head><title>Router</title></head>
<body><h1>Router CGI</h1>
<p>Request handled by the device CGI interface.</p>
</body></html>"""

    def _iot_env_response(self, path: str) -> str:
        """Fake device environment disclosure for ``/IoT/.env`` style probes.

        Returns a benign-looking set of device variables. Decoy only - no real
        secrets.
        """
        return """# IoT device environment (emulated)
DEVICE_MODEL=IoT-Router-GW100
FIRMWARE_VERSION=1.0.4
DEVICE_ROLE=gateway
LAN_SUBNET=192.168.0.0/24
UPNP_ENABLED=true
TELNET_ENABLED=false
LOG_LEVEL=info
"""

    def _login_failed_response(self) -> bytes:
        """Generic authorization error page (keeps the bot probing)."""
        body = """<!DOCTYPE html>
<html><head><title>Router - Error</title></head>
<body>
<h3>Authorization Error</h3>
<p>Invalid username or password. Please try again.</p>
<p><a href="/login">Return to login</a></p>
</body></html>"""
        return self._build_http_response(body, 200, 'OK', 'text/html; charset=UTF-8')

    # -- Helpers ----------------------------------------------------------

    @staticmethod
    def _normalise_path(path: str) -> str:
        """Decode common URL-encoded separators used to bypass filters."""
        return (
            path.replace('%2e', '.')
            .replace('%2E', '.')
            .replace('%2f', '/')
            .replace('%2F', '/')
        )

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
        body_bytes = body.encode('iso-8859-1')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Router/{self.VERSION}\r\n'
            f'X-Powered-By: IoT-Gateway/1.0\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        )
        return response.encode('iso-8859-1') + body_bytes

    def __repr__(self) -> str:
        return f'IoTHandler(domain={self.domain!r})'
