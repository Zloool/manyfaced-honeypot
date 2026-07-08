"""PlexHandler – emulates a Plex Media Server (issue #284).

Provides realistic Plex Media Server responses including:
- The Plex web client app shell (/web)
- The UPnP/XML DeviceDescription served at /identity and /:32400/web
- The Plex XML API surface probed by scanners:
  - /status/sessions
  - /myplex/account
  - /library/sections
  - /player
- A sensitive-file disclosure trap for /plex/.env (decoded from /plex/%2eenv)

Plex Media Server is a popular self-hosted media platform frequently
targeted by automated probes and credential stuffers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import PLEX_HTTP

logger = logging.getLogger(__name__)


class PlexHandler(HTTPHandlerBase):
    """Plex Media Server honeypot handler."""

    domain = 'plex'
    DETECTED_ID = PLEX_HTTP
    VERSION = '1.40.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Plex response for the given request."""
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

        if method == 'POST' and (
            'login' in path.lower() or 'auth' in path.lower() or path.lower().startswith('/myplex')
        ):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        decoded = self._decode_path(path)

        if decoded in ('/web', '/:32400/web'):
            if decoded == '/web':
                body = self._web_app_page()
                content_type = 'text/html; charset=UTF-8'
            else:
                body = self._device_description()
                content_type = 'text/xml; charset=UTF-8'
            return self._build_http_response(body, 200, 'OK', content_type), self.DETECTED_ID

        if decoded == '/identity':
            body = self._device_description()
            return self._build_http_response(
                body, 200, 'OK', 'text/xml; charset=UTF-8'
            ), self.DETECTED_ID

        if decoded == '/status/sessions':
            body = self._status_sessions()
            return self._build_http_response(
                body, 200, 'OK', 'text/xml; charset=UTF-8'
            ), self.DETECTED_ID

        if decoded.startswith('/myplex/') or decoded == '/myplex':
            body = self._myplex_account()
            return self._build_http_response(
                body, 200, 'OK', 'text/xml; charset=UTF-8'
            ), self.DETECTED_ID

        if decoded == '/library/sections' or decoded.startswith('/library/'):
            body = self._library_sections()
            return self._build_http_response(
                body, 200, 'OK', 'text/xml; charset=UTF-8'
            ), self.DETECTED_ID

        if decoded == '/player':
            body = self._player_response()
            return self._build_http_response(
                body, 200, 'OK', 'text/xml; charset=UTF-8'
            ), self.DETECTED_ID

        if decoded.startswith('/plex/'):
            body = self._plex_env_disclosure()
            return self._build_http_response(
                body, 200, 'OK', 'text/plain; charset=UTF-8'
            ), self.DETECTED_ID

        body = self._web_app_page()
        return self._build_http_response(
            body, 200, 'OK', 'text/html; charset=UTF-8'
        ), self.DETECTED_ID

    def _web_app_page(self) -> str:
        """Plex web client app shell (HTML)."""
        return (
            '<!DOCTYPE html>\n'
            '<html lang="en">\n'
            '<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<title>Plex</title>\n'
            '<link rel="stylesheet" href="/web/css/plex.css">\n'
            '<script src="/web/js/plex.js"></script>\n'
            '</head>\n'
            '<body class="plex-web">\n'
            '<header class="plex-header">\n'
            '  <div class="plex-logo" aria-label="Plex">\n'
            '    <svg viewBox="0 0 100 30" width="80" height="24" role="img">\n'
            '      <path fill="#e5a00d" d="M0 0h20l10 15L20 30H0zM30 0h20l10 15L50 30H30zM60 0h20l10 15L80 30H60zM90 0h10v30H90z"/>\n'
            '    </svg>\n'
            '    <span class="plex-wordmark">Plex</span>\n'
            '  </div>\n'
            '  <nav class="plex-nav">\n'
            '    <a href="/web/index.html">Home</a>\n'
            '    <a href="/library/sections">Libraries</a>\n'
            '    <a href="/myplex/account">Account</a>\n'
            '  </nav>\n'
            '</header>\n'
            '<main class="plex-main">\n'
            '  <h1>Welcome to Plex</h1>\n'
            '  <p>Plex Media Server version 1.40.0 is running.</p>\n'
            '  <p>Sign in to access your media.</p>\n'
            '  <form method="POST" action="/myplex/account">\n'
            '    <input type="text" name="user" placeholder="Email or username" autocomplete="off">\n'
            '    <input type="password" name="password" placeholder="Password">\n'
            '    <input type="submit" value="Sign In">\n'
            '  </form>\n'
            '</main>\n'
            '<footer class="plex-footer">\n'
            '  <p>&copy; Plex, Inc. All rights reserved.</p>\n'
            '</footer>\n'
            '</body>\n'
            '</html>'
        )

    def _device_description(self) -> str:
        """Plex UPnP DeviceDescription XML (served at /identity and /:32400/web)."""
        serial = 'plex-honeypot-1017'
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<root xmlns="urn:schemas-upnp-org:device-1-0">\n'
            '  <specVersion>\n'
            '    <major>1</major>\n'
            '    <minor>0</minor>\n'
            '  </specVersion>\n'
            '  <device>\n'
            '    <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>\n'
            '    <friendlyName>Plex Media Server</friendlyName>\n'
            '    <manufacturer>Plex, Inc.</manufacturer>\n'
            '    <manufacturerURL>https://www.plex.tv/</manufacturerURL>\n'
            '    <modelName>Plex Media Server</modelName>\n'
            '    <modelNumber>1.40.0</modelNumber>\n'
            '    <modelURL>https://www.plex.tv/</modelURL>\n'
            '    <serialNumber>' + serial + '</serialNumber>\n'
            '    <presentationURL>/web</presentationURL>\n'
            '    <serverVersion>1.40.0</serverVersion>\n'
            '    <protocolVersion>1.40.0</protocolVersion>\n'
            '    <protocolCapabilities>navigation,streaming,http-live-streaming,http-mp4-streaming,http-video-streaming</protocolCapabilities>\n'
            '    <serviceList>\n'
            '      <service>\n'
            '        <serviceType>urn:schemas-plex-tv:service:plexmediaserver:1</serviceType>\n'
            '        <serviceId>urn:plex-tv:serviceId:PMS</serviceId>\n'
            '        <controlURL>/</controlURL>\n'
            '        <eventSubURL>/</eventSubURL>\n'
            '        <SCPDURL>/</SCPDURL>\n'
            '      </service>\n'
            '    </serviceList>\n'
            '  </device>\n'
            '</root>\n'
        )

    def _status_sessions(self) -> str:
        """Plex /status/sessions XML (active playback sessions)."""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<MediaContainer size="0" allowSync="0" identifier="com.plexapp.plugins.library" '
            'mediaTagPrefix="/system/bundle/media/flags/" mediaTagVersion="123456">\n'
            '</MediaContainer>\n'
        )

    def _myplex_account(self) -> str:
        """Plex /myplex/account XML (MyPlex account info)."""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<MediaContainer>\n'
            '  <User id="1017" email="user@example.com" username="honeypot" '
            'title="honeypot" cloudSyncEnabled="0" authToken=""></authToken>\n'
            '</MediaContainer>\n'
        )

    def _library_sections(self) -> str:
        """Plex /library/sections XML (configured libraries)."""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<MediaContainer size="2" allowSync="0" identifier="com.plexapp.plugins.library" '
            'mediaTagPrefix="/system/bundle/media/flags/" mediaTagVersion="123456">\n'
            '  <Directory allowSync="0" art="/:/resources/movie-fanart.jpg" '
            'id="1" key="1" type="movie" title="Movies" />\n'
            '  <Directory allowSync="0" art="/:/resources/tv-fanart.jpg" '
            'id="2" key="2" type="show" title="TV Shows" />\n'
            '</MediaContainer>\n'
        )

    def _player_response(self) -> str:
        """Plex /player XML (connected players)."""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<MediaContainer size="0" machineIdentifier="plex-honeypot-1017">\n'
            '</MediaContainer>\n'
        )

    def _plex_env_disclosure(self) -> str:
        """Sensitive-file disclosure trap for /plex/.env probes."""
        return (
            'PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR=/var/lib/plexmediaserver/Application Support\n'
            'PLEX_MEDIA_SERVER_HOME=/usr/lib/plexmediaserver\n'
            'PLEX_MEDIA_SERVER_MAX_PLUGIN_PROCESSES=6\n'
            'PLEX_MEDIA_SERVER_USER=plex\n'
            'PLEX_MEDIA_SERVER_TMPDIR=/tmp\n'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = (
            '<html><body><h3>Authorization Error</h3>'
            '<p>Invalid credentials. Please try again.</p></body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    @staticmethod
    def _decode_path(path: str) -> str:
        """Decode probe path encodings: %2e -> '.', %2f -> '/'."""
        return path.replace('%2e', '.').replace('%2E', '.').replace('%2f', '/').replace('%2F', '/')

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
        """Build a complete HTTP response (iso-8859-1 transport encoding)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Plex/{self.VERSION}\r\n'
            f'X-Plex-Protocol: 1.0\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Date: {now}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'PlexHandler(domain={self.domain!r})'
