"""SolrHandler – Apache Solr honeypot handler (issue #279).

Emulates the Apache Solr Admin UI and the Solr query/API surface so that
real-world Solr probes (config API, collection select, cores listing, info
system, authentication, and the classic /.env/.git probe paths) receive
plausible responses.  Captured login attempts on authentication endpoints
return a failed-auth page to encourage further probing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import SOLR_HTTP

logger = logging.getLogger(__name__)


class SolrHandler(HTTPHandlerBase):
    """Apache Solr honeypot handler."""

    domain = 'solr'
    DETECTED_ID = SOLR_HTTP
    VERSION = '9.4.0'

    # Probe paths seen in production scans (decoded form).
    CORES_PATH = '/solr/admin/cores'
    INFO_SYSTEM_PATH = '/solr/admin/info/system'
    AUTH_PATH = '/solr/admin/authentication'
    SELECT_PATH = '/solr/collection1/select'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an Apache Solr response for the given request."""
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

        # Decode percent-encoded probes: %2e -> '.', %2f -> '/'
        decoded = self._decode_path(path)
        path_lower = decoded.lower()

        # Login / authentication POST attempts -> capture + fake failure.
        if method == 'POST' and ('login' in path_lower or 'auth' in path_lower):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # ---- Route to the appropriate Solr response -----------------------
        if decoded == self.CORES_PATH or path_lower.endswith('/admin/cores'):
            body = self._cores_response()
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID
        if decoded == self.INFO_SYSTEM_PATH or path_lower.endswith('/admin/info/system'):
            body = self._info_system_response()
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID
        if decoded == self.AUTH_PATH or 'authentication' in path_lower:
            body = self._authentication_response()
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID
        if self.SELECT_PATH in decoded or path_lower.endswith('/select'):
            body = self._select_response()
            return self._build_http_response(body, 200, 'OK', self._json_type()), self.DETECTED_ID

        # Everything else Solr-ish (the admin dashboard, /solr, /solr/admin/,
        # /.env, /.git, etc.) gets the Admin UI HTML page.
        body = self._admin_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # -- Response builders --------------------------------------------------

    def _admin_page(self) -> str:
        """Apache Solr Admin UI dashboard HTML page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Apache Solr</title>
<link rel="icon" href="/solr/favicon.ico" type="image/x-icon">
<style>
  body { font-family: 'Lucida Grande', Helvetica, Arial, sans-serif; margin: 0; background: #f6f6f6; color: #333; }
  .header { background: #3b3b3b; color: #fff; padding: 14px 24px; display: flex; align-items: center; }
  .logo { font-size: 22px; font-weight: bold; letter-spacing: 0.5px; }
  .logo span { color: #4c9aff; }
  .subtitle { margin-left: auto; font-size: 13px; opacity: 0.8; }
  .wrap { max-width: 980px; margin: 32px auto; padding: 0 24px; }
  h1 { font-size: 26px; }
  .cards { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 24px; }
  .card { background: #fff; border: 1px solid #e1e1e1; border-radius: 6px; padding: 18px 22px; min-width: 200px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .card h2 { margin: 0 0 6px; font-size: 15px; color: #3b3b3b; }
  .card p { margin: 0; color: #888; font-size: 13px; }
  .footer { margin-top: 40px; font-size: 12px; color: #aaa; text-align: center; }
  code { background: #eee; padding: 1px 5px; border-radius: 3px; }
</style>
</head>
<body>
  <div class="header">
    <div class="logo">Apache <span>Solr</span></div>
    <div class="subtitle">Admin UI &middot; Version 9.4.0</div>
  </div>
  <div class="wrap">
    <h1>Apache Solr Dashboard</h1>
    <p>Welcome to the Apache Solr admin interface. Use the links below to manage cores, collections and query your indexes.</p>
    <div class="cards">
      <div class="card">
        <h2>Core Admin</h2>
        <p><a href="/solr/admin/cores">View cores</a></p>
      </div>
      <div class="card">
        <h2>System Info</h2>
        <p><a href="/solr/admin/info/system">Server details</a></p>
      </div>
      <div class="card">
        <h2>Query</h2>
        <p><a href="/solr/collection1/select?q=*:*">Search collection1</a></p>
      </div>
      <div class="card">
        <h2>Authentication</h2>
        <p><a href="/solr/admin/authentication">Security</a></p>
      </div>
    </div>
    <div class="footer">
      Powered by Apache Solr &middot; https://solr.apache.org
    </div>
  </div>
</body>
</html>"""

    def _cores_response(self) -> str:
        """JSON response for /solr/admin/cores."""
        payload = {
            'responseHeader': {'status': 0, 'QTime': 1},
            'status': 'OK',
            'initFailures': {},
            'defaultCoreName': 'collection1',
            'solr_core_status': {
                'collection1': {
                    'name': 'collection1',
                    'instanceDir': '/var/solr/data/collection1',
                    'dataDir': '/var/solr/data/collection1/data/',
                    'config': 'solrconfig.xml',
                    'schema': 'schema.xml',
                    'startTime': '2024-01-01T00:00:00.000Z',
                    'uptime': 1234567,
                    'index': {
                        'numDocs': 1042,
                        'maxDoc': 1050,
                        'deletedDocs': 8,
                        'version': 157,
                        'sizeInBytes': 4823041,
                    },
                }
            },
        }
        return json.dumps(payload)

    def _info_system_response(self) -> str:
        """JSON response for /solr/admin/info/system."""
        payload = {
            'responseHeader': {'status': 0, 'QTime': 0},
            'status': 'OK',
            'mode': 'solrcloud',
            'solr_home': '/var/solr/data',
            'lucene': {
                'solr-spec-version': self.VERSION,
                'lucene-spec-version': '9.8.0',
            },
            'jvm': {
                'version': '17.0.9 2023-10-17',
                'vmName': 'OpenJDK 64-Bit Server VM',
                'processors': 4,
                'memory': {'free': 214748364, 'total': 1073741824, 'max': 2147483648},
            },
            'system': {
                'name': 'Linux',
                'version': '5.15.0',
                'arch': 'amd64',
            },
        }
        return json.dumps(payload)

    def _authentication_response(self) -> str:
        """JSON response for /solr/admin/authentication."""
        payload = {
            'responseHeader': {'status': 0, 'QTime': 0},
            'status': 'OK',
            'authentication': {
                'class': 'solr.BasicAuthPlugin',
                'blockUnknown': True,
                'credentials': {'solr': 'REDACTED'},
            },
            'authorization': {
                'class': 'solr.RuleBasedAuthorizationPlugin',
                'user-role': {'solr': ['admin']},
                'permissions': [
                    {'name': 'all', 'role': 'admin'},
                ],
            },
        }
        return json.dumps(payload)

    def _select_response(self) -> str:
        """JSON response for /solr/<collection>/select query endpoint."""
        payload = {
            'responseHeader': {'status': 0, 'QTime': 3, 'params': {'q': '*:*', 'rows': '10'}},
            'status': 'OK',
            'response': {'numFound': 1042, 'start': 0, 'docs': []},
        }
        return json.dumps(payload)

    def _login_failed_response(self) -> bytes:
        """Login failed page – encourages the bot to keep probing."""
        body = (
            '<!DOCTYPE html><html><head><title>Apache Solr - Error</title></head>'
            '<body><h3>Authorization Error</h3>'
            '<p>Error: Invalid username or password. Please try again.</p>'
            '<p><a href="/solr/admin/authentication">Return to security</a></p>'
            '</body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    # -- Helpers ------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Decode percent-encoded probe segments (%2e -> '.', %2f -> '/')."""
        decoded = unquote_plus(path)
        decoded = decoded.replace('%2E', '.').replace('%2F', '/')
        decoded = decoded.replace('%2e', '.').replace('%2f', '/')
        return decoded

    def _json_type(self) -> str:
        return 'application/json; charset=UTF-8'

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
        """Build a complete HTTP response (iso-8859-1 wire encoding)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Apache Solr/{self.VERSION}\r\n'
            f'X-Solr: {self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'SolrHandler(domain={self.domain!r})'
