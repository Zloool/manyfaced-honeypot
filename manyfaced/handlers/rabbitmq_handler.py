"""RabbitMQHandler – honeypot face for the RabbitMQ Management UI / HTTP API.

Emulates the RabbitMQ Management Plugin so that probes of a real RabbitMQ
instance are captured.  Covers the production probe paths documented in
issue #285:

    /                       -> Management sign-in page (HTML)
    /cli/                   -> CLI / rabbitmqctl-style landing page (HTML)
    /api/                   -> API index (JSON)
    /api/overview           -> cluster overview (JSON)
    /api/queues             -> queue list (JSON)
    /api/exchanges          -> exchange list (JSON)
    /api/connections        -> connection list (JSON)
    /api/whoami             -> current user (JSON)
    /api/aliveness-test/%2f  -> aliveness test for vhost '/' (JSON)
    /rabbitmq/%2eenv        -> .env-style disclosure probe (text)

Percent-encoded segments in the path are normalized before routing
(%2e -> '.', %2f -> '/'), matching what the real management plugin receives
after the HTTP layer decodes the URL.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import RABBITMQ_HTTP

logger = logging.getLogger(__name__)


class RabbitMQHandler(HTTPHandlerBase):
    """RabbitMQ Management honeypot handler."""

    domain = 'rabbitmq'
    DETECTED_ID = RABBITMQ_HTTP
    VERSION = '3.13.0'

    # Substrings that indicate a credential-submission attempt.
    _LOGIN_KEYWORDS = ('login', 'auth', 'signin', 'sign-in', 'session')

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a RabbitMQ response for the given request."""
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

        # Credential submission (login / auth) -> capture + fake failure.
        if method == 'POST' and any(kw in path_lower for kw in self._LOGIN_KEYWORDS):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Normalize percent-encoding so routing matches decoded probe paths.
        decoded = self._decode_path(path)
        decoded_lower = decoded.lower()

        # --- API surface (JSON) -------------------------------------------
        if decoded_lower.startswith('/api/'):
            if decoded_lower == '/api/overview':
                body, content_type = self._api_overview(), 'application/json'
            elif decoded_lower == '/api/whoami':
                body, content_type = self._api_whoami(), 'application/json'
            elif decoded_lower.startswith('/api/aliveness-test/'):
                body, content_type = (
                    self._api_aliveness(decoded),
                    'application/json',
                )
            elif decoded_lower == '/api/queues':
                body, content_type = self._api_queues(), 'application/json'
            elif decoded_lower == '/api/exchanges':
                body, content_type = self._api_exchanges(), 'application/json'
            elif decoded_lower == '/api/connections':
                body, content_type = self._api_connections(), 'application/json'
            else:
                body, content_type = self._api_index(), 'application/json'
            return (
                self._build_http_response(body, 200, 'OK', content_type),
                self.DETECTED_ID,
            )

        # --- .env disclosure probe (text) --------------------------------
        if decoded_lower.startswith('/rabbitmq/') and decoded_lower.endswith('.env'):
            body = self._env_disclosure()
            return (
                self._build_http_response(body, 200, 'OK', 'text/plain; charset=UTF-8'),
                self.DETECTED_ID,
            )

        # --- CLI / management UI landing (HTML) --------------------------
        if decoded_lower.startswith('/cli/'):
            body = self._cli_page()
        else:
            body = self._management_login_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    # ------------------------------------------------------------------ #
    # Percent-decoding helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _decode_path(path: str) -> str:
        """Decode the path segments relevant to RabbitMQ probes.

        Only the two encodings seen in production probes are decoded
        (%2e -> '.', %2f -> '/') so routing matches the real plugin.
        """
        return path.replace('%2e', '.').replace('%2E', '.').replace('%2f', '/').replace('%2F', '/')

    # ------------------------------------------------------------------ #
    # HTML responses
    # ------------------------------------------------------------------ #
    def _management_login_page(self) -> str:
        """RabbitMQ Management UI sign-in page."""
        return (
            """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RabbitMQ Management</title>
<style>
  body { font-family: "Helvetica Neue", Arial, sans-serif; background: #f0f0f0; margin: 0; }
  .login-box { width: 360px; margin: 80px auto; background: #fff; border-radius: 6px;
               box-shadow: 0 2px 8px rgba(0,0,0,0.15); padding: 32px; }
  .logo { text-align: center; margin-bottom: 24px; }
  .logo img { height: 48px; }
  h1 { text-align: center; font-size: 20px; color: #f60; margin: 0 0 4px; }
  .subtitle { text-align: center; color: #888; font-size: 13px; margin-bottom: 24px; }
  label { display: block; font-size: 13px; color: #555; margin: 12px 0 4px; }
  input[type=text], input[type=password] { width: 100%; padding: 9px; border: 1px solid #ccc;
               border-radius: 4px; box-sizing: border-box; font-size: 14px; }
  button { width: 100%; margin-top: 20px; padding: 10px; background: #f60; color: #fff;
               border: none; border-radius: 4px; font-size: 14px; cursor: pointer; }
  button:hover { background: #e55b00; }
  .footer { text-align: center; color: #aaa; font-size: 12px; margin-top: 20px; }
</style>
</head>
<body>
  <div class="login-box">
    <div class="logo">
      <img src="/img/rabbitmq-logo.svg" alt="RabbitMQ">
    </div>
    <h1>RabbitMQ</h1>
    <div class="subtitle">Management Plugin &mdash; """
            + self.VERSION
            + """</div>
    <form method="POST" action="/api/whoami" name="loginForm" autocomplete="off">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="off">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="off">
      <button type="submit">Sign in</button>
    </form>
    <div class="footer">Copyright &copy; 2007&ndash;2024 VMware, Inc. or its affiliates.</div>
  </div>
</body>
</html>"""
        )

    def _cli_page(self) -> str:
        """RabbitMQ CLI landing page (mqtt/cli-style console hint)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RabbitMQ CLI</title>
</head>
<body>
<h1>RabbitMQ</h1>
<p>RabbitMQ Command Line Tools</p>
<ul>
  <li><code>rabbitmqctl</code> &mdash; broker control</li>
  <li><code>rabbitmq-diagnostics</code> &mdash; health &amp; status</li>
  <li><code>rabbitmq-plugins</code> &mdash; plugin management</li>
</ul>
<p>Management API available at <a href="/api/">/api/</a>.</p>
</body>
</html>"""

    def _env_disclosure(self) -> str:
        """Fake .env-style disclosure for the /rabbitmq/.env probe."""
        return (
            'RABBITMQ_DEFAULT_USER=guest\n'
            'RABBITMQ_DEFAULT_PASS=guest\n'
            'RABBITMQ_MANAGEMENT_PORT=15672\n'
            'RABBITMQ_ERLANG_COOKIE=SFMYZNUVIRKCOABZJLQN\n'
            'RABBITMQ_NODENAME=rabbit@localhost\n'
        )

    # ------------------------------------------------------------------ #
    # JSON API responses
    # ------------------------------------------------------------------ #
    def _api_index(self) -> str:
        """RabbitMQ HTTP API index."""
        overview = {
            'rabbitmq_version': self.VERSION,
            'product': 'RabbitMQ',
            'links': {
                'overview': './api/overview',
                'queues': './api/queues',
                'exchanges': './api/exchanges',
                'connections': './api/connections',
                'whoami': './api/whoami',
            },
        }
        return json.dumps(overview)

    def _api_overview(self) -> str:
        """Cluster overview &mdash; the most-probed API endpoint."""
        overview = {
            'rabbitmq_version': self.VERSION,
            'product': 'RabbitMQ',
            'cluster_name': 'rabbit@localhost',
            'management_version': self.VERSION,
            'erlang_version': '26.2.5',
            'message_stats': {
                'publish': 0,
                'confirm': 0,
                'deliver': 0,
                'deliver_get': 0,
                'ack': 0,
                'get': 0,
                'redeliver': 0,
            },
            'queue_totals': {
                'messages': 0,
                'messages_ready': 0,
                'messages_unacknowledged': 0,
            },
            'node': 'rabbit@localhost',
            'statistics_db_node': 'rabbit@localhost',
            'listeners': [
                {
                    'node': 'rabbit@localhost',
                    'protocol': 'amqp',
                    'port': 5672,
                    'ip_address': '0.0.0.0',
                },
                {
                    'node': 'rabbit@localhost',
                    'protocol': 'http',
                    'port': 15672,
                    'ip_address': '0.0.0.0',
                },
            ],
            'contexts': [
                {
                    'node': 'rabbit@localhost',
                    'description': 'RabbitMQ Management',
                    'port': 15672,
                    'ssl_port': None,
                }
            ],
        }
        return json.dumps(overview)

    def _api_whoami(self) -> str:
        """Current authenticated user."""
        whoami = {
            'name': 'guest',
            'tags': ['administrator'],
        }
        return json.dumps(whoami)

    def _api_aliveness(self, decoded_path: str) -> str:
        """Aliveness test for a vhost."""
        # Extract vhost: /api/aliveness-test/<vhost>
        decoded_path.split('/api/aliveness-test/', 1)[-1] or '/'
        result = {'status': 'ok'}
        return json.dumps(result)

    def _api_queues(self) -> str:
        """Empty queue list."""
        return json.dumps([])

    def _api_exchanges(self) -> str:
        """Empty exchange list."""
        return json.dumps([])

    def _api_connections(self) -> str:
        """Empty connection list."""
        return json.dumps([])

    # ------------------------------------------------------------------ #
    # Login failure response
    # ------------------------------------------------------------------ #
    def _login_failed_response(self) -> bytes:
        """Login failed response &mdash; encourages further probing."""
        body = (
            '<html><body><h3>Authorization Error</h3>'
            '<p>Error: invalid credentials.</p></body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
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
            f'Server: RabbitMQ/{self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'RabbitMQHandler(domain={self.domain!r})'
