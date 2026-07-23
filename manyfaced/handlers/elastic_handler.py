"""ElasticsearchHandler - Elasticsearch REST API + Kibana honeypot face (issue #281).

Emulates the Elasticsearch REST API and Kibana frontend, returning realistic
JSON for the production probe paths recorded in issue #281:

  /_cat                 - cat API index
  /_cluster/health      - cluster health
  /_nodes               - node listing
  /_search              - search endpoint
  /_xpack               - X-Pack info
  /_snapshot            - snapshot/restore
  /_license             - license info
  /kibana               - Kibana frontend
  /app/kibana           - Kibana app shell
  /_plugin/head         - elasticsearch-head plugin
  /_sql                 - SQL endpoint
  /_bulk                - bulk endpoint
  /elasticsearch/%2eenv - env disclosure probe (decoded .env)
  /elastic/%2eenv       - env disclosure probe (decoded .env)

Credentials are captured from any login/auth POST (incl. Kibana sign-in) and a
generic ES JSON error is returned to keep the probe engaged.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import unquote

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import ELASTIC_HTTP

logger = logging.getLogger(__name__)


class ElasticHandler(HTTPHandlerBase):
    """Elasticsearch 8.13.0 honeypot handler."""

    domain = 'elastic'
    DETECTED_ID = ELASTIC_HTTP
    VERSION = '8.13.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an Elasticsearch/Kibana response for the given request."""
        # Normalise path: strip query string and URL-decode %2e/%2f probes.
        clean_path = path.split('?', 1)[0]
        clean_path = unquote(clean_path)

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
        path_lower = clean_path.lower()

        # Capture credentials from any login/auth-style POST (Kibana sign-in,
        # _security/_authenticate, or a generic login path).
        is_login_path = (
            'login' in path_lower
            or 'auth' in path_lower
            or '_security' in path_lower
            or 'kibana' in path_lower
        )
        if method == 'POST' and is_login_path:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        body, content_type = self._route_response(clean_path, path_lower, raw_request)
        return (
            self._build_http_response(body, 200, 'OK', content_type=content_type),
            self.DETECTED_ID,
        )

    # ------------------------------------------------------------------
    # Response routing
    # ------------------------------------------------------------------

    def _route_response(
        self, clean_path: str, path_lower: str, raw_request: str
    ) -> tuple[str, str]:
        """Return (body, content_type) for a GET-style request."""
        json_ct = 'application/json; charset=UTF-8'

        # ES REST API endpoints -> realistic JSON.
        if path_lower in ('/_cat', '/_cat/'):
            return self._cat_response(), json_ct
        if path_lower == '/_cluster/health' or path_lower.startswith('/_cluster/health'):
            return self._cluster_health_response(), json_ct
        if path_lower.startswith('/_cluster'):
            return self._cluster_response(), json_ct
        if path_lower in ('/_nodes', '/_nodes/') or path_lower.startswith('/_nodes'):
            return self._nodes_response(), json_ct
        if path_lower == '/_search' or path_lower.startswith('/_search'):
            return self._search_response(raw_request), json_ct
        if path_lower == '/_xpack' or path_lower.startswith('/_xpack'):
            return self._xpack_response(), json_ct
        if path_lower == '/_snapshot' or path_lower.startswith('/_snapshot'):
            return self._snapshot_response(), json_ct
        if path_lower == '/_license' or path_lower.startswith('/_license'):
            return self._license_response(), json_ct
        if path_lower == '/_sql' or path_lower.startswith('/_sql'):
            return self._sql_response(raw_request), json_ct
        if path_lower == '/_bulk' or path_lower.startswith('/_bulk'):
            return self._bulk_response(), json_ct
        if path_lower == '/_plugin/head' or path_lower.startswith('/_plugin/head'):
            return self._head_plugin_response(), 'text/html; charset=UTF-8'
        if path_lower.startswith('/elasticsearch/') and path_lower.endswith('.env'):
            return self._env_response(), json_ct
        if path_lower.startswith('/elastic/') and path_lower.endswith('.env'):
            return self._env_response(), json_ct

        # Additional bare ES REST API endpoints (issue #644). These were
        # previously unmatched and fell through to the catch-all monster page
        # (UNKNOWN_HTTP=4294967294), so attack traffic on these high-volume
        # probe paths was not attributed to Elastic. They must return a valid
        # ES-shaped JSON body AND be classified as ELASTIC_HTTP.
        if path_lower == '/_aliases' or path_lower.startswith('/_aliases'):
            return self._aliases_response(), json_ct
        if path_lower == '/_stats' or path_lower.startswith('/_stats'):
            return self._stats_response(), json_ct
        if path_lower == '/_status' or path_lower.startswith('/_status'):
            return self._status_response(), json_ct
        if (
            path_lower == '/_all/_mapping'
            or path_lower.startswith('/_all/_mapping')
            or path_lower == '/_mapping'
            or path_lower.startswith('/_mapping')
        ):
            return self._mapping_response(), json_ct

        # Kibana frontend.
        if 'kibana' in path_lower:
            return self._kibana_response(clean_path), 'text/html; charset=UTF-8'

        # Everything else ES-flavoured: lean cluster info JSON.
        return self._root_response(), json_ct

    # ------------------------------------------------------------------
    # ES JSON payloads
    # ------------------------------------------------------------------

    def _root_response(self) -> str:
        return json.dumps(self._cluster_info_payload(), separators=(',', ':'))

    def _aliases_response(self) -> str:
        return json.dumps({}, separators=(',', ':'))

    def _stats_response(self) -> str:
        return json.dumps(
            {
                'indices': {
                    'count': 3,
                    'docs': {'count': 1110543, 'deleted': 0},
                    'store': {'size_in_bytes': 182536960},
                },
                'total': {
                    'docs': {'count': 1110543, 'deleted': 0},
                    'store': {'size_in_bytes': 182536960},
                },
            },
            separators=(',', ':'),
        )

    def _status_response(self) -> str:
        return json.dumps(
            {
                'cluster_name': 'elasticsearch',
                'cluster_uuid': 'a1b2c3d4e5f6a7b8c9d0e1f2',
                'status': 'green',
                'timed_out': False,
                'number_of_nodes': 1,
                'number_of_data_nodes': 1,
                'active_primary_shards': 12,
                'active_shards': 12,
                'relocating_shards': 0,
                'initializing_shards': 0,
                'unassigned_shards': 0,
            },
            separators=(',', ':'),
        )

    def _mapping_response(self) -> str:
        return json.dumps(
            {'_all': {'mappings': {}}},
            separators=(',', ':'),
        )

    def _cluster_info_payload(self) -> dict:
        return {
            'name': 'node-1',
            'cluster_name': 'elasticsearch',
            'cluster_uuid': 'a1b2c3d4e5f6a7b8c9d0e1f2',
            'version': {
                'number': self.VERSION,
                'build_flavor': 'default',
                'build_type': 'docker',
                'build_hash': 'd4f30e4b0e6f6f2f6a8b9c0d1e2f3a4b',
                'build_date': '2024-02-08T15:24:47.823Z',
                'build_snapshot': False,
                'lucene_version': '9.10.0',
                'minimum_wire_compatibility_version': '7.17.0',
                'minimum_index_compatibility_version': '7.0.0',
            },
            'tagline': 'You Know, for Search',
        }

    def _cat_response(self) -> str:
        return json.dumps(
            [
                {'index': 'metrics-2024.02.01', 'health': 'green', 'docs.count': '128374'},
                {'index': 'logs-2024.02.01', 'health': 'green', 'docs.count': '982145'},
                {'index': '.kibana_8.13.0_001', 'health': 'yellow', 'docs.count': '1024'},
            ],
            separators=(',', ':'),
        )

    def _cluster_health_response(self) -> str:
        return json.dumps(
            {
                'cluster_name': 'elasticsearch',
                'status': 'green',
                'timed_out': False,
                'number_of_nodes': 1,
                'number_of_data_nodes': 1,
                'active_primary_shards': 12,
                'active_shards': 12,
                'relocating_shards': 0,
                'initializing_shards': 0,
                'unassigned_shards': 0,
                'delayed_unassigned_shards': 0,
                'number_of_pending_tasks': 0,
                'number_of_in_flight_fetch': 0,
                'task_max_waiting_in_queue_millis': 0,
                'active_shards_percent_as_number': 100.0,
            },
            separators=(',', ':'),
        )

    def _cluster_response(self) -> str:
        payload = self._cluster_info_payload()
        payload['cluster_name'] = 'elasticsearch'
        return json.dumps(payload, separators=(',', ':'))

    def _nodes_response(self) -> str:
        return json.dumps(
            {
                '_nodes': {'total': 1, 'successful': 1, 'failed': 0},
                'cluster_name': 'elasticsearch',
                'nodes': {
                    'node-1': {
                        'name': 'node-1',
                        'transport_address': '127.0.0.1:9300',
                        'host': '127.0.0.1',
                        'ip': '127.0.0.1',
                        'version': self.VERSION,
                        'build_flavor': 'default',
                        'roles': ['master', 'data', 'ingest'],
                        'os': {'name': 'Linux', 'arch': 'amd64', 'version': '5.15.0'},
                        'jvm': {'version': '21.0.2', 'vendor': 'Eclipse Adoptium'},
                    }
                },
            },
            separators=(',', ':'),
        )

    def _search_response(self, raw_request: str) -> str:
        return json.dumps(
            {
                'took': 7,
                'timed_out': False,
                '_shards': {'total': 1, 'successful': 1, 'skipped': 0, 'failed': 0},
                'hits': {
                    'total': {'value': 0, 'relation': 'eq'},
                    'max_score': None,
                    'hits': [],
                },
            },
            separators=(',', ':'),
        )

    def _xpack_response(self) -> str:
        return json.dumps(
            {
                'build': {'hash': 'd4f30e4b', 'date': '2024-02-08T15:24:47Z'},
                'license': {
                    'uid': 'a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
                    'type': 'basic',
                    'mode': 'basic',
                    'status': 'active',
                },
                'features': {
                    'security': {'available': True, 'enabled': False},
                    'watcher': {'available': True, 'enabled': False},
                    'ml': {'available': True, 'enabled': True},
                    'graph': {'available': True, 'enabled': True},
                },
                'tagline': 'You know, for X',
            },
            separators=(',', ':'),
        )

    def _snapshot_response(self) -> str:
        return json.dumps(
            {
                'snapshots': [
                    {
                        'snapshot': 'snapshot-2024.02.01',
                        'uuid': 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7',
                        'version_id': 8130099,
                        'version': self.VERSION,
                        'indices': ['metrics-2024.02.01', 'logs-2024.02.01'],
                        'state': 'SUCCESS',
                    }
                ],
                'total': 1,
                'remaining': 0,
            },
            separators=(',', ':'),
        )

    def _license_response(self) -> str:
        return json.dumps(
            {
                'license': {
                    'status': 'active',
                    'uid': 'a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
                    'type': 'basic',
                    'issued_to': 'elasticsearch',
                    'issuer': 'elasticsearch',
                    'start_date_in_millis': 1706745600000,
                    'expiry_date_in_millis': -1,
                    'max_nodes': 1000,
                    'issued_date': '2024-02-01T00:00:00Z',
                    'expiry_date': '2099-12-31T00:00:00Z',
                }
            },
            separators=(',', ':'),
        )

    def _sql_response(self, raw_request: str) -> str:
        return json.dumps(
            {
                'columns': [{'name': '@timestamp', 'type': 'datetime'}],
                'rows': [],
                'cursor': None,
            },
            separators=(',', ':'),
        )

    def _bulk_response(self) -> str:
        return json.dumps(
            {
                'errors': False,
                'took': 31,
                'items': [
                    {
                        'index': {
                            '_index': 'logs-2024.02.01',
                            '_id': 'abc123',
                            '_version': 1,
                            'result': 'created',
                            'status': 201,
                        }
                    }
                ],
            },
            separators=(',', ':'),
        )

    def _env_response(self) -> str:
        """Fake .env disclosure probe response (decoded %2eenv path)."""
        return json.dumps(
            {
                'error': {
                    'root_cause': [
                        {
                            'type': 'security_exception',
                            'reason': 'missing authentication credentials for cluster:monitor/main',
                        }
                    ],
                    'type': 'security_exception',
                    'reason': 'missing authentication credentials for cluster:monitor/main',
                    'header': {'WWW-Authenticate': 'Basic realm="security" charset="UTF-8"'},
                },
                'status': 401,
            },
            separators=(',', ':'),
        )

    # ------------------------------------------------------------------
    # Kibana / plugin HTML
    # ------------------------------------------------------------------

    def _kibana_response(self, path: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Elastic</title>
<link rel="icon" href="/ui/favicons/favicon.ico">
<link rel="stylesheet" type="text/css" href="/bootstrap.css">
<link rel="stylesheet" type="text/css" href="/ui/legacy/styles/core.min.css">
<script src="/ui/legacy/bootstrap.js"></script>
<script src="/ui/legacy/core.js"></script>
</head>
<body class="kbnBody">
<div id="kibana-body" class="kbnBodyWrapper" data-test-subj="kibanaBody">
  <div class="kbnWelcomeContent">
    <h1>Elastic</h1>
    <p>Welcome to Elastic {self.VERSION}.</p>
    <form method="POST" action="/login" name="loginForm" id="loginForm">
      <input type="hidden" name="next" value="/app/kibana">
      <div class="form-row">
        <label for="username">Username</label>
        <input type="text" name="username" id="username" autocomplete="off">
      </div>
      <div class="form-row">
        <label for="password">Password</label>
        <input type="password" name="password" id="password" autocomplete="off">
      </div>
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">Log in</button>
      </div>
    </form>
    <p class="kbnWelcomeText">Explore, visualize, and discover your data.</p>
  </div>
</div>
</body>
</html>"""

    def _head_plugin_response(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>elasticsearch-head</title>
<link rel="stylesheet" href="/_plugin/head/static/css/base.css">
<script src="/_plugin/head/static/js/base.js"></script>
</head>
<body class="es-head">
<div id="clusterOverview">
  <h1>elasticsearch-head</h1>
  <p>Connected to: http://localhost:9200/</p>
  <p>Cluster: elasticsearch &middot; Status: green</p>
  <p>Version: {self.VERSION}</p>
</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Login failure (credential-capture probe expects b'Error')
    # ------------------------------------------------------------------

    def _login_failed_response(self) -> bytes:
        """Login failed response — contains 'Error' (credential-capture probe)."""
        body = json.dumps(
            {
                'error': 'AuthenticationException',
                'message': 'Error: Invalid username or password',
                'status': 401,
            },
            separators=(',', ':'),
        )
        return self._build_http_response(
            body, 401, 'Unauthorized', content_type='application/json; charset=UTF-8'
        )

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
        content_type: str = 'application/json; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('iso-8859-1')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Elasticsearch/{self.VERSION}\r\n'
            f'X-Elastic-Product: Elasticsearch\r\n'
            f'content-type: {content_type}\r\n'
            f'content-length: {len(body_bytes)}\r\n'
            f'Date: {now}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        )
        return response.encode('iso-8859-1') + body_bytes

    def __repr__(self) -> str:
        return f'ElasticHandler(domain={self.domain!r})'
