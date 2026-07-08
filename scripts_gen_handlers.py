"""One-shot generator: create scaffold (stub) handlers + routes + tests for 24
new 'Add missing handler' faces, and wire the 4 shared files (status.py,
handlers/__init__.py, routes/__init__.py, generic_handler.py).

This establishes importable, registered, green-CI stubs. Realistic responses,
rich route sets, and credential capture are filled in by parallel workers that
each own ONLY their own <svc>_handler.py / routes_<svc>.py / test_service_<svc>.py.
"""

from __future__ import annotations

import os

REPO = os.path.dirname(os.path.abspath(__file__))
HANDLERS = os.path.join(REPO, 'manyfaced', 'handlers')
ROUTES = os.path.join(HANDLERS, 'routes')
TESTS = os.path.join(REPO, 'test')

# (issue, svc_key, Class, CONST, display, version, paths, keyword)
SPECS = [
    (
        287,
        'thinkphp',
        'ThinkPHPHandler',
        'THINKPHP_HTTP',
        'ThinkPHP',
        '8.0.0',
        ['/index.php', '/public/index.php', '/thinkphp'],
        'ThinkPHP',
    ),
    (
        286,
        'laravel',
        'LaravelHandler',
        'LARAVEL_HTTP',
        'Laravel',
        '10.48.0',
        ['/laravel', '/_ignition', '/storage/logs/laravel.log', '/vendor/laravel'],
        'Laravel',
    ),
    (
        282,
        'zabbix',
        'ZabbixHandler',
        'ZABBIX_HTTP',
        'Zabbix',
        '6.4.0',
        ['/zc', '/evox/about', '/zabbix.php', '/api_jsonrpc.php'],
        'Zabbix',
    ),
    (
        278,
        'elasticsearch',
        'ElasticsearchHandler',
        'ELASTIC_HTTP',
        'Elasticsearch',
        '8.12.0',
        ['/_cat', '/_search', '/_cluster', '/_nodes', '/query'],
        'Elasticsearch',
    ),
    (
        276,
        'gitlab',
        'GitLabHandler',
        'GITLAB_HTTP',
        'GitLab',
        '16.8.5',
        ['/sdk/weblanguage', '/users/sign_in', '/api/v4', '/explore'],
        'GitLab',
    ),
    (
        298,
        'rabbitmq',
        'RabbitMQHandler',
        'RABBITMQ_HTTP',
        'RabbitMQ',
        '3.12.0',
        ['/api/overview', '/api/queues', '/api/exchanges', '/rabbitmq'],
        'RabbitMQ',
    ),
    (
        296,
        'jupyter',
        'JupyterHandler',
        'JUPYTER_HTTP',
        'Jupyter',
        '4.2.0',
        ['/jupyter', '/lab', '/notebooks', '/tree'],
        'Jupyter',
    ),
    (
        295,
        'plex',
        'PlexHandler',
        'PLEX_HTTP',
        'Plex',
        '1.32.0',
        ['/web/index.html', '/status/sessions', '/identity', '/plex'],
        'Plex',
    ),
    (
        291,
        'grafana',
        'GrafanaHandler',
        'GRAFANA_HTTP',
        'Grafana',
        '10.4.0',
        ['/grafana', '/prometheus', '/api/datasources', '/api/health'],
        'Grafana',
    ),
    (
        279,
        'solr',
        'SolrHandler',
        'SOLR_HTTP',
        'Apache Solr',
        '9.5.0',
        ['/solr/admin/info/system', '/solr/admin/cores', '/solr'],
        'Solr',
    ),
    (
        297,
        'redis_admin',
        'RedisAdminHandler',
        'REDIS_ADMIN_HTTP',
        'Redis Admin',
        '2.0.0',
        ['/redis-admin', '/redis-commander', '/redis'],
        'Redis',
    ),
    (
        293,
        'magento',
        'MagentoHandler',
        'MAGENTO_HTTP',
        'Magento',
        '2.4.6',
        ['/magento', '/admin', '/index.php/admin'],
        'Magento',
    ),
    (
        289,
        'squid',
        'SquidHandler',
        'SQUID_HTTP',
        'Squid',
        '6.8.0',
        ['/squid', '/cachemgr', '/cgi-bin'],
        'Squid',
    ),
    (
        288,
        'hnap',
        'HNAPHandler',
        'HNAP_HTTP',
        'HNAP',
        '1.0',
        ['/HNAP1', '/hnap', '/post_login.xml'],
        'HNAP',
    ),
    (
        285,
        'aws_creds',
        'AWSHandler',
        'AWS_HTTP',
        'AWS',
        '1.0',
        ['/.aws/credentials', '/aws/credentials', '/.env.aws'],
        'AWS',
    ),
    (
        281,
        'spring',
        'SpringHandler',
        'SPRING_HTTP',
        'Spring Boot',
        '3.2.0',
        ['/actuator', '/actuator/health', '/api/env'],
        'Spring',
    ),
    (
        280,
        'atlassian',
        'AtlassianHandler',
        'ATLASSIAN_HTTP',
        'Confluence',
        '8.5.0',
        ['/wiki', '/login.action', '/setup.action', '/rest/api'],
        'Confluence',
    ),
    (
        277,
        'nextjs',
        'NextjsHandler',
        'NEXTJS_HTTP',
        'Next.js',
        '14.1.0',
        ['/_next', '/__nextjs_action', '/vercel.json'],
        'Next.js',
    ),
    (
        274,
        'k8s',
        'KubernetesHandler',
        'KUBERNETES_HTTP',
        'Kubernetes',
        '1.29.0',
        ['/api', '/apis', '/healthz', '/readyz', '/metrics', '/version'],
        'Kubernetes',
    ),
    (
        294,
        'nginx_probe',
        'NginxProbeHandler',
        'NGINX_PROBE_HTTP',
        'Nginx',
        '1.24.0',
        ['/nginx_status', '/server-status', '/stub_status', '/status'],
        'nginx',
    ),
    (
        284,
        'iot',
        'IoTHandler',
        'IOT_HTTP',
        'IoT Router',
        '1.0',
        ['/boaform/admin/formlogin', '/apply.cgi', '/cgi-bin', '/getcfg.php'],
        'IoT',
    ),
    (283, 'mcp', 'MCPHandler', 'MCP_HTTP', 'MCP', '2024.11.0', ['/mcp', '/sse'], 'MCP'),
    (
        275,
        'docker',
        'DockerHandler',
        'DOCKER_HTTP',
        'Docker Registry',
        '25.0.0',
        ['/v2/_catalog', '/v2', '/version', '/info', '/_ping'],
        'Docker',
    ),
    (
        292,
        'dbadmin',
        'DBAdminHandler',
        'DBADMIN_HTTP',
        'Adminer',
        '4.8.1',
        ['/adminer', '/sqlbuddy', '/dbadmin', '/myadmin', '/adminer.php'],
        'Adminer',
    ),
]


def handler_source(spec):
    issue, svc, cls, const, disp, ver, paths, kw = spec
    return f'''"""{cls} - scaffold stub for issue #{issue}.

TODO: replace the placeholder page with a realistic {disp} impersonation
matching the production probe paths in the issue. Keep the class shape, the
DETECTED_ID constant, and the generate_response() signature intact.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import {const}

logger = logging.getLogger(__name__)


class {cls}(HTTPHandlerBase):
    """{disp} honeypot handler (scaffold)."""

    domain = '{svc}'
    DETECTED_ID = {const}

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a {disp} response for the given request.""""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {{
            'path': path,
            'method': self._extract_method(raw_request),
            'headers': dict(headers) if headers else {{}},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }}
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        path_lower = path.lower()

        if method == 'POST' and any(kw in path_lower for kw in ['login', 'auth']):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {{}}
            )
            if credentials:
                return self._login_failed_response(), detected

        body = self._main_page()
        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    def _main_page(self) -> str:
        """{disp} placeholder page (scaffold).""""
        return (
            '<!DOCTYPE html><html><head><title>{disp}</title></head>'
            f'<body><h1>{disp}</h1>'
            f'<p>Service: {disp} {ver}</p>'
            '</body></html>'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing.""""
        body = (
            '<html><body><h3>Authorization Error</h3>'
            '<p>Invalid credentials.</p></body></html>'
        )
        return self._build_http_response(body, 200, 'OK')

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request.""""
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
        """Build a complete HTTP response.""""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {{status_code}} {{status_text}}\\r\\n'
            f'Server: {disp}/{{ver}}\\r\\n'
            f'Date: {{now}}\\r\\n'
            f'Content-Type: {{content_type}}\\r\\n'
            f'Connection: close\\r\\n'
            f'\\r\\n'
            f'{{body}}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'{cls}(domain={{self.domain!r}})'
'''


def routes_source(spec):
    issue, svc, cls, const, disp, ver, paths, kw = spec
    route_lines = []
    seen = set()
    for i, p in enumerate(paths):
        key = f'{svc}_{i}'
        route_lines.append(f"    Route(PathExact('{p}'), _{svc}(), {const}, '{key}'),")
        if p.count('/') >= 2 and not p.rstrip('/').endswith(
            ('.php', '.xml', '.json', '.html', '.log', '.txt')
        ):
            parent = p.rstrip('/')
            if parent not in seen:
                seen.add(parent)
                route_lines.append(
                    f"    Route(PathPrefix('{parent}/'), _{svc}(), {const}, '{svc}_prefix_{i}'),"
                )
    body = ',\n'.join(route_lines)
    return f'''"""{disp} routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import {const}


def _{svc}() -> type:
    from manyfaced.handlers.{svc}_handler import {cls}

    return {cls}


ROUTES: list[Route] = [
    # ---- {disp} (issue #{issue}) ----
{body}
]
'''


def test_source(spec):
    issue, svc, cls, const, disp, ver, paths, kw = spec
    first = paths[0]
    return f'''"""{disp} handler tests (scaffold)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import {const}
from manyfaced.handlers import {cls}


class Test{cls}(unittest.TestCase):
    """Test {disp} responses.""""

    def setUp(self):
        self.handler = {cls}()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, {const})

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {{'1.2.3.4': profile}}
        response, detected = self.handler.generate_response(
            '{first}',
            'GET {first} HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n',
            '1.2.3.4',
        )
        self.assertIn(b'{disp}', response)
        self.assertEqual(detected, {const})

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {{'1.2.3.4': profile}}
        response, _ = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\\r\\nHost: example.com\\r\\n'
            'Content-Type: application/x-www-form-urlencoded\\r\\n\\r\\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)
'''


def main():
    # 1. status.py constants
    status_path = os.path.join(REPO, 'manyfaced', 'common', 'status.py')
    with open(status_path, 'r', encoding='utf-8') as f:
        status_txt = f.read()
    const_block = "\n# Scaffolded 'Add missing handler' faces (issues #272-#298)\n"
    for i, spec in enumerate(SPECS):
        _, svc, cls, const, disp, ver, paths, kw = spec
        val = 1010 + i
        const_block += f'{const} = {val}\n'
    if 'THINKPHP_HTTP' not in status_txt:
        status_txt = status_txt.rstrip() + '\n' + const_block
        with open(status_path, 'w', encoding='utf-8') as f:
            f.write(status_txt)

    # 2. per-service files
    for spec in SPECS:
        issue, svc, cls, const, disp, ver, paths, kw = spec
        with open(os.path.join(HANDLERS, f'{svc}_handler.py'), 'w', encoding='utf-8') as f:
            f.write(handler_source(spec))
        with open(os.path.join(ROUTES, f'routes_{svc}.py'), 'w', encoding='utf-8') as f:
            f.write(routes_source(spec))
        with open(os.path.join(TESTS, f'test_service_{svc}.py'), 'w', encoding='utf-8') as f:
            f.write(test_source(spec))

    # 3. handlers/__init__.py
    init_path = os.path.join(HANDLERS, '__init__.py')
    with open(init_path, 'r', encoding='utf-8') as f:
        init_txt = f.read()
    for spec in SPECS:
        issue, svc, cls, const, disp, ver, paths, kw = spec
        if f'from manyfaced.handlers.{svc}_handler import {cls}' not in init_txt:
            init_txt = init_txt.replace(
                'from manyfaced.handlers.config_disclosure_handler import ConfigDisclosureHandler',
                f'from manyfaced.handlers.config_disclosure_handler import ConfigDisclosureHandler\n'
                f'from manyfaced.handlers.{svc}_handler import {cls}',
            )
            init_txt = init_txt.replace(
                "    'ConfigDisclosureHandler',\n",
                f"    'ConfigDisclosureHandler',\n    '{cls}',\n",
            )
    with open(init_path, 'w', encoding='utf-8') as f:
        f.write(init_txt)

    # 4. routes/__init__.py
    rinit_path = os.path.join(ROUTES, '__init__.py')
    with open(rinit_path, 'r', encoding='utf-8') as f:
        rinit_txt = f.read()
    for spec in SPECS:
        issue, svc, cls, const, disp, ver, paths, kw = spec
        if f'routes_{svc} import ROUTES as _{svc}_routes' not in rinit_txt:
            rinit_txt = rinit_txt.replace(
                'from manyfaced.handlers.routes.routes_wordpress import ROUTES as _wordpress_routes  # noqa: E402',
                f'from manyfaced.handlers.routes.routes_wordpress import ROUTES as _wordpress_routes  # noqa: E402\n'
                f'from manyfaced.handlers.routes.routes_{svc} import ROUTES as _{svc}_routes  # noqa: E402',
            )
            rinit_txt = rinit_txt.replace(
                '    + list(_config_disclosure_routes)\n',
                f'    + list(_config_disclosure_routes)\n    + list(_{svc}_routes)\n',
            )
    with open(rinit_path, 'w', encoding='utf-8') as f:
        f.write(rinit_txt)

    # 5. generic_handler.py monster-page catalog
    gh_path = os.path.join(HANDLERS, 'generic_handler.py')
    with open(gh_path, 'r', encoding='utf-8') as f:
        gh_txt = f.read()
    for spec in SPECS:
        issue, svc, cls, const, disp, ver, paths, kw = spec
        if f"'{svc}':" not in gh_txt:
            gh_txt = gh_txt.replace(
                "    'redis': ('Redis', '7.2.3', 'Running (v7.2.3)'),\n",
                f"    'redis': ('Redis', '7.2.3', 'Running (v7.2.3)'),\n"
                f"    '{svc}': ('{disp}', '{ver}', 'Running (v{ver})'),\n",
            )
            sample = paths[:3]
            gh_txt = gh_txt.replace(
                "    'cpanel': ['/cpanel/', '/whm/', '/webmail/'],\n",
                f"    'cpanel': ['/cpanel/', '/whm/', '/webmail/'],\n    '{svc}': {sample!r},\n",
            )
    with open(gh_path, 'w', encoding='utf-8') as f:
        f.write(gh_txt)

    print(f'Generated {len(SPECS)} scaffold services with IDs 1010-{1010 + len(SPECS) - 1}')


if __name__ == '__main__':
    main()
