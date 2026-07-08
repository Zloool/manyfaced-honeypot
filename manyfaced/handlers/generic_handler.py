"""GenericHandler – default handler for unknown/unmatched paths.

Serves a "monster page" packed with keywords, links, and hints about
popular services (WordPress, phpMyAdmin, Jenkins, Tomcat, etc.) to
attract probing bots and encourage deeper exploration.

Also handles path traversal, file inclusion, and other exploit attempts
by returning realistic-looking error pages with debug information.

The monster page uses a static service catalogue for service discovery.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import textwrap
from typing import Any

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Static service catalogue for the monster page
# ---------------------------------------------------------------------------

_SERVICE_INFO: dict[str, tuple[str, str, str]] = {
    'wordpress': ('WordPress CMS', '6.5.3', 'Running (v6.5.3)'),
    'phpmyadmin': ('phpMyAdmin', '5.2.1', 'Running (v5.2.1)'),
    'jenkins': ('Jenkins CI/CD', '2.426', 'Running (v2.426)'),
    'tomcat': ('Apache Tomcat', '9.0.87', 'Running (v9.0.87)'),
    'drupal': ('Drupal CMS', '10.2.4', 'Running (v10.2.4)'),
    'cpanel': ('cPanel', '120.0.6', 'Running (v120.0.6)'),
    'gitlab': ('GitLab', '16.8.5', 'Running (v16.8.5)'),
    'nginx': ('Nginx', '1.24.0', 'Running (v1.24.0)'),
    'mysql': ('MySQL/MariaDB', '10.11.4', 'Running (v10.11.4)'),
    'redis': ('Redis', '7.2.3', 'Running (v7.2.3)'),
    'dbadmin': ('Adminer', '4.8.1', 'Running (v4.8.1)'),
    'docker': ('Docker Registry', '25.0.0', 'Running (v25.0.0)'),
    'mcp': ('MCP', '2024.11.0', 'Running (v2024.11.0)'),
    'iot': ('IoT Router', '1.0', 'Running (v1.0)'),
    'nginx_probe': ('Nginx', '1.24.0', 'Running (v1.24.0)'),
    'k8s': ('Kubernetes', '1.29.0', 'Running (v1.29.0)'),
    'nextjs': ('Next.js', '14.1.0', 'Running (v14.1.0)'),
    'atlassian': ('Confluence', '8.5.0', 'Running (v8.5.0)'),
    'spring': ('Spring Boot', '3.2.0', 'Running (v3.2.0)'),
    'aws_creds': ('AWS', '1.0', 'Running (v1.0)'),
    'hnap': ('HNAP', '1.0', 'Running (v1.0)'),
    'squid': ('Squid', '6.8.0', 'Running (v6.8.0)'),
    'magento': ('Magento', '2.4.6', 'Running (v2.4.6)'),
    'redis_admin': ('Redis Admin', '2.0.0', 'Running (v2.0.0)'),
    'solr': ('Apache Solr', '9.5.0', 'Running (v9.5.0)'),
    'grafana': ('Grafana', '10.4.0', 'Running (v10.4.0)'),
    'plex': ('Plex', '1.32.0', 'Running (v1.32.0)'),
    'jupyter': ('Jupyter', '4.2.0', 'Running (v4.2.0)'),
    'rabbitmq': ('RabbitMQ', '3.12.0', 'Running (v3.12.0)'),
    'elasticsearch': ('Elasticsearch', '8.12.0', 'Running (v8.12.0)'),
    'zabbix': ('Zabbix', '6.4.0', 'Running (v6.4.0)'),
    'laravel': ('Laravel', '10.48.0', 'Running (v10.48.0)'),
    'thinkphp': ('ThinkPHP', '8.0.0', 'Running (v8.0.0)'),
}

# Representative paths per service – mirrors the route table for display
_SERVICE_PATHS: dict[str, list[str]] = {
    'wordpress': ['/wp-login.php', '/wp-admin/', '/xmlrpc.php'],
    'phpmyadmin': ['/phpmyadmin/', '/pma/', '/mysql/'],
    'jenkins': ['/jenkins/', '/jenkins/login', '/hudson/'],
    'tomcat': ['/manager/html', '/host-manager/html', '/server-status'],
    'drupal': ['/user/login', '/admin', '/node'],
    'cpanel': ['/cpanel/', '/whm/', '/webmail/'],
    'dbadmin': ['/adminer', '/sqlbuddy', '/dbadmin'],
    'docker': ['/v2/_catalog', '/v2', '/version'],
    'mcp': ['/mcp', '/sse'],
    'iot': ['/boaform/admin/formlogin', '/apply.cgi', '/cgi-bin'],
    'nginx_probe': ['/nginx_status', '/server-status', '/stub_status'],
    'k8s': ['/api', '/apis', '/healthz'],
    'nextjs': ['/_next', '/__nextjs_action', '/vercel.json'],
    'atlassian': ['/wiki', '/login.action', '/setup.action'],
    'spring': ['/actuator', '/actuator/health', '/api/env'],
    'aws_creds': ['/.aws/credentials', '/aws/credentials', '/.env.aws'],
    'hnap': ['/HNAP1', '/hnap', '/post_login.xml'],
    'squid': ['/squid', '/cachemgr', '/cgi-bin'],
    'magento': ['/magento', '/admin', '/index.php/admin'],
    'redis_admin': ['/redis-admin', '/redis-commander', '/redis'],
    'solr': ['/solr/admin/info/system', '/solr/admin/cores', '/solr'],
    'grafana': ['/grafana', '/prometheus', '/api/datasources'],
    'plex': ['/web/index.html', '/status/sessions', '/identity'],
    'jupyter': ['/jupyter', '/lab', '/notebooks'],
    'rabbitmq': ['/api/overview', '/api/queues', '/api/exchanges'],
    'elasticsearch': ['/_cat', '/_search', '/_cluster'],
    'zabbix': ['/zc', '/evox/about', '/zabbix.php'],
    'laravel': ['/laravel', '/_ignition', '/storage/logs/laravel.log'],
    'thinkphp': ['/index.php', '/public/index.php', '/thinkphp'],
}


def _collect_handler_keywords() -> list[dict[str, Any]]:
    """Collect service info and representative paths for the monster page.

    Returns a list of dicts with keys:
        - domain: handler domain name
        - name: display name (from _SERVICE_INFO or domain)
        - version: version string
        - status: status string
        - patterns: list of representative service paths
        - login_paths: subset of patterns that look like login paths
    """
    keywords = []

    for domain, info in _SERVICE_INFO.items():
        display_name, version, status = info
        patterns = _SERVICE_PATHS.get(domain, [])

        # Determine login paths (paths containing "login", "admin", "manage", etc.)
        login_keywords = ['login', 'admin', 'manage', 'console', 'dashboard']
        login_paths = [p for p in patterns if any(kw in p.lower() for kw in login_keywords)]

        keywords.append(
            {
                'domain': domain,
                'name': display_name,
                'version': version,
                'status': status,
                'patterns': patterns,
                'login_paths': login_paths,
            }
        )

    return keywords


def _build_monster_page(keywords: list[dict[str, Any]]) -> str:
    """Build the monster page HTML from collected handler keywords."""
    # Build service rows
    service_rows = ''
    for kw in keywords:
        # Build access links
        links = []
        for p in kw['patterns'][:3]:  # Limit to first 3 patterns per service
            links.append(f'<a href="{p}">{p.split("/")[-1] or p}</a>')
        access_str = ' | '.join(links) if links else 'N/A'

        service_rows += f"""
            <tr>
                <td>{kw['name']}</td>
                <td class="status-active">{kw['status']}</td>
                <td>{access_str}</td>
            </tr>"""

    # Build quick links
    quick_links = []
    for kw in keywords:
        for p in kw['patterns'][:2]:  # Limit to first 2 patterns per service
            quick_links.append(f'<a href="{p}">{kw["name"]} {p}</a>')

    quick_links_str = ' | '.join(quick_links[:10]) if quick_links else 'None'

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Status - Admin Panel</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .section {{ background: #16213e; border: 1px solid #0f3460; border-radius: 5px; padding: 15px; margin: 10px 0; }}
        .section h2 {{ color: #53d8fb; margin-top: 0; }}
        a {{ color: #53d8fb; text-decoration: none; }}
        a:hover {{ text-decoration: underline; color: #e94560; }}
        .warning {{ background: #e9456022; border-left: 4px solid #e94560; padding: 10px; margin: 10px 0; }}
        .info {{ background: #53d8fb11; border-left: 4px solid #53d8fb; padding: 10px; margin: 10px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #0f3460; padding: 8px; text-align: left; }}
        th {{ background: #0f3460; }}
        .status-active {{ color: #4ade80; }}
        .status-warning {{ color: #fbbf24; }}
        .status-critical {{ color: #e94560; }}
    </style>
</head>
<body>
    <h1>&#128274; Server Administration Panel</h1>
    <div class="warning">&#9888; WARNING: Unauthenticated access detected. All activities are being logged.</div>

    <div class="section">
        <h2>&#128640; Available Services</h2>
        <table>
            <tr><th>Service</th><th>Status</th><th>Access</th></tr>
            {textwrap.indent(service_rows, '            ').strip()}
        </table>
    </div>

    <div class="section">
        <h2>&#128196; Quick Links</h2>
        <p>{quick_links_str}</p>
    </div>

    <div class="section">
        <h2>&#128161; Server Information</h2>
        <table>
            <tr><td>Server</td><td>Apache/2.4.57 (Ubuntu) OpenSSL/3.0.11</td></tr>
            <tr><td>PHP</td><td>8.2.15 (Zend Engine 4.2.15)</td></tr>
            <tr><td>OS</td><td>Ubuntu 22.04.4 LTS (Linux 5.15.0-91-generic)</td></tr>
            <tr><td>Database</td><td>MySQL 8.0.36 / MariaDB 10.11.4</td></tr>
            <tr><td>Memory</td><td>4.0 GB / 8.0 GB</td></tr>
            <tr><td>Disk</td><td>25.0 GB / 50.0 GB</td></tr>
            <tr><td>Uptime</td><td>14 days, 7 hours, 32 minutes</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>&#128274; Recent Security Events</h2>
        <div class="warning">&#9888; 3 failed login attempts detected in the last hour</div>
        <div class="info">&#128161; Database backup completed successfully at 2026-04-21 03:00:00 UTC</div>
        <div class="info">&#128161; SSL certificate expires in 45 days (2026-06-05)</div>
    </div>

    <div class="section">
        <h2>&#128736; Debug Information</h2>
        <pre style="background: #000; padding: 10px; border-radius: 5px; overflow-x: auto;">
Server Root: /var/www/html
Document Root: /var/www/html
Config File: /etc/apache2/apache2.conf
PHP Config: /etc/php/8.2/apache2/php.ini
MySQL Config: /etc/mysql/my.cnf
Log Files: /var/log/apache2/
Backup Dir: /var/backups/
Git Repo: /var/www/html/.git/
        </pre>
    </div>

    <div style="text-align: center; margin-top: 30px; color: #666; font-size: 12px;">
        &copy; 2026 Server Admin Panel | Powered by Apache/2.4.57 | PHP/8.2.15 | MySQL/8.0.36
    </div>
</body>
</html>"""


# Cached monster page (generated once at module load)
_MONSTER_PAGE = _build_monster_page(_collect_handler_keywords())


# Error page for file traversal / inclusion attempts
_TRAVERSAL_ERROR = """\
<!DOCTYPE html>
<html>
<head><title>Error - 403 Forbidden</title></head>
<body style="font-family: monospace; background: #1a1a2e; color: #eee; padding: 40px;">
    <h1 style="color: #e94560;">403 - Forbidden</h1>
    <p>Access to the requested file is denied.</p>
    <div style="background: #0f3460; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #53d8fb;">Debug Information:</h3>
        <pre>
Path: {path}
Server: Apache/2.4.57 (Ubuntu)
PHP: 8.2.15
MySQL: 8.0.36
Document Root: /var/www/html
Config: /etc/apache2/apache2.conf
        </pre>
    </div>
    <p style="color: #666;">Server Error Log: /var/log/apache2/error.log</p>
    <p style="color: #666;">Database Config: /var/www/html/wp-config.php</p>
</body>
</html>
"""


class GenericHandler(HTTPHandlerBase):
    """Default handler for unknown/unmatched paths.

    Serves a "monster page" packed with keywords, links, and hints about
    popular services (WordPress, phpMyAdmin, Jenkins, Tomcat, etc.) to
    attract probing bots and encourage deeper exploration.

    Also handles path traversal, file inclusion, and other exploit attempts
    by returning realistic-looking error pages with debug information.
    """

    domain = 'generic'
    DETECTED_ID = 4294967294  # UNKNOWN_HTTP

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a response for an unknown path."""
        profile = self.get_or_create_profile(bot_ip)

        # Record the request
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

        # Check for exploit patterns in the path
        if '..' in path or '/etc/' in path or 'php://' in path_lower:
            # Path traversal / inclusion attempt
            body = _TRAVERSAL_ERROR.format(path=path)
            response = self._build_http_response(body, path, '403 Forbidden')
        elif method == 'POST' and any(kw in path_lower for kw in ['login', 'admin', 'auth']):
            # POST to a login-like path
            credentials = self._extract_credentials(raw_request, headers or {})
            if credentials:
                profile.capture_credentials(credentials)
                # Redirect to a plausible admin page
                response = self._build_http_response(
                    '<html><body>Redirecting...</body></html>',
                    path,
                    '302 Found',
                    extra_headers={'Location': '/admin/'},
                )
            else:
                response = self._build_http_response(_MONSTER_PAGE, path)
        else:
            # Default: serve the monster page
            response = self._build_http_response(_MONSTER_PAGE, path)

        profile._response_count = (
            profile._response_count + 1 if hasattr(profile, '_response_count') else 1
        )
        self._response_count += 1

        return response, self.DETECTED_ID

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        path: str,
        status: str = '200 OK',
        extra_headers: dict[str, str] | None = None,
    ) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_type = 'text/html; charset=UTF-8'

        if 'xml' in path or 'xmlrpc' in path:
            content_type = 'application/xml; charset=utf-8'

        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: Apache/2.4.57 (Ubuntu)\r\n'
            f'X-Powered-By: PHP/8.2.15\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
        )

        if extra_headers:
            for key, value in extra_headers.items():
                response += f'{key}: {value}\r\n'

        response += '\r\n'
        response += body

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'GenericHandler(domain={self.domain!r})'
