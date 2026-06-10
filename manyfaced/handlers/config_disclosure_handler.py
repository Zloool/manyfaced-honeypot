"""ConfigDisclosureHandler – handles config file disclosure attempts.

Uses response builders from config_responses module to keep this handler
under the 400-line limit. Dispatch table routes path patterns to responses.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import CONFIG_DISCLOSURE_HTTP
from manyfaced.handlers.config_responses import (
    fake_backup_sql,
    fake_composer_json,
    fake_config_json,
    fake_config_php,
    fake_database_yml,
    fake_db_directory,
    fake_docker_compose_yml,
    fake_dockerfile,
    fake_env_file,
    fake_git_config,
    fake_git_head,
    fake_htaccess_file,
    fake_htpasswd_file,
    fake_my_cnf,
    fake_nginx_conf,
    fake_package_json,
    fake_php_ini,
    fake_phpinfo_php,
    fake_security_txt,
    fake_settings_py,
    fake_web_config,
    fake_wp_config_php,
    fake_xmlrpc_php,
)

logger = logging.getLogger(__name__)


def _check_path(path_lower: str, *patterns: str) -> bool:
    """Check if any of the given patterns appear in path_lower."""
    return any(p in path_lower for p in patterns)


class ConfigDisclosureHandler(HTTPHandlerBase):
    """Config file disclosure honeypot handler."""

    domain = 'config_disclosure'
    DETECTED_ID = CONFIG_DISCLOSURE_HTTP

    # Dispatch table: (path_check_fn, response_fn, content_type) tuples.
    # Evaluated in order; first match wins.
    _DISPATCH_TABLE: list[tuple] = [
        (_check_path, '/wp-config.php', fake_wp_config_php, 'application/x-httpd-php'),
        (_check_path, '/xmlrpc.php', fake_xmlrpc_php, 'application/x-httpd-php'),
        (_check_path, '/.env', fake_env_file, 'text/plain'),
        (_check_path, '/.htaccess', fake_htaccess_file, 'text/plain'),
        (_check_path, '/.htpasswd', fake_htpasswd_file, 'text/plain'),
        (
            _check_path,
            '/config.php',
            '/configuration.php',
            fake_config_php,
            'application/x-httpd-php',
        ),
        (_check_path, '/settings.py', fake_settings_py, 'text/x-python'),
        (_check_path, '/database.yml', fake_database_yml, 'text/x-yaml'),
        (_check_path, '/config.json', fake_config_json, 'application/json'),
        (_check_path, '/web.config', fake_web_config, 'application/xml'),
        (_check_path, '/phpinfo.php', '/info.php', fake_phpinfo_php, 'text/html'),
        (_check_path, '/php.ini', fake_php_ini, 'text/plain'),
        (_check_path, '/my.cnf', '/mysqld.cnf', fake_my_cnf, 'text/plain'),
        (_check_path, '/nginx.conf', fake_nginx_conf, 'text/plain'),
        (_check_path, '/docker-compose.yml', fake_docker_compose_yml, 'text/x-yaml'),
        (_check_path, '/Dockerfile', fake_dockerfile, 'text/plain'),
        (_check_path, '/composer.json', fake_composer_json, 'application/json'),
        (_check_path, '/package.json', fake_package_json, 'application/json'),
        (
            _check_path,
            '/backup.sql',
            '/dump.sql',
            '/database.sql',
            fake_backup_sql,
            'application/sql',
        ),
        (_check_path, '/db/', '/mysql/', '/postgres/', fake_db_directory, 'text/html'),
        # .git/head before .git/config (more specific)
        (lambda p: '/.git/head' in p, fake_git_head, 'text/plain'),
        (lambda p: '/.git/config' in p, fake_git_config, 'text/plain'),
        (
            _check_path,
            '/security.txt',
            '/.well-known/security.txt',
            fake_security_txt,
            'text/plain',
        ),
    ]

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a config disclosure response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {
            'path': path,
            'method': self._extract_method(raw_request),
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        # Escalate on config file access attempts
        profile.escalation_label = 'config_file_probe'

        path_lower = path.lower()

        # Dispatch: find first matching route
        for entry in self._DISPATCH_TABLE:
            check_fn = entry[0]
            if check_fn(path_lower, *entry[1:-2]):
                response_fn = entry[-2]
                content_type = entry[-1]
                body = response_fn()
                return self._build_http_response(
                    body, 200, 'OK', {'Content-Type': content_type}
                ), self.DETECTED_ID

        # Default: serve wp-config.php as the most common target
        body = fake_wp_config_php()
        return self._build_http_response(
            body, 200, 'OK', {'Content-Type': 'application/x-httpd-php'}
        ), self.DETECTED_ID

    def _extract_method(self, raw_request: str) -> str:
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
        return f'ConfigDisclosureHandler(domain={self.domain!r})'
