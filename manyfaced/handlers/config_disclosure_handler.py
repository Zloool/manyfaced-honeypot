"""ConfigDisclosureHandler – handles config file disclosure attempts.

Uses response builders from config_responses module to keep this handler
under the 400-line limit. Dispatch table routes path patterns to responses.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote_plus
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import CONFIG_DISCLOSURE_HTTP
from manyfaced.handlers.config_responses import (
    fake_app_config,
    fake_appsettings_json,
    fake_application_ini,
    fake_apache_conf,
    fake_composer_json,
    fake_config_json,
    fake_config_php,
    fake_database_yml,
    fake_db_directory,
    fake_docker_compose_yml,
    fake_dockerfile,
    fake_doctrine_yml,
    fake_env_file,
    fake_generic_ini,
    fake_generic_json,
    fake_generic_php,
    fake_generic_text,
    fake_generic_yaml,
    fake_gemfile,
    fake_gemfile_lock,
    fake_git_config,
    fake_git_head,
    fake_git_index,
    fake_httpd_conf,
    fake_htaccess_file,
    fake_htpasswd_file,
    fake_makefile,
    fake_my_cnf,
    fake_nginx_conf,
    fake_package_json,
    fake_parameters_yml,
    fake_parameters_yml_dist,
    fake_pip_conf,
    fake_php_ini,
    fake_phpinfo_php,
    fake_postgresql_conf,
    fake_redis_conf,
    fake_requirements_txt,
    fake_routing_yml,
    fake_security_yml,
    fake_security_txt,
    fake_service_yml,
    fake_settings_py,
    fake_setup_cfg,
    fake_sql_dump,
    fake_tox_ini,
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

    # Response map keyed by the route ``name`` from routes_config_disclosure.py.
    # This is the single source of truth: every routed path yields a body that
    # is type-appropriate for its artifact. Handlers no longer fall back to a
    # wp-config.php body for paths that have no bespoke builder.
    _RESPONSE_MAP: dict[str, tuple] = {
        # WordPress config
        'config_wp_config_php': (fake_wp_config_php, 'application/x-httpd-php'),
        'config_wp_config_bak': (fake_wp_config_php, 'application/x-httpd-php'),
        'config_wp_config_old': (fake_wp_config_php, 'application/x-httpd-php'),
        'config_wp_config_dist': (fake_wp_config_php, 'application/x-httpd-php'),
        'config_wp_config_txt': (fake_wp_config_php, 'application/x-httpd-php'),
        # PHP config
        'config_php': (fake_config_php, 'application/x-httpd-php'),
        'config_php_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_php_old': (fake_generic_php, 'application/x-httpd-php'),
        'config_configuration_php': (fake_config_php, 'application/x-httpd-php'),
        'config_configuration_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_conf_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_conf_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_db_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_local_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_local_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_globals_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_globals_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_initialize_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_initialize_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_constants_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_constants_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_xmlrpc_php': (fake_xmlrpc_php, 'application/x-httpd-php'),
        'config_xmlrpc_bak': (fake_xmlrpc_php, 'application/x-httpd-php'),
        'config_phpinfo_php': (fake_phpinfo_php, 'text/html'),
        'config_phpinfo_bak': (fake_phpinfo_php, 'text/html'),
        'config_info_php': (fake_phpinfo_php, 'text/html'),
        'config_info_bak': (fake_phpinfo_php, 'text/html'),
        'config_test_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_test_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_debug_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_debug_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_console_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_console_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_cli_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_cli_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_install_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_install_bak': (fake_generic_php, 'application/x-httpd-php'),
        'config_upgrade_php': (fake_generic_php, 'application/x-httpd-php'),
        'config_upgrade_bak': (fake_generic_php, 'application/x-httpd-php'),
        # Python config
        'config_settings_py': (fake_settings_py, 'text/x-python'),
        'config_settings_bak': (fake_settings_py, 'text/x-python'),
        'config_settings_old': (fake_settings_py, 'text/x-python'),
        # Ruby config
        'config_database_yml': (fake_database_yml, 'text/x-yaml'),
        'config_database_bak': (fake_database_yml, 'text/x-yaml'),
        # JSON config
        'config_json': (fake_config_json, 'application/json'),
        'config_json_bak': (fake_generic_json, 'application/json'),
        # Environment files
        'config_env': (fake_env_file, 'text/plain'),
        'config_env_bak': (fake_env_file, 'text/plain'),
        'config_env_local': (fake_env_file, 'text/plain'),
        'config_env_prod': (fake_env_file, 'text/plain'),
        'config_env_example': (fake_env_file, 'text/plain'),
        'config_env_sample': (fake_env_file, 'text/plain'),
        # Apache config
        'config_htaccess': (fake_htaccess_file, 'text/plain'),
        'config_htaccess_bak': (fake_htaccess_file, 'text/plain'),
        'config_htaccess_old': (fake_htaccess_file, 'text/plain'),
        'config_htpasswd': (fake_htpasswd_file, 'text/plain'),
        'config_htpasswd_bak': (fake_htpasswd_file, 'text/plain'),
        # Windows config
        'config_web_config': (fake_web_config, 'application/xml'),
        'config_web_config_bak': (fake_web_config, 'application/xml'),
        # .NET / other config
        'config_app_config': (fake_app_config, 'application/xml'),
        'config_app_bak': (fake_app_config, 'application/xml'),
        'config_application_ini': (fake_application_ini, 'text/plain'),
        'config_application_bak': (fake_generic_ini, 'text/plain'),
        # Symfony / YAML config
        'config_parameters_yml': (fake_parameters_yml, 'text/x-yaml'),
        'config_parameters_dist': (fake_parameters_yml_dist, 'text/x-yaml'),
        'config_service_yml': (fake_service_yml, 'text/x-yaml'),
        'config_service_bak': (fake_generic_yaml, 'text/x-yaml'),
        'config_doctrine_yml': (fake_doctrine_yml, 'text/x-yaml'),
        'config_doctrine_bak': (fake_generic_yaml, 'text/x-yaml'),
        'config_routing_yml': (fake_routing_yml, 'text/x-yaml'),
        'config_routing_bak': (fake_generic_yaml, 'text/x-yaml'),
        'config_security_yml': (fake_security_yml, 'text/x-yaml'),
        'config_security_bak': (fake_generic_yaml, 'text/x-yaml'),
        # ASP.NET config
        'config_appsettings_json': (fake_appsettings_json, 'application/json'),
        'config_appsettings_bak': (fake_appsettings_json, 'application/json'),
        # Node.js / JS config
        'config_package_json': (fake_package_json, 'application/json'),
        'config_package_bak': (fake_generic_json, 'application/json'),
        'config_composer_json': (fake_composer_json, 'application/json'),
        'config_composer_bak': (fake_generic_json, 'application/json'),
        # Ruby / Python config
        'config_gemfile': (fake_gemfile, 'text/plain'),
        'config_gemfile_lock': (fake_gemfile_lock, 'text/plain'),
        'config_pip_conf': (fake_pip_conf, 'text/plain'),
        'config_pip_bak': (fake_pip_conf, 'text/plain'),
        'config_requirements_txt': (fake_requirements_txt, 'text/plain'),
        'config_requirements_bak': (fake_requirements_txt, 'text/plain'),
        'config_setup_cfg': (fake_setup_cfg, 'text/plain'),
        'config_setup_bak': (fake_setup_cfg, 'text/plain'),
        'config_tox_ini': (fake_tox_ini, 'text/plain'),
        'config_tox_bak': (fake_tox_ini, 'text/plain'),
        # Build / deployment config
        'config_makefile': (fake_makefile, 'text/plain'),
        'config_makefile_bak': (fake_makefile, 'text/plain'),
        'config_dockerfile': (fake_dockerfile, 'text/plain'),
        'config_dockerfile_bak': (fake_dockerfile, 'text/plain'),
        'config_docker_compose_yml': (fake_docker_compose_yml, 'text/x-yaml'),
        'config_docker_compose_bak': (fake_docker_compose_yml, 'text/x-yaml'),
        # Web server config
        'config_nginx_conf': (fake_nginx_conf, 'text/plain'),
        'config_nginx_bak': (fake_nginx_conf, 'text/plain'),
        'config_apache_conf': (fake_apache_conf, 'text/plain'),
        'config_apache_bak': (fake_apache_conf, 'text/plain'),
        'config_httpd_conf': (fake_httpd_conf, 'text/plain'),
        'config_httpd_bak': (fake_httpd_conf, 'text/plain'),
        # Database config
        'config_my_cnf': (fake_my_cnf, 'text/plain'),
        'config_my_cnf_bak': (fake_my_cnf, 'text/plain'),
        'config_mysqld_cnf': (fake_my_cnf, 'text/plain'),
        'config_postgresql_conf': (fake_postgresql_conf, 'text/plain'),
        'config_postgresql_bak': (fake_postgresql_conf, 'text/plain'),
        'config_redis_conf': (fake_redis_conf, 'text/plain'),
        'config_redis_bak': (fake_redis_conf, 'text/plain'),
        # PHP ini
        'config_php_ini': (fake_php_ini, 'text/plain'),
        'config_php_ini_bak': (fake_php_ini, 'text/plain'),
        # SQL dump files
        'config_backup_sql': (fake_sql_dump, 'application/sql'),
        'config_backup_bak': (fake_sql_dump, 'application/sql'),
        'config_dump_sql': (fake_sql_dump, 'application/sql'),
        'config_dump_bak': (fake_sql_dump, 'application/sql'),
        'config_database_sql': (fake_sql_dump, 'application/sql'),
        'config_db_sql': (fake_sql_dump, 'application/sql'),
        'config_db_bak': (fake_sql_dump, 'application/sql'),
        'config_dump_gz': (fake_generic_text, 'application/gzip'),
        'config_dump_zip': (fake_generic_text, 'application/zip'),
        'config_backup_tar_gz': (fake_generic_text, 'application/gzip'),
        'config_backup_zip': (fake_generic_text, 'application/zip'),
        # SQL / DB directories (prefix)
        'config_sql_dir': (fake_db_directory, 'text/html'),
        'config_mysql_dir': (fake_db_directory, 'text/html'),
        'config_postgres_dir': (fake_db_directory, 'text/html'),
        # Git config files
        'config_git_config': (fake_git_config, 'text/plain'),
        'config_git_head': (fake_git_head, 'text/plain'),
        'config_git_index': (fake_git_index, 'text/plain'),
        # Security disclosure
        'config_security_txt': (fake_security_txt, 'text/plain'),
        'config_well_known_security_txt': (fake_security_txt, 'text/plain'),
    }

    # Fallback body for any routed path that has no bespoke builder.
    # Content-appropriate (plaintext) rather than a mismatched wp-config.php,
    # so a scanner cannot distinguish the host as a honeypot by body type.
    _DEFAULT_BODY = (fake_generic_text, 'text/plain')

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a config disclosure response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        method = self._extract_method(raw_request)
        body = self._extract_body(raw_request, headers)

        request_data = {
            'path': path,
            'method': method,
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        # POST bodies may carry exploit/IOC payloads (e.g. the
        # `0x[]=DTAB` probe seen in production). Surface them as a dedicated
        # exploit/IOC signal without broadening credential capture.
        if method == 'POST' and body:
            profile.record_request(
                {
                    'path': path,
                    'method': method,
                    'vector': 'config_disclosure_post',
                    'post_body': body,
                    'raw': raw_request,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }
            )

        # Escalate on config file access attempts
        profile.escalation_label = 'config_file_probe'

        path_lower = path.lower()

        # Prefer the route-matched body (single source of truth from
        # routes_config_disclosure.py). If the router exposed the matched
        # route name, use it directly; otherwise fall back to a substring
        # lookup so the handler is correct even when invoked directly.
        route_name = self._matched_route_name(path_lower)
        if route_name is None:
            route_name = ''
        builder, content_type = self._RESPONSE_MAP.get(route_name, self._DEFAULT_BODY)

        response_body = builder()
        return self._build_http_response(
            response_body, 200, 'OK', {'Content-Type': content_type}
        ), self.DETECTED_ID

    def _matched_route_name(self, path_lower: str) -> str | None:
        """Return the route ``name`` whose matcher matches ``path_lower``.

        Reuses the canonical route table from routes_config_disclosure.py so the
        handler's body is always aligned with what the router actually routes.
        """
        from manyfaced.handlers.routes.routes_config_disclosure import ROUTES

        for route in ROUTES:
            if route.matcher.match(path_lower):
                return route.name
        return None

    def _extract_body(self, raw_request: str, headers: dict[str, str] | None) -> str:
        """Extract the decoded POST/PUT body from a raw HTTP request."""
        if not raw_request:
            return ''
        # Body starts after the first blank line.
        split = raw_request.split('\r\n\r\n', 1)
        if len(split) < 2:
            return ''
        raw_body = split[1]
        ctype = (headers or {}).get('Content-Type', '')
        try:
            if 'application/x-www-form-urlencoded' in ctype:
                return unquote_plus(raw_body)
            return raw_body
        except Exception:
            return raw_body

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
