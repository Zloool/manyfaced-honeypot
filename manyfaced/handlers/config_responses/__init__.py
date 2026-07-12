"""Standalone response builders for ConfigDisclosureHandler fake config content.

Each function returns a string of realistic but fake configuration file content.
Imported by ConfigDisclosureHandler to keep the handler class under 400 lines.

Functions are organized into submodules:
- php_configs.py: PHP-related configs (wp-config.php, xmlrpc.php, etc.)
- server_configs.py: Server/web server configs (.htaccess, nginx.conf, etc.)
- yaml_json_configs.py: YAML/JSON/Docker configs (database.yml, docker-compose.yml, etc.)
- security_configs.py: Environment, git, and security files (.env, .git/config, etc.)

This __init__.py re-exports all functions for backward compatibility.
"""

from manyfaced.handlers.config_responses.php_configs import (
    fake_config_php,
    fake_php_ini,
    fake_phpinfo_php,
    fake_settings_py,
    fake_wp_config_php,
    fake_xmlrpc_php,
)
from manyfaced.handlers.config_responses.security_configs import (
    fake_backup_sql,
    fake_db_directory,
    fake_env_file,
    fake_git_config,
    fake_git_head,
    fake_security_txt,
)
from manyfaced.handlers.config_responses.server_configs import (
    fake_htaccess_file,
    fake_htpasswd_file,
    fake_my_cnf,
    fake_nginx_conf,
    fake_web_config,
)
from manyfaced.handlers.config_responses.yaml_json_configs import (
    fake_composer_json,
    fake_config_json,
    fake_database_yml,
    fake_docker_compose_yml,
    fake_dockerfile,
    fake_package_json,
)
from manyfaced.handlers.config_responses.more_configs import (
    fake_application_ini,
    fake_apache_conf,
    fake_app_config,
    fake_appsettings_json,
    fake_doctrine_yml,
    fake_generic_ini,
    fake_generic_json,
    fake_generic_php,
    fake_generic_text,
    fake_generic_yaml,
    fake_gemfile,
    fake_gemfile_lock,
    fake_git_index,
    fake_httpd_conf,
    fake_makefile,
    fake_parameters_yml,
    fake_parameters_yml_dist,
    fake_pip_conf,
    fake_postgresql_conf,
    fake_redis_conf,
    fake_requirements_txt,
    fake_routing_yml,
    fake_security_yml,
    fake_service_yml,
    fake_setup_cfg,
    fake_sql_dump,
    fake_tox_ini,
)

__all__ = [
    'fake_wp_config_php',
    'fake_xmlrpc_php',
    'fake_env_file',
    'fake_htaccess_file',
    'fake_htpasswd_file',
    'fake_config_php',
    'fake_settings_py',
    'fake_database_yml',
    'fake_config_json',
    'fake_web_config',
    'fake_phpinfo_php',
    'fake_php_ini',
    'fake_my_cnf',
    'fake_nginx_conf',
    'fake_docker_compose_yml',
    'fake_dockerfile',
    'fake_composer_json',
    'fake_package_json',
    'fake_backup_sql',
    'fake_db_directory',
    'fake_git_config',
    'fake_git_head',
    'fake_security_txt',
    # more_configs
    'fake_application_ini',
    'fake_apache_conf',
    'fake_app_config',
    'fake_appsettings_json',
    'fake_doctrine_yml',
    'fake_generic_ini',
    'fake_generic_json',
    'fake_generic_php',
    'fake_generic_text',
    'fake_generic_yaml',
    'fake_gemfile',
    'fake_gemfile_lock',
    'fake_git_index',
    'fake_httpd_conf',
    'fake_makefile',
    'fake_parameters_yml',
    'fake_parameters_yml_dist',
    'fake_pip_conf',
    'fake_postgresql_conf',
    'fake_redis_conf',
    'fake_requirements_txt',
    'fake_routing_yml',
    'fake_security_yml',
    'fake_service_yml',
    'fake_setup_cfg',
    'fake_sql_dump',
    'fake_tox_ini',
]
