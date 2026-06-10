"""ConfigDisclosure routes — sensitive file disclosure patterns.

All patterns migrate intact — they simply lose overlap paths (/xmlrpc.php,
/mysql, /files) because higher-priority routes are listed first in the
combined ROUTES list.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import CONFIG_DISCLOSURE_HTTP


def _config_disclosure() -> type:
    from manyfaced.handlers.config_disclosure_handler import ConfigDisclosureHandler

    return ConfigDisclosureHandler


ROUTES: list[Route] = [
    # WordPress config files
    Route(PathExact('/wp-config.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_wp_config_php'),
    Route(PathExact('/wp-config.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_wp_config_bak'),
    Route(PathExact('/wp-config.php.old'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_wp_config_old'),
    Route(PathExact('/wp-config.php.dist'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_wp_config_dist'),
    Route(PathExact('/wp-config.php.txt'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_wp_config_txt'),
    # PHP config files
    Route(PathExact('/config.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_php'),
    Route(PathExact('/config.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_php_bak'),
    Route(PathExact('/config.php.old'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_php_old'),
    Route(PathExact('/configuration.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_configuration_php'),
    Route(PathExact('/configuration.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_configuration_bak'),
    # Python config files
    Route(PathExact('/settings.py'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_settings_py'),
    Route(PathExact('/settings.py.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_settings_bak'),
    Route(PathExact('/settings.py.old'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_settings_old'),
    # Ruby config files
    Route(PathExact('/database.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_database_yml'),
    Route(PathExact('/database.yml.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_database_bak'),
    # JSON config files
    Route(PathExact('/config.json'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_json'),
    Route(PathExact('/config.json.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_json_bak'),
    # Environment files
    Route(PathExact('/.env'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_env'),
    Route(PathExact('/.env.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_env_bak'),
    Route(PathExact('/.env.local'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_env_local'),
    Route(PathExact('/.env.prod'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_env_prod'),
    Route(PathExact('/.env.example'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_env_example'),
    Route(PathExact('/.env.sample'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_env_sample'),
    # Apache config files
    Route(PathExact('/.htaccess'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_htaccess'),
    Route(PathExact('/.htaccess.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_htaccess_bak'),
    Route(PathExact('/.htaccess.old'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_htaccess_old'),
    Route(PathExact('/.htpasswd'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_htpasswd'),
    Route(PathExact('/.htpasswd.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_htpasswd_bak'),
    # XML-RPC (overlap: WordPress wins above; this route is unreachable for /xmlrpc.php)
    Route(PathExact('/xmlrpc.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_xmlrpc_php'),
    Route(PathExact('/xmlrpc.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_xmlrpc_bak'),
    # Windows config files
    Route(PathExact('/web.config'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_web_config'),
    Route(PathExact('/web.config.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_web_config_bak'),
    # Additional PHP config files
    Route(PathExact('/conf.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_conf_php'),
    Route(PathExact('/conf.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_conf_bak'),
    Route(PathExact('/db.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_db_php'),
    Route(PathExact('/db.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_db_bak'),
    Route(PathExact('/local.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_local_php'),
    Route(PathExact('/local.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_local_bak'),
    # .NET / other config files
    Route(PathExact('/app.config'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_app_config'),
    Route(PathExact('/app.config.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_app_bak'),
    Route(PathExact('/application.ini'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_application_ini'),
    Route(PathExact('/application.ini.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_application_bak'),
    Route(PathExact('/globals.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_globals_php'),
    Route(PathExact('/globals.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_globals_bak'),
    Route(PathExact('/initialize.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_initialize_php'),
    Route(PathExact('/initialize.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_initialize_bak'),
    Route(PathExact('/constants.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_constants_php'),
    Route(PathExact('/constants.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_constants_bak'),
    # Symfony / YAML config files
    Route(PathExact('/parameters.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_parameters_yml'),
    Route(PathExact('/parameters.yml.dist'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_parameters_dist'),
    Route(PathExact('/service.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_service_yml'),
    Route(PathExact('/service.yml.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_service_bak'),
    Route(PathExact('/doctrine.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_doctrine_yml'),
    Route(PathExact('/doctrine.yml.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_doctrine_bak'),
    Route(PathExact('/routing.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_routing_yml'),
    Route(PathExact('/routing.yml.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_routing_bak'),
    Route(PathExact('/security.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_security_yml'),
    Route(PathExact('/security.yml.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_security_bak'),
    # ASP.NET config files
    Route(PathExact('/appsettings.json'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_appsettings_json'),
    Route(PathExact('/appsettings.json.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_appsettings_bak'),
    # Node.js / JS config files
    Route(PathExact('/package.json'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_package_json'),
    Route(PathExact('/package.json.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_package_bak'),
    Route(PathExact('/composer.json'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_composer_json'),
    Route(PathExact('/composer.json.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_composer_bak'),
    # Ruby / Python config files
    Route(PathExact('/Gemfile'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_gemfile'),
    Route(PathExact('/Gemfile.lock'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_gemfile_lock'),
    Route(PathExact('/pip.conf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_pip_conf'),
    Route(PathExact('/pip.conf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_pip_bak'),
    Route(PathExact('/requirements.txt'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_requirements_txt'),
    Route(PathExact('/requirements.txt.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_requirements_bak'),
    Route(PathExact('/setup.cfg'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_setup_cfg'),
    Route(PathExact('/setup.cfg.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_setup_bak'),
    Route(PathExact('/tox.ini'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_tox_ini'),
    Route(PathExact('/tox.ini.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_tox_bak'),
    # Build / deployment config files
    Route(PathExact('/Makefile'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_makefile'),
    Route(PathExact('/Makefile.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_makefile_bak'),
    Route(PathExact('/Dockerfile'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_dockerfile'),
    Route(PathExact('/Dockerfile.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_dockerfile_bak'),
    Route(PathExact('/docker-compose.yml'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_docker_compose_yml'),
    Route(
        PathExact('/docker-compose.yml.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_docker_compose_bak'
    ),
    # Web server config files
    Route(PathExact('/nginx.conf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_nginx_conf'),
    Route(PathExact('/nginx.conf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_nginx_bak'),
    Route(PathExact('/apache.conf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_apache_conf'),
    Route(PathExact('/apache.conf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_apache_bak'),
    Route(PathExact('/httpd.conf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_httpd_conf'),
    Route(PathExact('/httpd.conf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_httpd_bak'),
    # Database config files
    Route(PathExact('/my.cnf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_my_cnf'),
    Route(PathExact('/my.cnf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_my_cnf_bak'),
    Route(PathExact('/mysqld.cnf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_mysqld_cnf'),
    Route(PathExact('/postgresql.conf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_postgresql_conf'),
    Route(PathExact('/postgresql.conf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_postgresql_bak'),
    Route(PathExact('/redis.conf'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_redis_conf'),
    Route(PathExact('/redis.conf.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_redis_bak'),
    # PHP config files
    Route(PathExact('/php.ini'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_php_ini'),
    Route(PathExact('/php.ini.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_php_ini_bak'),
    # PHP info / debug files
    Route(PathExact('/phpinfo.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_phpinfo_php'),
    Route(PathExact('/phpinfo.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_phpinfo_bak'),
    Route(PathExact('/info.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_info_php'),
    Route(PathExact('/info.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_info_bak'),
    Route(PathExact('/test.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_test_php'),
    Route(PathExact('/test.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_test_bak'),
    Route(PathExact('/debug.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_debug_php'),
    Route(PathExact('/debug.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_debug_bak'),
    Route(PathExact('/console.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_console_php'),
    Route(PathExact('/console.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_console_bak'),
    Route(PathExact('/cli.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_cli_php'),
    Route(PathExact('/cli.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_cli_bak'),
    # Install / upgrade files
    Route(PathExact('/install.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_install_php'),
    Route(PathExact('/install.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_install_bak'),
    Route(PathExact('/upgrade.php'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_upgrade_php'),
    Route(PathExact('/upgrade.php.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_upgrade_bak'),
    # SQL dump files
    Route(PathExact('/backup.sql'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_backup_sql'),
    Route(PathExact('/backup.sql.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_backup_bak'),
    Route(PathExact('/dump.sql'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_dump_sql'),
    Route(PathExact('/dump.sql.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_dump_bak'),
    Route(PathExact('/database.sql'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_database_sql'),
    Route(PathExact('/database.sql.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_database_bak'),
    Route(PathExact('/db.sql'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_db_sql'),
    Route(PathExact('/db.sql.bak'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_db_bak'),
    Route(PathExact('/dump.sql.gz'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_dump_gz'),
    Route(PathExact('/dump.sql.zip'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_dump_zip'),
    Route(PathExact('/backup.tar.gz'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_backup_tar_gz'),
    Route(PathExact('/backup.zip'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_backup_zip'),
    # SQL / DB directories (prefix match)
    Route(PathPrefix('/sql/'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_sql_dir'),
    Route(PathPrefix('/mysql/'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_mysql_dir'),
    Route(PathPrefix('/postgres/'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_postgres_dir'),
    # Git config files (prefix match for .git subpaths)
    Route(PathExact('/.git/config'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_git_config'),
    Route(PathExact('/.git/head'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_git_head'),
    Route(PathExact('/.git/index'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_git_index'),
    # Security disclosure files
    Route(PathExact('/security.txt'), _config_disclosure(), CONFIG_DISCLOSURE_HTTP, 'config_security_txt'),
    Route(
        PathExact('/.well-known/security.txt'),
        _config_disclosure(),
        1,
        'config_well_known_security_txt',
    ),
]
