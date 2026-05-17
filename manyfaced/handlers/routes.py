"""Explicit HTTP route table for the honeypot router.

The order of ROUTES is the dispatch policy. To change which handler wins for a
given path, reorder entries here.  Do NOT scatter routing decisions across
handler classes.

Overlap resolution (deliberate ordering):
    /xmlrpc.php       → WordPressHandler   (WordPress canonical endpoint)
    /files            → DrupalHandler      (Drupal files directory)
    /mysql            → PhpMyAdminHandler  (phpMyAdmin database admin)

ConfigDisclosure's patterns all migrate intact — they simply lose the above
three paths because higher-priority routes are listed first.

WebDAVHandler is NOT registered here (separate brief).
"""

from __future__ import annotations

# Router types
from manyfaced.handlers.router import Any, PathExact, PathPrefix, Route, Router

# Handler classes (imported lazily to avoid circular imports)
# We store the *class* in each Route; the router instantiates it on dispatch.


def _wp() -> type:  # noqa: N999 — module-level name is fine for internal helper
    from manyfaced.handlers.wordpress_handler import WordPressHandler

    return WordPressHandler


def _pma() -> type:
    from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler

    return PhpMyAdminHandler


def _jenkins() -> type:
    from manyfaced.handlers.jenkins_handler import JenkinsHandler

    return JenkinsHandler


def _tomcat() -> type:
    from manyfaced.handlers.tomcat_handler import TomcatHandler

    return TomcatHandler


def _drupal() -> type:
    from manyfaced.handlers.drupal_handler import DrupalHandler

    return DrupalHandler


def _cpanel() -> type:
    from manyfaced.handlers.cpanel_handler import CPanelHandler

    return CPanelHandler


def _config_disclosure() -> type:
    from manyfaced.handlers.config_disclosure_handler import ConfigDisclosureHandler

    return ConfigDisclosureHandler


def _generic() -> type:
    from manyfaced.handlers.generic_handler import GenericHandler

    return GenericHandler


def _bitrix() -> type:
    from manyfaced.handlers.bitrix_handler import BitrixHandler

    return BitrixHandler


# ---------------------------------------------------------------------------
# ROUTES – ordered list of Route entries
# ---------------------------------------------------------------------------

ROUTES: list[Route] = [
    # ---- WordPress (canonical WP endpoints win over Drupal/ConfigDisclosure) ---
    Route(PathExact('/wp-login'), _wp(), 1, 'wordpress_wp_login'),
    Route(PathPrefix('/wp-login.php'), _wp(), 1, 'wordpress_wp_login_php'),
    Route(PathExact('/wp-admin'), _wp(), 1, 'wordpress_wp_admin'),
    Route(PathPrefix('/wp-admin/'), _wp(), 1, 'wordpress_wp_admin_slash'),
    Route(PathExact('/wp-content'), _wp(), 1, 'wordpress_wp_content'),
    Route(PathPrefix('/wp-content/'), _wp(), 1, 'wordpress_wp_content_slash'),
    Route(PathExact('/wp-includes'), _wp(), 1, 'wordpress_wp_includes'),
    Route(PathPrefix('/wp-includes/'), _wp(), 1, 'wordpress_wp_includes_slash'),
    # /xmlrpc.php — WordPress wins (overlap: Drupal + ConfigDisclosure also claim it)
    Route(PathExact('/xmlrpc.php'), _wp(), 1, 'wordpress_xmlrpc_php'),
    Route(PathExact('/wordpress'), _wp(), 1, 'wordpress_wordpress'),
    Route(PathPrefix('/wordpress/'), _wp(), 1, 'wordpress_wordpress_slash'),
    Route(PathExact('/blog'), _wp(), 1, 'wordpress_blog'),
    Route(PathPrefix('/blog/'), _wp(), 1, 'wordpress_blog_slash'),
    # ---- phpMyAdmin (canonical DB admin endpoints) ---------------------------
    Route(PathExact('/phpmyadmin'), _pma(), 1, 'phpmyadmin_phpmyadmin'),
    Route(PathPrefix('/phpmyadmin/'), _pma(), 1, 'phpmyadmin_phpmyadmin_slash'),
    Route(
        PathExact('/phpmyadmin/index.php'),
        _pma(),
        1,
        'phpmyadmin_index_php',
    ),
    Route(PathExact('/pma'), _pma(), 1, 'phpmyadmin_pma'),
    Route(PathPrefix('/pma/'), _pma(), 1, 'phpmyadmin_pma_slash'),
    Route(PathExact('/pma/index.php'), _pma(), 1, 'phpmyadmin_pma_index_php'),
    # /mysql — phpMyAdmin wins (overlap: ConfigDisclosure also claims it)
    Route(PathExact('/mysql'), _pma(), 1, 'phpmyadmin_mysql'),
    Route(PathPrefix('/mysql/'), _pma(), 1, 'phpmyadmin_mysql_slash'),
    Route(PathExact('/mysql/index.php'), _pma(), 1, 'phpmyadmin_mysql_index_php'),
    Route(PathExact('/db'), _pma(), 1, 'phpmyadmin_db'),
    Route(PathPrefix('/db/'), _pma(), 1, 'phpmyadmin_db_slash'),
    Route(PathExact('/db/index.php'), _pma(), 1, 'phpmyadmin_db_index_php'),
    Route(PathExact('/database'), _pma(), 1, 'phpmyadmin_database'),
    Route(PathPrefix('/database/'), _pma(), 1, 'phpmyadmin_database_slash'),
    Route(
        PathExact('/database/index.php'),
        _pma(),
        1,
        'phpmyadmin_database_index_php',
    ),
    # ---- Jenkins -------------------------------------------------------------
    Route(PathExact('/jenkins'), _jenkins(), 1, 'jenkins_jenkins'),
    Route(PathPrefix('/jenkins/'), _jenkins(), 1, 'jenkins_jenkins_slash'),
    Route(PathExact('/jenkins/login'), _jenkins(), 1, 'jenkins_login'),
    Route(PathExact('/jenkins/script'), _jenkins(), 1, 'jenkins_script'),
    Route(PathExact('/jenkins/manage'), _jenkins(), 1, 'jenkins_manage'),
    Route(PathExact('/jenkins/api'), _jenkins(), 1, 'jenkins_api'),
    Route(PathExact('/jenkins/computer'), _jenkins(), 1, 'jenkins_computer'),
    Route(PathExact('/jenkins/view'), _jenkins(), 1, 'jenkins_view'),
    Route(PathExact('/jenkins/job'), _jenkins(), 1, 'jenkins_job'),
    Route(PathExact('/hudson'), _jenkins(), 1, 'jenkins_hudson'),
    Route(PathPrefix('/hudson/'), _jenkins(), 1, 'jenkins_hudson_slash'),
    Route(PathExact('/hudson/login'), _jenkins(), 1, 'jenkins_hudson_login'),
    # ---- Tomcat --------------------------------------------------------------
    Route(PathExact('/manager'), _tomcat(), 1, 'tomcat_manager'),
    Route(PathPrefix('/manager/'), _tomcat(), 1, 'tomcat_manager_slash'),
    Route(PathExact('/manager/html'), _tomcat(), 1, 'tomcat_manager_html'),
    Route(PathExact('/host-manager'), _tomcat(), 1, 'tomcat_host_manager'),
    Route(PathPrefix('/host-manager/'), _tomcat(), 1, 'tomcat_host_manager_slash'),
    Route(
        PathExact('/host-manager/html'),
        _tomcat(),
        1,
        'tomcat_host_manager_html',
    ),
    Route(PathExact('/tomcat'), _tomcat(), 1, 'tomcat_tomcat'),
    Route(PathPrefix('/tomcat/'), _tomcat(), 1, 'tomcat_tomcat_slash'),
    Route(PathExact('/server-status'), _tomcat(), 1, 'tomcat_server_status'),
    Route(PathExact('/server-info'), _tomcat(), 1, 'tomcat_server_info'),
    Route(PathExact('/jmxproxy'), _tomcat(), 1, 'tomcat_jmx_proxy'),
    Route(PathPrefix('/jmxproxy/'), _tomcat(), 1, 'tomcat_jmx_proxy_slash'),
    Route(PathExact('/examples'), _tomcat(), 1, 'tomcat_examples'),
    Route(PathPrefix('/examples/'), _tomcat(), 1, 'tomcat_examples_slash'),
    Route(PathExact('/ROOT'), _tomcat(), 1, 'tomcat_root'),
    Route(PathPrefix('/ROOT/'), _tomcat(), 1, 'tomcat_root_slash'),
    # ---- Drupal (canonical CMS endpoints) ------------------------------------
    Route(PathExact('/user'), _drupal(), 1, 'drupal_user'),
    Route(PathPrefix('/user/'), _drupal(), 1, 'drupal_user_slash'),
    Route(PathExact('/user/login'), _drupal(), 1, 'drupal_user_login'),
    Route(PathExact('/user/register'), _drupal(), 1, 'drupal_user_register'),
    Route(PathExact('/admin'), _drupal(), 1, 'drupal_admin'),
    Route(PathPrefix('/admin/'), _drupal(), 1, 'drupal_admin_slash'),
    Route(PathExact('/admin/config'), _drupal(), 1, 'drupal_admin_config'),
    Route(PathExact('/node'), _drupal(), 1, 'drupal_node'),
    Route(PathPrefix('/node/'), _drupal(), 1, 'drupal_node_slash'),
    Route(PathExact('/sites'), _drupal(), 1, 'drupal_sites'),
    Route(PathPrefix('/sites/'), _drupal(), 1, 'drupal_sites_slash'),
    Route(
        PathExact('/sites/default'),
        _drupal(),
        1,
        'drupal_sites_default',
    ),
    # /xmlrpc.php already claimed by WordPress above — Drupal's pattern is
    # intentionally omitted here (overlap resolution: WordPress wins).
    Route(PathExact('/drupal'), _drupal(), 1, 'drupal_drupal'),
    Route(PathPrefix('/drupal/'), _drupal(), 1, 'drupal_drupal_slash'),
    Route(PathExact('/cgi-bin'), _drupal(), 1, 'drupal_cgi_bin'),
    Route(PathPrefix('/cgi-bin/'), _drupal(), 1, 'drupal_cgi_bin_slash'),
    # /files — Drupal wins (overlap: WebDAV also claims it; separate brief)
    Route(PathExact('/files'), _drupal(), 1, 'drupal_files'),
    Route(PathPrefix('/files/'), _drupal(), 1, 'drupal_files_slash'),
    # ---- cPanel / WHM --------------------------------------------------------
    Route(PathExact('/cpanel'), _cpanel(), 1, 'cpanel_cpanel'),
    Route(PathPrefix('/cpanel/'), _cpanel(), 1, 'cpanel_cpanel_slash'),
    Route(
        PathExact('/cpanel/hotlinkprotect'),
        _cpanel(),
        1,
        'cpanel_hotlinkprotect',
    ),
    Route(PathExact('/whm'), _cpanel(), 1, 'cpanel_whm'),
    Route(PathPrefix('/whm/'), _cpanel(), 1, 'cpanel_whm_slash'),
    Route(PathExact('/whm/login'), _cpanel(), 1, 'cpanel_whm_login'),
    Route(PathExact('/webmail'), _cpanel(), 1, 'cpanel_webmail'),
    Route(PathPrefix('/webmail/'), _cpanel(), 1, 'cpanel_webmail_slash'),
    Route(PathExact('/webmail/login'), _cpanel(), 1, 'cpanel_webmail_login'),
    Route(PathExact('/mail'), _cpanel(), 1, 'cpanel_mail'),
    Route(PathPrefix('/mail/'), _cpanel(), 1, 'cpanel_mail_slash'),
    Route(PathExact('/webdisk'), _cpanel(), 1, 'cpanel_webdisk'),
    Route(PathPrefix('/webdisk/'), _cpanel(), 1, 'cpanel_webdisk_slash'),
    Route(PathExact('/cpsess'), _cpanel(), 1, 'cpanel_cpsess'),
    Route(PathExact('/setup1'), _cpanel(), 1, 'cpanel_setup1'),
    Route(PathPrefix('/setup1/'), _cpanel(), 1, 'cpanel_setup1_slash'),
    Route(PathExact('/~'), _cpanel(), 1, 'cpanel_tilde'),
    # ---- Bitrix (1C-Bitrix CMS) --------------------------------------------------
    Route(PathExact('/bitrix/admin'), _bitrix(), 1, 'bitrix_admin'),
    Route(PathPrefix('/bitrix/admin/'), _bitrix(), 1, 'bitrix_admin_slash'),
    Route(PathPrefix('/bitrix/auth/'), _bitrix(), 1, 'bitrix_auth'),
    Route(PathExact('/bitrix/auth'), _bitrix(), 1, 'bitrix_auth_exact'),
    Route(PathPrefix('/bitrix/setup/'), _bitrix(), 1, 'bitrix_setup'),
    Route(PathPrefix('/bitrix/tools/'), _bitrix(), 1, 'bitrix_tools'),
    Route(PathExact('/bitrix'), _bitrix(), 1, 'bitrix_bitrix'),
    Route(PathPrefix('/bitrix/'), _bitrix(), 1, 'bitrix_slash'),
    # ---- ConfigDisclosure (all patterns migrate intact; loses overlaps above) -
    # WordPress config files
    Route(PathExact('/wp-config.php'), _config_disclosure(), 1, 'config_wp_config_php'),
    Route(
        PathExact('/wp-config.php.bak'),
        _config_disclosure(),
        1,
        'config_wp_config_bak',
    ),
    Route(
        PathExact('/wp-config.php.old'),
        _config_disclosure(),
        1,
        'config_wp_config_old',
    ),
    Route(
        PathExact('/wp-config.php.dist'),
        _config_disclosure(),
        1,
        'config_wp_config_dist',
    ),
    Route(
        PathExact('/wp-config.php.txt'),
        _config_disclosure(),
        1,
        'config_wp_config_txt',
    ),
    # PHP config files
    Route(PathExact('/config.php'), _config_disclosure(), 1, 'config_php'),
    Route(PathExact('/config.php.bak'), _config_disclosure(), 1, 'config_php_bak'),
    Route(PathExact('/config.php.old'), _config_disclosure(), 1, 'config_php_old'),
    Route(
        PathExact('/configuration.php'),
        _config_disclosure(),
        1,
        'config_configuration_php',
    ),
    Route(
        PathExact('/configuration.php.bak'),
        _config_disclosure(),
        1,
        'config_configuration_bak',
    ),
    # Python config files
    Route(PathExact('/settings.py'), _config_disclosure(), 1, 'config_settings_py'),
    Route(
        PathExact('/settings.py.bak'),
        _config_disclosure(),
        1,
        'config_settings_bak',
    ),
    Route(
        PathExact('/settings.py.old'),
        _config_disclosure(),
        1,
        'config_settings_old',
    ),
    # Ruby config files
    Route(PathExact('/database.yml'), _config_disclosure(), 1, 'config_database_yml'),
    Route(
        PathExact('/database.yml.bak'),
        _config_disclosure(),
        1,
        'config_database_bak',
    ),
    # JSON config files
    Route(PathExact('/config.json'), _config_disclosure(), 1, 'config_json'),
    Route(
        PathExact('/config.json.bak'),
        _config_disclosure(),
        1,
        'config_json_bak',
    ),
    # Environment files
    Route(PathExact('/.env'), _config_disclosure(), 1, 'config_env'),
    Route(PathExact('/.env.bak'), _config_disclosure(), 1, 'config_env_bak'),
    Route(PathExact('/.env.local'), _config_disclosure(), 1, 'config_env_local'),
    Route(PathExact('/.env.prod'), _config_disclosure(), 1, 'config_env_prod'),
    Route(PathExact('/.env.example'), _config_disclosure(), 1, 'config_env_example'),
    Route(PathExact('/.env.sample'), _config_disclosure(), 1, 'config_env_sample'),
    # Apache config files
    Route(PathExact('/.htaccess'), _config_disclosure(), 1, 'config_htaccess'),
    Route(PathExact('/.htaccess.bak'), _config_disclosure(), 1, 'config_htaccess_bak'),
    Route(
        PathExact('/.htaccess.old'),
        _config_disclosure(),
        1,
        'config_htaccess_old',
    ),
    Route(PathExact('/.htpasswd'), _config_disclosure(), 1, 'config_htpasswd'),
    Route(
        PathExact('/.htpasswd.bak'),
        _config_disclosure(),
        1,
        'config_htpasswd_bak',
    ),
    # XML-RPC (overlap: WordPress wins above; this route is unreachable for /xmlrpc.php)
    Route(PathExact('/xmlrpc.php'), _config_disclosure(), 1, 'config_xmlrpc_php'),
    Route(
        PathExact('/xmlrpc.php.bak'),
        _config_disclosure(),
        1,
        'config_xmlrpc_bak',
    ),
    # Windows config files
    Route(PathExact('/web.config'), _config_disclosure(), 1, 'config_web_config'),
    Route(
        PathExact('/web.config.bak'),
        _config_disclosure(),
        1,
        'config_web_config_bak',
    ),
    # Additional PHP config files
    Route(PathExact('/conf.php'), _config_disclosure(), 1, 'config_conf_php'),
    Route(
        PathExact('/conf.php.bak'),
        _config_disclosure(),
        1,
        'config_conf_bak',
    ),
    Route(PathExact('/db.php'), _config_disclosure(), 1, 'config_db_php'),
    Route(
        PathExact('/db.php.bak'),
        _config_disclosure(),
        1,
        'config_db_bak',
    ),
    Route(PathExact('/local.php'), _config_disclosure(), 1, 'config_local_php'),
    Route(
        PathExact('/local.php.bak'),
        _config_disclosure(),
        1,
        'config_local_bak',
    ),
    # .NET / other config files
    Route(PathExact('/app.config'), _config_disclosure(), 1, 'config_app_config'),
    Route(
        PathExact('/app.config.bak'),
        _config_disclosure(),
        1,
        'config_app_bak',
    ),
    Route(
        PathExact('/application.ini'),
        _config_disclosure(),
        1,
        'config_application_ini',
    ),
    Route(
        PathExact('/application.ini.bak'),
        _config_disclosure(),
        1,
        'config_application_bak',
    ),
    Route(PathExact('/globals.php'), _config_disclosure(), 1, 'config_globals_php'),
    Route(
        PathExact('/globals.php.bak'),
        _config_disclosure(),
        1,
        'config_globals_bak',
    ),
    Route(
        PathExact('/initialize.php'),
        _config_disclosure(),
        1,
        'config_initialize_php',
    ),
    Route(
        PathExact('/initialize.php.bak'),
        _config_disclosure(),
        1,
        'config_initialize_bak',
    ),
    Route(
        PathExact('/constants.php'),
        _config_disclosure(),
        1,
        'config_constants_php',
    ),
    Route(
        PathExact('/constants.php.bak'),
        _config_disclosure(),
        1,
        'config_constants_bak',
    ),
    # Symfony / YAML config files
    Route(
        PathExact('/parameters.yml'),
        _config_disclosure(),
        1,
        'config_parameters_yml',
    ),
    Route(
        PathExact('/parameters.yml.dist'),
        _config_disclosure(),
        1,
        'config_parameters_dist',
    ),
    Route(PathExact('/service.yml'), _config_disclosure(), 1, 'config_service_yml'),
    Route(
        PathExact('/service.yml.bak'),
        _config_disclosure(),
        1,
        'config_service_bak',
    ),
    Route(
        PathExact('/doctrine.yml'),
        _config_disclosure(),
        1,
        'config_doctrine_yml',
    ),
    Route(
        PathExact('/doctrine.yml.bak'),
        _config_disclosure(),
        1,
        'config_doctrine_bak',
    ),
    Route(PathExact('/routing.yml'), _config_disclosure(), 1, 'config_routing_yml'),
    Route(
        PathExact('/routing.yml.bak'),
        _config_disclosure(),
        1,
        'config_routing_bak',
    ),
    Route(
        PathExact('/security.yml'),
        _config_disclosure(),
        1,
        'config_security_yml',
    ),
    Route(
        PathExact('/security.yml.bak'),
        _config_disclosure(),
        1,
        'config_security_bak',
    ),
    # ASP.NET config files
    Route(
        PathExact('/appsettings.json'),
        _config_disclosure(),
        1,
        'config_appsettings_json',
    ),
    Route(
        PathExact('/appsettings.json.bak'),
        _config_disclosure(),
        1,
        'config_appsettings_bak',
    ),
    # Node.js / JS config files
    Route(PathExact('/package.json'), _config_disclosure(), 1, 'config_package_json'),
    Route(
        PathExact('/package.json.bak'),
        _config_disclosure(),
        1,
        'config_package_bak',
    ),
    Route(
        PathExact('/composer.json'),
        _config_disclosure(),
        1,
        'config_composer_json',
    ),
    Route(
        PathExact('/composer.json.bak'),
        _config_disclosure(),
        1,
        'config_composer_bak',
    ),
    # Ruby / Python config files
    Route(PathExact('/Gemfile'), _config_disclosure(), 1, 'config_gemfile'),
    Route(
        PathExact('/Gemfile.lock'),
        _config_disclosure(),
        1,
        'config_gemfile_lock',
    ),
    Route(PathExact('/pip.conf'), _config_disclosure(), 1, 'config_pip_conf'),
    Route(
        PathExact('/pip.conf.bak'),
        _config_disclosure(),
        1,
        'config_pip_bak',
    ),
    Route(
        PathExact('/requirements.txt'),
        _config_disclosure(),
        1,
        'config_requirements_txt',
    ),
    Route(
        PathExact('/requirements.txt.bak'),
        _config_disclosure(),
        1,
        'config_requirements_bak',
    ),
    Route(PathExact('/setup.cfg'), _config_disclosure(), 1, 'config_setup_cfg'),
    Route(
        PathExact('/setup.cfg.bak'),
        _config_disclosure(),
        1,
        'config_setup_bak',
    ),
    Route(PathExact('/tox.ini'), _config_disclosure(), 1, 'config_tox_ini'),
    Route(
        PathExact('/tox.ini.bak'),
        _config_disclosure(),
        1,
        'config_tox_bak',
    ),
    # Build / deployment config files
    Route(PathExact('/Makefile'), _config_disclosure(), 1, 'config_makefile'),
    Route(
        PathExact('/Makefile.bak'),
        _config_disclosure(),
        1,
        'config_makefile_bak',
    ),
    Route(PathExact('/Dockerfile'), _config_disclosure(), 1, 'config_dockerfile'),
    Route(
        PathExact('/Dockerfile.bak'),
        _config_disclosure(),
        1,
        'config_dockerfile_bak',
    ),
    Route(
        PathExact('/docker-compose.yml'),
        _config_disclosure(),
        1,
        'config_docker_compose_yml',
    ),
    Route(
        PathExact('/docker-compose.yml.bak'),
        _config_disclosure(),
        1,
        'config_docker_compose_bak',
    ),
    # Web server config files
    Route(PathExact('/nginx.conf'), _config_disclosure(), 1, 'config_nginx_conf'),
    Route(
        PathExact('/nginx.conf.bak'),
        _config_disclosure(),
        1,
        'config_nginx_bak',
    ),
    Route(PathExact('/apache.conf'), _config_disclosure(), 1, 'config_apache_conf'),
    Route(
        PathExact('/apache.conf.bak'),
        _config_disclosure(),
        1,
        'config_apache_bak',
    ),
    Route(PathExact('/httpd.conf'), _config_disclosure(), 1, 'config_httpd_conf'),
    Route(
        PathExact('/httpd.conf.bak'),
        _config_disclosure(),
        1,
        'config_httpd_bak',
    ),
    # Database config files
    Route(PathExact('/my.cnf'), _config_disclosure(), 1, 'config_my_cnf'),
    Route(
        PathExact('/my.cnf.bak'),
        _config_disclosure(),
        1,
        'config_my_cnf_bak',
    ),
    Route(PathExact('/mysqld.cnf'), _config_disclosure(), 1, 'config_mysqld_cnf'),
    Route(
        PathExact('/postgresql.conf'),
        _config_disclosure(),
        1,
        'config_postgresql_conf',
    ),
    Route(
        PathExact('/postgresql.conf.bak'),
        _config_disclosure(),
        1,
        'config_postgresql_bak',
    ),
    Route(PathExact('/redis.conf'), _config_disclosure(), 1, 'config_redis_conf'),
    Route(
        PathExact('/redis.conf.bak'),
        _config_disclosure(),
        1,
        'config_redis_bak',
    ),
    # PHP config files
    Route(PathExact('/php.ini'), _config_disclosure(), 1, 'config_php_ini'),
    Route(
        PathExact('/php.ini.bak'),
        _config_disclosure(),
        1,
        'config_php_ini_bak',
    ),
    # PHP info / debug files
    Route(PathExact('/phpinfo.php'), _config_disclosure(), 1, 'config_phpinfo_php'),
    Route(
        PathExact('/phpinfo.php.bak'),
        _config_disclosure(),
        1,
        'config_phpinfo_bak',
    ),
    Route(PathExact('/info.php'), _config_disclosure(), 1, 'config_info_php'),
    Route(
        PathExact('/info.php.bak'),
        _config_disclosure(),
        1,
        'config_info_bak',
    ),
    Route(PathExact('/test.php'), _config_disclosure(), 1, 'config_test_php'),
    Route(
        PathExact('/test.php.bak'),
        _config_disclosure(),
        1,
        'config_test_bak',
    ),
    Route(PathExact('/debug.php'), _config_disclosure(), 1, 'config_debug_php'),
    Route(
        PathExact('/debug.php.bak'),
        _config_disclosure(),
        1,
        'config_debug_bak',
    ),
    Route(PathExact('/console.php'), _config_disclosure(), 1, 'config_console_php'),
    Route(
        PathExact('/console.php.bak'),
        _config_disclosure(),
        1,
        'config_console_bak',
    ),
    Route(PathExact('/cli.php'), _config_disclosure(), 1, 'config_cli_php'),
    Route(
        PathExact('/cli.php.bak'),
        _config_disclosure(),
        1,
        'config_cli_bak',
    ),
    # Install / upgrade files
    Route(PathExact('/install.php'), _config_disclosure(), 1, 'config_install_php'),
    Route(
        PathExact('/install.php.bak'),
        _config_disclosure(),
        1,
        'config_install_bak',
    ),
    Route(PathExact('/upgrade.php'), _config_disclosure(), 1, 'config_upgrade_php'),
    Route(
        PathExact('/upgrade.php.bak'),
        _config_disclosure(),
        1,
        'config_upgrade_bak',
    ),
    # SQL dump files
    Route(PathExact('/backup.sql'), _config_disclosure(), 1, 'config_backup_sql'),
    Route(
        PathExact('/backup.sql.bak'),
        _config_disclosure(),
        1,
        'config_backup_bak',
    ),
    Route(PathExact('/dump.sql'), _config_disclosure(), 1, 'config_dump_sql'),
    Route(
        PathExact('/dump.sql.bak'),
        _config_disclosure(),
        1,
        'config_dump_bak',
    ),
    Route(
        PathExact('/database.sql'),
        _config_disclosure(),
        1,
        'config_database_sql',
    ),
    Route(
        PathExact('/database.sql.bak'),
        _config_disclosure(),
        1,
        'config_database_bak',
    ),
    Route(PathExact('/db.sql'), _config_disclosure(), 1, 'config_db_sql'),
    Route(
        PathExact('/db.sql.bak'),
        _config_disclosure(),
        1,
        'config_db_bak',
    ),
    Route(PathExact('/dump.sql.gz'), _config_disclosure(), 1, 'config_dump_gz'),
    Route(PathExact('/dump.sql.zip'), _config_disclosure(), 1, 'config_dump_zip'),
    Route(
        PathExact('/backup.tar.gz'),
        _config_disclosure(),
        1,
        'config_backup_tar_gz',
    ),
    Route(PathExact('/backup.zip'), _config_disclosure(), 1, 'config_backup_zip'),
    # SQL / DB directories (prefix match)
    Route(PathPrefix('/sql/'), _config_disclosure(), 1, 'config_sql_dir'),
    Route(
        PathPrefix('/mysql/'),
        _config_disclosure(),
        1,
        'config_mysql_dir',
    ),
    Route(
        PathPrefix('/postgres/'),
        _config_disclosure(),
        1,
        'config_postgres_dir',
    ),
    # Git config files (prefix match for .git subpaths)
    Route(PathExact('/.git/config'), _config_disclosure(), 1, 'config_git_config'),
    Route(PathExact('/.git/head'), _config_disclosure(), 1, 'config_git_head'),
    Route(PathExact('/.git/index'), _config_disclosure(), 1, 'config_git_index'),
    # Security disclosure files
    Route(
        PathExact('/security.txt'),
        _config_disclosure(),
        1,
        'config_security_txt',
    ),
    Route(
        PathExact('/.well-known/security.txt'),
        _config_disclosure(),
        1,
        'config_well_known_security_txt',
    ),
    # ---- Catch-all (GenericHandler) ------------------------------------------
    Route(Any(), _generic(), 4294967294, 'catchall_monster_page'),
]


# ---------------------------------------------------------------------------
# Router singleton
# ---------------------------------------------------------------------------

router = Router(ROUTES)
