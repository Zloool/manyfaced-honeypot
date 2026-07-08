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
"""

from __future__ import annotations

# Router types
from manyfaced.handlers.router import (  # noqa: F401
    Any,
    PathExact as PathExact,
    PathPrefix as PathPrefix,
    Route,
    Router,
)

# Handler classes (imported lazily to avoid circular imports)


def _generic() -> type:
    from manyfaced.handlers.generic_handler import GenericHandler

    return GenericHandler


# Ensure the Kubernetes shim module is part of the import graph (re-exports KubernetesHandler).
from manyfaced.handlers.k8s_handler import KubernetesHandler  # noqa: F401


# ---------------------------------------------------------------------------
# Import per-service route tables and concatenate them in order
# ---------------------------------------------------------------------------

from manyfaced.handlers.routes.routes_bitrix import ROUTES as _bitrix_routes  # noqa: E402
from manyfaced.handlers.routes.routes_config_disclosure import (
    ROUTES as _config_disclosure_routes,  # noqa: E402
)
from manyfaced.handlers.routes.routes_cpanel import ROUTES as _cpanel_routes  # noqa: E402
from manyfaced.handlers.routes.routes_drupal import ROUTES as _drupal_routes  # noqa: E402
from manyfaced.handlers.routes.routes_jenkins import ROUTES as _jenkins_routes  # noqa: E402
from manyfaced.handlers.routes.routes_phpmyadmin import (
    ROUTES as _phpmyadmin_routes,  # noqa: E402
)
from manyfaced.handlers.routes.routes_tomcat import ROUTES as _tomcat_routes  # noqa: E402
from manyfaced.handlers.routes.routes_webdav import ROUTES as _webdav_routes  # noqa: E402
from manyfaced.handlers.routes.routes_wordpress import ROUTES as _wordpress_routes  # noqa: E402
from manyfaced.handlers.routes.routes_dbadmin import ROUTES as _dbadmin_routes  # noqa: E402
from manyfaced.handlers.routes.routes_docker import ROUTES as _docker_routes  # noqa: E402
from manyfaced.handlers.routes.routes_mcp import ROUTES as _mcp_routes  # noqa: E402
from manyfaced.handlers.routes.routes_iot import ROUTES as _iot_routes  # noqa: E402
from manyfaced.handlers.routes.routes_nginx_probe import ROUTES as _nginx_probe_routes  # noqa: E402
from manyfaced.handlers.routes.routes_k8s import ROUTES as _k8s_routes  # noqa: E402
from manyfaced.handlers.routes.routes_nextjs import ROUTES as _nextjs_routes  # noqa: E402
from manyfaced.handlers.routes.routes_atlassian import ROUTES as _atlassian_routes  # noqa: E402
from manyfaced.handlers.routes.routes_spring import ROUTES as _spring_routes  # noqa: E402
from manyfaced.handlers.routes.routes_aws_creds import ROUTES as _aws_creds_routes  # noqa: E402
from manyfaced.handlers.routes.routes_hnap import ROUTES as _hnap_routes  # noqa: E402
from manyfaced.handlers.routes.routes_squid import ROUTES as _squid_routes  # noqa: E402
from manyfaced.handlers.routes.routes_magento import ROUTES as _magento_routes  # noqa: E402
from manyfaced.handlers.routes.routes_redis_admin import ROUTES as _redis_admin_routes  # noqa: E402
from manyfaced.handlers.routes.routes_solr import ROUTES as _solr_routes  # noqa: E402
from manyfaced.handlers.routes.routes_grafana import ROUTES as _grafana_routes  # noqa: E402
from manyfaced.handlers.routes.routes_plex import ROUTES as _plex_routes  # noqa: E402
from manyfaced.handlers.routes.routes_jupyter import ROUTES as _jupyter_routes  # noqa: E402
from manyfaced.handlers.routes.routes_rabbitmq import ROUTES as _rabbitmq_routes  # noqa: E402
from manyfaced.handlers.routes.routes_gitlab import ROUTES as _gitlab_routes  # noqa: E402
from manyfaced.handlers.routes.routes_elasticsearch import ROUTES as _elasticsearch_routes  # noqa: E402
from manyfaced.handlers.routes.routes_zabbix import ROUTES as _zabbix_routes  # noqa: E402
from manyfaced.handlers.routes.routes_laravel import ROUTES as _laravel_routes  # noqa: E402
from manyfaced.handlers.routes.routes_thinkphp import ROUTES as _thinkphp_routes  # noqa: E402
from manyfaced.handlers.routes.routes_elastic import ROUTES as _elastic_routes  # noqa: E402
from manyfaced.handlers.routes.routes_env_disc import ROUTES as _env_disc_routes  # noqa: E402
from manyfaced.handlers.routes.routes_nginx import ROUTES as _nginx_routes  # noqa: E402
from manyfaced.handlers.routes.routes_phpunit import ROUTES as _phpunit_routes  # noqa: E402

# Concatenate in the original order: WordPress → phpMyAdmin → Jenkins → Tomcat →
# Drupal → cPanel → Bitrix → WebDAV → ConfigDisclosure → catch-all
ROUTES: list[Route] = (
    list(_wordpress_routes)
    + list(_phpmyadmin_routes)
    + list(_jenkins_routes)
    + list(_tomcat_routes)
    + list(_drupal_routes)
    + list(_cpanel_routes)
    + list(_bitrix_routes)
    + list(_webdav_routes)
    + list(_config_disclosure_routes)
    + list(_dbadmin_routes)
    + list(_docker_routes)
    + list(_mcp_routes)
    + list(_iot_routes)
    + list(_nginx_probe_routes)
    + list(_k8s_routes)
    + list(_nextjs_routes)
    + list(_atlassian_routes)
    + list(_spring_routes)
    + list(_aws_creds_routes)
    + list(_hnap_routes)
    + list(_squid_routes)
    + list(_magento_routes)
    + list(_redis_admin_routes)
    + list(_solr_routes)
    + list(_grafana_routes)
    + list(_plex_routes)
    + list(_jupyter_routes)
    + list(_rabbitmq_routes)
    + list(_gitlab_routes)
    + list(_elasticsearch_routes)
    + list(_zabbix_routes)
    + list(_laravel_routes)
    + list(_thinkphp_routes)
    + list(_elastic_routes)
    + list(_env_disc_routes)
    + list(_nginx_routes)
    + list(_phpunit_routes)
    + [Route(Any(), _generic(), 4294967294, 'catchall_monster_page')]
)

# ---------------------------------------------------------------------------
# Router singleton
# ---------------------------------------------------------------------------

router = Router(ROUTES)
