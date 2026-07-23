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
from manyfaced.common import status as _status

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
from manyfaced.handlers.routes.routes_exploit_cgi import ROUTES as _exploit_cgi_routes  # noqa: E402
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
from manyfaced.handlers.routes.routes_nginx import ROUTES as _nginx_routes
from manyfaced.handlers.routes.routes_phpunit import ROUTES as _phpunit_routes
from manyfaced.handlers.routes.routes_splunk import ROUTES as _splunk_routes
from manyfaced.handlers.routes.routes_sharepoint import ROUTES as _sharepoint_routes
from manyfaced.handlers.routes.routes_citrix import ROUTES as _citrix_routes
from manyfaced.handlers.routes.routes_fortinet import ROUTES as _fortinet_routes
from manyfaced.handlers.routes.routes_coldfusion import ROUTES as _coldfusion_routes
from manyfaced.handlers.routes.routes_langflow import ROUTES as _langflow_routes
from manyfaced.handlers.routes.routes_joomla import ROUTES as _joomla_routes
from manyfaced.handlers.fingerprint import HighEntropyPath, NotFoundHandler  # noqa: E402

# Dispatch policy (issue #503 / #453 / #519): exploit-specific faces are
# concatenated BEFORE the broad web-root framework faces (Drupal, WordPress,
# Laravel, Kubernetes, Docker, Elastic, ThinkPHP) so a greedy framework prefix
# (Drupal's old /admin/, Kubernetes' old /api/, Elastic's old /_) can NOT shadow
# the dedicated exploit handlers for nested probes like:
#   /cgi-bin/*            -> ExploitCgiHandler   (was Drupal, issue #505)
#   /admin/vendor/phpunit/-> PhpUnitHandler     (was Drupal, issue #506)
#   /admin/.env           -> EnvDiscHandler      (was Drupal, issue #508)
#   /api/vendor/phpunit/ -> PhpUnitHandler     (was Kubernetes, issue #453)
#   /api/route            -> NextjsHandler       (was Kubernetes, issue #453)
#   /api/datasources      -> GrafanaHandler      (was Kubernetes, issue #453)
#   /_next                -> NextjsHandler        (was Elastic, issue #519)
#   /laravel/vendor/...   -> PhpUnitHandler     (was Laravel, issue #519)
# Order within the exploit block is also significant for the /api/ namespace:
# phpunit (specific /api/vendor/phpunit/) -> grafana (specific API
# sub-namespaces) -> env_disc (specific secret sub-paths) -> nextjs (broad
# /api/ server actions) so each face wins its own /api/* subtree.
# NOTE: ConfigDisclosure is intentionally kept in its ORIGINAL position (after
# WebDAV, before DBAdmin) — NOT moved to the front. If it were placed before
# WordPress/phpMyAdmin it would steal /xmlrpc.php and /mysql/; and because
# EnvDisc owns the bare PathExact('/.env') route in front of ConfigDisclosure,
# bare /.env would wrongly hit EnvDisc instead of ConfigDisclosure (issue #508).
# The greedy framework prefixes were REMOVED/NARROWED in their route tables
# (see routes_drupal/kubernetes/elastic) so the exploit faces below win.
ROUTES: list[Route] = (
    # ---- Exploit faces FIRST (win over removed greedy framework prefixes) ----
    list(_exploit_cgi_routes)
    + list(_phpunit_routes)
    + list(_grafana_routes)
    + list(_env_disc_routes)
    # Langflow owns its specific /api/v1/* endpoints (run/flows/validate/
    # upload) and must be listed BEFORE the k8s /api/v1/ prefix below so its
    # exact routes win over k8s for those paths (issue #592).
    + list(_langflow_routes)
    # Kubernetes core API (/api/v1/* and /apis/*) must win over the generic
    # Next.js /api/ prefix (issue #592). Listed BEFORE _nextjs_routes so the
    # dedicated kube-apiserver face is not reverse-shadowed (it used to sit
    # after Next.js at the bottom of the table).
    + list(_k8s_routes)
    # RabbitMQ management UI/API (issue #643): must win over the generic
    # Next.js /api/ prefix and the Solr/Grafana/Elastic tables for shared
    # paths (/api/*, /cli, /login, bare root) so 15672 probes classify as
    # RABBITMQ_HTTP instead of falling through to a sibling face.
    + list(_rabbitmq_routes)
    + list(_nextjs_routes)
    # ---- Broad web-root framework / service faces ----
    + list(_wordpress_routes)
    + list(_phpmyadmin_routes)
    + list(_jenkins_routes)
    + list(_tomcat_routes)
    + list(_drupal_routes)
    + list(_cpanel_routes)
    + list(_bitrix_routes)
    + list(_webdav_routes)
    # ConfigDisclosure stays in its original slot (after WebDAV) so it owns the
    # bare /.env probe (issue #508) without stealing WordPress/phpMyAdmin paths.
    + list(_config_disclosure_routes)
    + list(_dbadmin_routes)
    + list(_docker_routes)
    + list(_mcp_routes)
    + list(_iot_routes)
    + list(_nginx_probe_routes)
    + list(_atlassian_routes)
    + list(_spring_routes)
    + list(_aws_creds_routes)
    + list(_hnap_routes)
    + list(_squid_routes)
    + list(_magento_routes)
    + list(_redis_admin_routes)
    + list(_solr_routes)
    + list(_plex_routes)
    + list(_jupyter_routes)
    + list(_gitlab_routes)
    + list(_elasticsearch_routes)
    + list(_zabbix_routes)
    + list(_laravel_routes)
    + list(_thinkphp_routes)
    + list(_elastic_routes)
    + list(_nginx_routes)
    # New threat-intel faces (issues #391-#397): Joomla, Langflow, ColdFusion,
    # Fortinet, Citrix, SharePoint, Splunk. Concatenated last (before the
    # fingerprint-deflection + monster-page catch-all) so they coexist with the
    # existing framework handlers without shadowing them.
    + list(_joomla_routes)
    + list(_coldfusion_routes)
    + list(_fortinet_routes)
    + list(_citrix_routes)
    + list(_sharepoint_routes)
    + list(_splunk_routes)
    # Fingerprint-deflection layer (issue #324): high-entropy random paths and
    # a missing /favicon.ico get a realistic Apache 404 *before* the monster-page
    # catch-all, so we don't answer-everything-with-200 (a classic honeypot tell).
    + [Route(HighEntropyPath(), NotFoundHandler, _status.FINGERPRINT_PROBE, 'fingerprint_404')]
    + [Route(PathExact('/favicon.ico'), NotFoundHandler, _status.FINGERPRINT_PROBE, 'favicon_404')]
    + [Route(Any(), _generic(), 4294967294, 'catchall_monster_page')]
)

# ---------------------------------------------------------------------------
# Router singleton
# ---------------------------------------------------------------------------

router = Router(ROUTES)
