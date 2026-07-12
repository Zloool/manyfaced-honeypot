"""Grafana (observability platform) routes.

Routes mirror the production probe paths from issue #289:
  /grafana  /login  /api/org  /api/dashboards/home  /api/frontend/settings
  /api/search  /grafana/login  /api/%2e%2e
URL-encoded path segments (%2e -> '.', %2f -> '/') are decoded by the handler
before matching, so the catch-all PathPrefix('/api/') and PathPrefix('/grafana/')
routes cover the encoded traversal probes.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import GRAFANA_HTTP


def _grafana() -> type:
    from manyfaced.handlers.grafana_handler import GrafanaHandler

    return GrafanaHandler


ROUTES: list[Route] = [
    # ---- Grafana (issue #289) ----------------------------------------------
    Route(PathExact('/grafana'), _grafana(), GRAFANA_HTTP, 'grafana_root'),
    Route(PathExact('/login'), _grafana(), GRAFANA_HTTP, 'grafana_login'),
    Route(PathExact('/grafana/login'), _grafana(), GRAFANA_HTTP, 'grafana_login_nested'),
    Route(PathExact('/api/org'), _grafana(), GRAFANA_HTTP, 'grafana_api_org'),
    # Specific Grafana REST sub-namespaces only — the previous bare
    # `PathPrefix('/api/')` shadowed Next.js server-action RCE (/api/route),
    # PHPUnit eval-stdin (/api/vendor/phpunit/...) and env-disclosure
    # (/api/.env) probes (issue #453). Enumerating Grafana's real API
    # surface lets those dedicated faces win for their own subtrees.
    Route(PathPrefix('/api/datasources'), _grafana(), GRAFANA_HTTP, 'grafana_api_datasources'),
    Route(PathPrefix('/api/search'), _grafana(), GRAFANA_HTTP, 'grafana_api_search'),
    Route(PathPrefix('/api/frontend'), _grafana(), GRAFANA_HTTP, 'grafana_api_frontend'),
    Route(PathPrefix('/api/users'), _grafana(), GRAFANA_HTTP, 'grafana_api_users'),
    Route(PathPrefix('/api/alerts'), _grafana(), GRAFANA_HTTP, 'grafana_api_alerts'),
    Route(PathPrefix('/api/annotations'), _grafana(), GRAFANA_HTTP, 'grafana_api_annotations'),
    Route(PathPrefix('/api/admin'), _grafana(), GRAFANA_HTTP, 'grafana_api_admin'),
    Route(PathPrefix('/api/login'), _grafana(), GRAFANA_HTTP, 'grafana_api_login'),
    Route(PathPrefix('/api/auth'), _grafana(), GRAFANA_HTTP, 'grafana_api_auth'),
    Route(PathPrefix('/api/dashboards'), _grafana(), GRAFANA_HTTP, 'grafana_api_dashboards'),
    Route(PathPrefix('/api/teams'), _grafana(), GRAFANA_HTTP, 'grafana_api_teams'),
    Route(PathPrefix('/api/folders'), _grafana(), GRAFANA_HTTP, 'grafana_api_folders'),
    Route(PathPrefix('/api/plugins'), _grafana(), GRAFANA_HTTP, 'grafana_api_plugins'),
    Route(PathPrefix('/api/prometheus'), _grafana(), GRAFANA_HTTP, 'grafana_api_prometheus'),
    Route(PathPrefix('/api/alertmanager'), _grafana(), GRAFANA_HTTP, 'grafana_api_alertmanager'),
    Route(PathPrefix('/grafana/'), _grafana(), GRAFANA_HTTP, 'grafana_prefix'),
]
