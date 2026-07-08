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
    Route(PathPrefix('/api/'), _grafana(), GRAFANA_HTTP, 'grafana_api_prefix'),
    Route(PathPrefix('/grafana/'), _grafana(), GRAFANA_HTTP, 'grafana_prefix'),
]
