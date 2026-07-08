"""Grafana routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import GRAFANA_HTTP


def _grafana() -> type:
    from manyfaced.handlers.grafana_handler import GrafanaHandler

    return GrafanaHandler


ROUTES: list[Route] = [
    # ---- Grafana (issue #291) ----
    Route(PathExact('/grafana'), _grafana(), GRAFANA_HTTP, 'grafana_0'),
    Route(PathExact('/prometheus'), _grafana(), GRAFANA_HTTP, 'grafana_1'),
    Route(PathExact('/api/datasources'), _grafana(), GRAFANA_HTTP, 'grafana_2'),
    Route(PathPrefix('/api/datasources/'), _grafana(), GRAFANA_HTTP, 'grafana_prefix_2'),
    Route(PathExact('/api/health'), _grafana(), GRAFANA_HTTP, 'grafana_3'),
    Route(PathPrefix('/api/health/'), _grafana(), GRAFANA_HTTP, 'grafana_prefix_3'),
]
