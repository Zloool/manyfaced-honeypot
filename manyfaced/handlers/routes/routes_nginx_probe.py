"""Nginx routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, Route

from manyfaced.common.status import NGINX_PROBE_HTTP


def _nginx_probe() -> type:
    from manyfaced.handlers.nginx_probe_handler import NginxProbeHandler

    return NginxProbeHandler


ROUTES: list[Route] = [
    # ---- Nginx (issue #294) ----
    Route(PathExact('/nginx_status'), _nginx_probe(), NGINX_PROBE_HTTP, 'nginx_probe_0'),
    Route(PathExact('/server-status'), _nginx_probe(), NGINX_PROBE_HTTP, 'nginx_probe_1'),
    Route(PathExact('/stub_status'), _nginx_probe(), NGINX_PROBE_HTTP, 'nginx_probe_2'),
    Route(PathExact('/status'), _nginx_probe(), NGINX_PROBE_HTTP, 'nginx_probe_3'),
]
