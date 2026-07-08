"""Nginx (web server) routes (issue #294)."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

# Issue #294 specifies NGINX_HTTP (value 1029). The shared status.py defines
# NGINX_PROBE_HTTP = 1029 as the canonical Nginx face ID; alias it here.
from manyfaced.common.status import NGINX_PROBE_HTTP as NGINX_HTTP


def _nginx() -> type:
    from manyfaced.handlers.nginx_handler import NginxHandler

    return NginxHandler


ROUTES: list[Route] = [
    # ---- Nginx (web server / issue #294) -----------------------------------
    Route(PathExact('/index.html'), _nginx(), NGINX_HTTP, 'nginx_index'),
    Route(PathExact('/nginx_status'), _nginx(), NGINX_HTTP, 'nginx_status'),
    Route(PathExact('/server-status'), _nginx(), NGINX_HTTP, 'nginx_server_status'),
    Route(PathPrefix('/api/'), _nginx(), NGINX_HTTP, 'nginx_api'),
    Route(PathPrefix('/nginx/'), _nginx(), NGINX_HTTP, 'nginx_probe'),
]
