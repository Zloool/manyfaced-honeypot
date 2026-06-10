"""Tomcat routes — Apache Tomcat endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import TOMCAT_HTTP


def _tomcat() -> type:
    from manyfaced.handlers.tomcat_handler import TomcatHandler

    return TomcatHandler


ROUTES: list[Route] = [
    # ---- Tomcat --------------------------------------------------------------
    Route(PathExact('/manager'), _tomcat(), TOMCAT_HTTP, 'tomcat_manager'),
    Route(PathPrefix('/manager/'), _tomcat(), TOMCAT_HTTP, 'tomcat_manager_slash'),
    Route(PathExact('/manager/html'), _tomcat(), TOMCAT_HTTP, 'tomcat_manager_html'),
    Route(PathExact('/host-manager'), _tomcat(), TOMCAT_HTTP, 'tomcat_host_manager'),
    Route(PathPrefix('/host-manager/'), _tomcat(), TOMCAT_HTTP, 'tomcat_host_manager_slash'),
    Route(
        PathExact('/host-manager/html'),
        _tomcat(),
        1,
        'tomcat_host_manager_html',
    ),
    Route(PathExact('/tomcat'), _tomcat(), TOMCAT_HTTP, 'tomcat_tomcat'),
    Route(PathPrefix('/tomcat/'), _tomcat(), TOMCAT_HTTP, 'tomcat_tomcat_slash'),
    Route(PathExact('/server-status'), _tomcat(), TOMCAT_HTTP, 'tomcat_server_status'),
    Route(PathExact('/server-info'), _tomcat(), TOMCAT_HTTP, 'tomcat_server_info'),
    Route(PathExact('/jmxproxy'), _tomcat(), TOMCAT_HTTP, 'tomcat_jmx_proxy'),
    Route(PathPrefix('/jmxproxy/'), _tomcat(), TOMCAT_HTTP, 'tomcat_jmx_proxy_slash'),
    Route(PathExact('/examples'), _tomcat(), TOMCAT_HTTP, 'tomcat_examples'),
    Route(PathPrefix('/examples/'), _tomcat(), TOMCAT_HTTP, 'tomcat_examples_slash'),
    Route(PathExact('/ROOT'), _tomcat(), TOMCAT_HTTP, 'tomcat_root'),
    Route(PathPrefix('/ROOT/'), _tomcat(), TOMCAT_HTTP, 'tomcat_root_slash'),
]
