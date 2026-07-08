"""IoT / generic router web admin routes (issue #284).

Mirrors the production probe paths described in the issue. URL-encoded dot/slash
sequences (e.g. ``/IoT/%2eenv``) are normalised by the handler before dispatch,
so the PathPrefix('/IoT/') route captures them cleanly.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import IOT_HTTP


def _iot() -> type:
    from manyfaced.handlers.iot_handler import IoTHandler

    return IoTHandler


ROUTES: list[Route] = [
    # ---- IoT / generic router web admin (issue #284) --------------------
    Route(PathExact('/admin'), _iot(), IOT_HTTP, 'iot_admin'),
    Route(PathExact('/login'), _iot(), IOT_HTTP, 'iot_login'),
    Route(PathExact('/index.html'), _iot(), IOT_HTTP, 'iot_index_html'),
    Route(PathPrefix('/cgi-bin/'), _iot(), IOT_HTTP, 'iot_cgi_bin'),
    Route(PathPrefix('/upnp/'), _iot(), IOT_HTTP, 'iot_upnp'),
    Route(PathPrefix('/IoT/'), _iot(), IOT_HTTP, 'iot_env'),
]
