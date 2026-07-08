"""IoT Router routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import IOT_HTTP


def _iot() -> type:
    from manyfaced.handlers.iot_handler import IoTHandler

    return IoTHandler


ROUTES: list[Route] = [
    # ---- IoT Router (issue #284) ----
    Route(PathExact('/boaform/admin/formlogin'), _iot(), IOT_HTTP, 'iot_0'),
    Route(PathPrefix('/boaform/admin/formlogin/'), _iot(), IOT_HTTP, 'iot_prefix_0'),
    Route(PathExact('/apply.cgi'), _iot(), IOT_HTTP, 'iot_1'),
    Route(PathExact('/cgi-bin'), _iot(), IOT_HTTP, 'iot_2'),
    Route(PathExact('/getcfg.php'), _iot(), IOT_HTTP, 'iot_3'),
]
