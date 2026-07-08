"""Zabbix routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ZABBIX_HTTP


def _zabbix() -> type:
    from manyfaced.handlers.zabbix_handler import ZabbixHandler

    return ZabbixHandler


ROUTES: list[Route] = [
    # ---- Zabbix (issue #282) ----
    Route(PathExact('/zc'), _zabbix(), ZABBIX_HTTP, 'zabbix_0'),
    Route(PathExact('/evox/about'), _zabbix(), ZABBIX_HTTP, 'zabbix_1'),
    Route(PathPrefix('/evox/about/'), _zabbix(), ZABBIX_HTTP, 'zabbix_prefix_1'),
    Route(PathExact('/zabbix.php'), _zabbix(), ZABBIX_HTTP, 'zabbix_2'),
    Route(PathExact('/api_jsonrpc.php'), _zabbix(), ZABBIX_HTTP, 'zabbix_3'),
]
