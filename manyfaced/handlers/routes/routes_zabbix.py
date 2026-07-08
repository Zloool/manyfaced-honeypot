"""Zabbix (issue #282) routes — frontend sign-in, about page, JSON-RPC API.

Mirrors the Bitrix route table. Covers the production probe paths:
    /zc?action=getinfo      -> Zabbix "zc" info endpoint
    /evox/about             -> EVOX/Zabbix "about" page
    /zabbix/favicon.ico     -> static asset (prefix match)
    /zabbix.php             -> Zabbix frontend sign-in page
    /api_jsonrpc.php        -> Zabbix JSON-RPC API
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ZABBIX_HTTP


def _zabbix() -> type:
    from manyfaced.handlers.zabbix_handler import ZabbixHandler

    return ZabbixHandler


ROUTES: list[Route] = [
    # ---- Zabbix frontend / JSON-RPC (issue #282) ---------------------------
    Route(PathExact('/zc'), _zabbix(), ZABBIX_HTTP, 'zabbix_zc'),
    Route(PathExact('/zabbix.php'), _zabbix(), ZABBIX_HTTP, 'zabbix_php'),
    Route(PathExact('/api_jsonrpc.php'), _zabbix(), ZABBIX_HTTP, 'zabbix_api'),
    Route(PathExact('/evox/about'), _zabbix(), ZABBIX_HTTP, 'zabbix_evox_about'),
    Route(PathPrefix('/zabbix/'), _zabbix(), ZABBIX_HTTP, 'zabbix_assets'),
]
