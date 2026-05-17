"""Bitrix (1C-Bitrix CMS) routes."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route


def _bitrix() -> type:
    from manyfaced.handlers.bitrix_handler import BitrixHandler

    return BitrixHandler


ROUTES: list[Route] = [
    # ---- Bitrix (1C-Bitrix CMS) --------------------------------------------------
    Route(PathExact('/bitrix/admin'), _bitrix(), 1, 'bitrix_admin'),
    Route(PathPrefix('/bitrix/admin/'), _bitrix(), 1, 'bitrix_admin_slash'),
    Route(PathPrefix('/bitrix/auth/'), _bitrix(), 1, 'bitrix_auth'),
    Route(PathExact('/bitrix/auth'), _bitrix(), 1, 'bitrix_auth_exact'),
    Route(PathPrefix('/bitrix/setup/'), _bitrix(), 1, 'bitrix_setup'),
    Route(PathPrefix('/bitrix/tools/'), _bitrix(), 1, 'bitrix_tools'),
    Route(PathExact('/bitrix'), _bitrix(), 1, 'bitrix_bitrix'),
    Route(PathPrefix('/bitrix/'), _bitrix(), 1, 'bitrix_slash'),
]
