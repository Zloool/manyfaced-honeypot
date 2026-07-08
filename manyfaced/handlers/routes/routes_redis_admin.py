"""Redis Admin routes (issue #297).

Mirrors the bitrix route layout. Covers real production probe paths for
redis-commander / redis-insight web-admin consoles:

    /redis-commander      -> UI landing page
    /redis-insight        -> UI landing page
    /api/redis            -> JSON API
    /api/config           -> JSON config endpoint
    /redis/%2eenv         -> path traversal / config probe (decoded in handler)
    /admin/redis          -> admin console
    /config               -> config probe
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import REDIS_ADMIN_HTTP


def _redis_admin() -> type:
    from manyfaced.handlers.redis_admin_handler import RedisAdminHandler

    return RedisAdminHandler


ROUTES: list[Route] = [
    # ---- Redis Admin (issue #297) ------------------------------------------
    Route(PathExact('/redis-commander'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_commander'),
    Route(PathExact('/redis-insight'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_insight'),
    Route(PathExact('/api/config'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_api_config'),
    Route(PathPrefix('/api/'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_api'),
    Route(PathPrefix('/admin/'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_admin'),
    Route(PathPrefix('/redis/'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_redis'),
]
