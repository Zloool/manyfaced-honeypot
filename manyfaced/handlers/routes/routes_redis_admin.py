"""Redis Admin routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import REDIS_ADMIN_HTTP


def _redis_admin() -> type:
    from manyfaced.handlers.redis_admin_handler import RedisAdminHandler

    return RedisAdminHandler


ROUTES: list[Route] = [
    # ---- Redis Admin (issue #297) ----
    Route(PathExact('/redis-admin'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_0'),
    Route(PathExact('/redis-commander'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_1'),
    Route(PathExact('/redis'), _redis_admin(), REDIS_ADMIN_HTTP, 'redis_admin_2'),
]
