"""Adminer routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import DBADMIN_HTTP


def _dbadmin() -> type:
    from manyfaced.handlers.dbadmin_handler import DBAdminHandler

    return DBAdminHandler


ROUTES: list[Route] = [
    # ---- Adminer (issue #292) ----
    Route(PathExact('/adminer'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_0'),
    Route(PathExact('/sqlbuddy'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_1'),
    Route(PathExact('/dbadmin'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_2'),
    Route(PathExact('/myadmin'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_3'),
    Route(PathExact('/adminer.php'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_4'),
]
