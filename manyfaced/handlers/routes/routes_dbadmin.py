"""DB admin (Adminer / phpMyAdmin / SQL Buddy / myAdmin) routes.

Mirrors routes_bitrix.py. Covers the production probe paths from issue #292.
Encoded variants (e.g. /db/%2eenv) are decoded inside the handler, so the
PathPrefix('/db/') entry also captures the .env disclosure probe.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import DBADMIN_HTTP


def _dbadmin() -> type:
    from manyfaced.handlers.dbadmin_handler import DBAdminHandler

    return DBAdminHandler


ROUTES: list[Route] = [
    # ---- DB admin (issue #292) -------------------------------------------------
    Route(PathExact('/adminer'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_adminer'),
    Route(PathExact('/adminer.php'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_adminer_php'),
    Route(PathExact('/sqlbuddy'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_sqlbuddy'),
    Route(PathExact('/myadmin'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_myadmin'),
    Route(PathExact('/phpmyadmin'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_phpmyadmin'),
    Route(PathExact('/dbadmin'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_dbadmin'),
    Route(PathPrefix('/dbadmin/'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_dbadmin_slash'),
    Route(PathPrefix('/db/'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_db_slash'),
    # Encoded .env disclosure probe (decoded by the handler to /db/.env).
    Route(PathExact('/db/%2eenv'), _dbadmin(), DBADMIN_HTTP, 'dbadmin_env_encoded'),
]
