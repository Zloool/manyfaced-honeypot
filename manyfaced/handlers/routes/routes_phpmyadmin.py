"""phpMyAdmin routes — canonical DB admin endpoints.

Covers the real-world probe paths that scanners hit when hunting for an
exposed phpMyAdmin instance:

    /phpmyadmin  /phpMyAdmin  /pma  /index.php  /phpmyadmin/index.php
    /sql.php  /phpmyadmin/%2eenv  (/mysql, /db, /database legacy aliases)

The %2e -> '.' and %2f -> '/' decoding is done inside the handler (paths are
URL-encoded by probes), so the routes here match the literal request paths.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import PHPMYADMIN_HTTP


def _phpmyadmin() -> type:
    from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler

    return PhpMyAdminHandler


ROUTES: list[Route] = [
    # ---- phpMyAdmin (canonical DB admin endpoints) -------------------------
    Route(PathExact('/phpmyadmin'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_phpmyadmin'),
    Route(PathExact('/phpMyAdmin'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_phpMyAdmin'),
    Route(PathExact('/pma'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_pma'),
    Route(PathExact('/index.php'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_index_php'),
    Route(PathPrefix('/phpmyadmin/'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_phpmyadmin_slash'),
    Route(PathPrefix('/pma/'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_pma_slash'),
    # Legacy aliases (kept so the ConfigDisclosure /mysql overlap tests stay green).
    # /mysql — phpMyAdmin wins (overlap: ConfigDisclosure also claims it).
    Route(PathExact('/mysql'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_mysql'),
    Route(PathPrefix('/mysql/'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_mysql_slash'),
    Route(PathExact('/mysql/index.php'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_mysql_index_php'),
    Route(PathExact('/db'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_db'),
    Route(PathPrefix('/db/'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_db_slash'),
    Route(PathExact('/db/index.php'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_db_index_php'),
    Route(PathExact('/database'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_database'),
    Route(PathPrefix('/database/'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_database_slash'),
    Route(PathExact('/database/index.php'), _phpmyadmin(), PHPMYADMIN_HTTP, 'phpmyadmin_database_index_php'),
]
