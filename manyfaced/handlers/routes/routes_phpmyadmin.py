"""phpMyAdmin routes — canonical DB admin endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import PHPMYADMIN_HTTP


def _pma() -> type:
    from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler

    return PhpMyAdminHandler


ROUTES: list[Route] = [
    # ---- phpMyAdmin (canonical DB admin endpoints) ---------------------------
    Route(PathExact('/phpmyadmin'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_phpmyadmin'),
    Route(PathPrefix('/phpmyadmin/'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_phpmyadmin_slash'),
    Route(
        PathExact('/phpmyadmin/index.php'),
        _pma(),
        1,
        'phpmyadmin_index_php',
    ),
    Route(PathExact('/pma'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_pma'),
    Route(PathPrefix('/pma/'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_pma_slash'),
    Route(PathExact('/pma/index.php'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_pma_index_php'),
    # /mysql — phpMyAdmin wins (overlap: ConfigDisclosure also claims it)
    Route(PathExact('/mysql'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_mysql'),
    Route(PathPrefix('/mysql/'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_mysql_slash'),
    Route(PathExact('/mysql/index.php'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_mysql_index_php'),
    Route(PathExact('/db'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_db'),
    Route(PathPrefix('/db/'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_db_slash'),
    Route(PathExact('/db/index.php'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_db_index_php'),
    Route(PathExact('/database'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_database'),
    Route(PathPrefix('/database/'), _pma(), PHPMYADMIN_HTTP, 'phpmyadmin_database_slash'),
    Route(
        PathExact('/database/index.php'),
        _pma(),
        1,
        'phpmyadmin_database_index_php',
    ),
]
