"""phpMyAdmin routes — canonical DB admin endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route


def _pma() -> type:
    from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler

    return PhpMyAdminHandler


ROUTES: list[Route] = [
    # ---- phpMyAdmin (canonical DB admin endpoints) ---------------------------
    Route(PathExact('/phpmyadmin'), _pma(), 1, 'phpmyadmin_phpmyadmin'),
    Route(PathPrefix('/phpmyadmin/'), _pma(), 1, 'phpmyadmin_phpmyadmin_slash'),
    Route(
        PathExact('/phpmyadmin/index.php'),
        _pma(),
        1,
        'phpmyadmin_index_php',
    ),
    Route(PathExact('/pma'), _pma(), 1, 'phpmyadmin_pma'),
    Route(PathPrefix('/pma/'), _pma(), 1, 'phpmyadmin_pma_slash'),
    Route(PathExact('/pma/index.php'), _pma(), 1, 'phpmyadmin_pma_index_php'),
    # /mysql — phpMyAdmin wins (overlap: ConfigDisclosure also claims it)
    Route(PathExact('/mysql'), _pma(), 1, 'phpmyadmin_mysql'),
    Route(PathPrefix('/mysql/'), _pma(), 1, 'phpmyadmin_mysql_slash'),
    Route(PathExact('/mysql/index.php'), _pma(), 1, 'phpmyadmin_mysql_index_php'),
    Route(PathExact('/db'), _pma(), 1, 'phpmyadmin_db'),
    Route(PathPrefix('/db/'), _pma(), 1, 'phpmyadmin_db_slash'),
    Route(PathExact('/db/index.php'), _pma(), 1, 'phpmyadmin_db_index_php'),
    Route(PathExact('/database'), _pma(), 1, 'phpmyadmin_database'),
    Route(PathPrefix('/database/'), _pma(), 1, 'phpmyadmin_database_slash'),
    Route(
        PathExact('/database/index.php'),
        _pma(),
        1,
        'phpmyadmin_database_index_php',
    ),
]
