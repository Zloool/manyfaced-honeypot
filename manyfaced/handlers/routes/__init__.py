"""Explicit HTTP route table for the honeypot router.

The order of ROUTES is the dispatch policy. To change which handler wins for a
given path, reorder entries here.  Do NOT scatter routing decisions across
handler classes.

Overlap resolution (deliberate ordering):
    /xmlrpc.php       → WordPressHandler   (WordPress canonical endpoint)
    /files            → DrupalHandler      (Drupal files directory)
    /mysql            → PhpMyAdminHandler  (phpMyAdmin database admin)

ConfigDisclosure's patterns all migrate intact — they simply lose the above
three paths because higher-priority routes are listed first.
"""

from __future__ import annotations

# Router types
from manyfaced.handlers.router import Any, PathExact, PathPrefix, Route, Router

# Handler classes (imported lazily to avoid circular imports)


def _generic() -> type:
    from manyfaced.handlers.generic_handler import GenericHandler

    return GenericHandler


# ---------------------------------------------------------------------------
# Import per-service route tables and concatenate them in order
# ---------------------------------------------------------------------------

from manyfaced.handlers.routes.routes_bitrix import ROUTES as _bitrix_routes  # noqa: E402
from manyfaced.handlers.routes.routes_config_disclosure import (
    ROUTES as _config_disclosure_routes,  # noqa: E402
)
from manyfaced.handlers.routes.routes_cpanel import ROUTES as _cpanel_routes  # noqa: E402
from manyfaced.handlers.routes.routes_drupal import ROUTES as _drupal_routes  # noqa: E402
from manyfaced.handlers.routes.routes_jenkins import ROUTES as _jenkins_routes  # noqa: E402
from manyfaced.handlers.routes.routes_phpmyadmin import (
    ROUTES as _phpmyadmin_routes,  # noqa: E402
)
from manyfaced.handlers.routes.routes_tomcat import ROUTES as _tomcat_routes  # noqa: E402
from manyfaced.handlers.routes.routes_webdav import ROUTES as _webdav_routes  # noqa: E402
from manyfaced.handlers.routes.routes_wordpress import ROUTES as _wordpress_routes  # noqa: E402

# Concatenate in the original order: WordPress → phpMyAdmin → Jenkins → Tomcat →
# Drupal → cPanel → Bitrix → WebDAV → ConfigDisclosure → catch-all
ROUTES: list[Route] = (
    list(_wordpress_routes)
    + list(_phpmyadmin_routes)
    + list(_jenkins_routes)
    + list(_tomcat_routes)
    + list(_drupal_routes)
    + list(_cpanel_routes)
    + list(_bitrix_routes)
    + list(_webdav_routes)
    + list(_config_disclosure_routes)
    + [Route(Any(), _generic(), 4294967294, 'catchall_monster_page')]
)

# ---------------------------------------------------------------------------
# Router singleton
# ---------------------------------------------------------------------------

router = Router(ROUTES)
