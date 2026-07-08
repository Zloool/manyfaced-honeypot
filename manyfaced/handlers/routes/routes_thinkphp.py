"""ThinkPHP (issue #287) routes.

Mirrors the production probe paths used against ThinkPHP deployments. The
router strips the query string and lower-cases the path before matching, so
the ``?s=/index/think\app/invokefunction&...`` RCE probes match the exact
``/index.php`` / ``/public/index.php`` entry scripts.

Order matters (first match wins): exact entry-script hits first, then
prefixed catch-alls for the same entry scripts, then a general /thinkphp
namespace catch.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import THINKPHP_HTTP


def _thinkphp() -> type:
    from manyfaced.handlers.thinkphp_handler import ThinkPHPHandler

    return ThinkPHPHandler


ROUTES: list[Route] = [
    # ---- ThinkPHP (issue #287) ---------------------------------------------
    # Exact entry scripts — these catch the ?s=/index/think\app/invokefunction
    # RCE chains (query string is stripped by the router before matching).
    Route(PathExact('/index.php'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_index_php'),
    Route(PathExact('/public/index.php'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_public_index_php'),
    # Prefixed catch-alls for anything under the entry scripts.
    Route(PathPrefix('/index.php'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_index_php_prefix'),
    Route(PathPrefix('/public/index.php'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_public_index_php_prefix'),
    # General framework namespace catch.
    Route(PathPrefix('/thinkphp'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_namespace'),
]
