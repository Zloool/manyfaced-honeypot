"""ThinkPHP routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import THINKPHP_HTTP


def _thinkphp() -> type:
    from manyfaced.handlers.thinkphp_handler import ThinkPHPHandler

    return ThinkPHPHandler


ROUTES: list[Route] = [
    # ---- ThinkPHP (issue #287) ----
    Route(PathExact('/index.php'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_0'),
    Route(PathExact('/public/index.php'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_1'),
    Route(PathExact('/thinkphp'), _thinkphp(), THINKPHP_HTTP, 'thinkphp_2'),
]
