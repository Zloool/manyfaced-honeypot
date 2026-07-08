"""Laravel routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import LARAVEL_HTTP


def _laravel() -> type:
    from manyfaced.handlers.laravel_handler import LaravelHandler

    return LaravelHandler


ROUTES: list[Route] = [
    # ---- Laravel (issue #286) ----
    Route(PathExact('/laravel'), _laravel(), LARAVEL_HTTP, 'laravel_0'),
    Route(PathExact('/_ignition'), _laravel(), LARAVEL_HTTP, 'laravel_1'),
    Route(PathExact('/storage/logs/laravel.log'), _laravel(), LARAVEL_HTTP, 'laravel_2'),
    Route(PathExact('/vendor/laravel'), _laravel(), LARAVEL_HTTP, 'laravel_3'),
    Route(PathPrefix('/vendor/laravel/'), _laravel(), LARAVEL_HTTP, 'laravel_prefix_3'),
]
