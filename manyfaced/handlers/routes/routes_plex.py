"""Plex routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import PLEX_HTTP


def _plex() -> type:
    from manyfaced.handlers.plex_handler import PlexHandler

    return PlexHandler


ROUTES: list[Route] = [
    # ---- Plex (issue #295) ----
    Route(PathExact('/web/index.html'), _plex(), PLEX_HTTP, 'plex_0'),
    Route(PathExact('/status/sessions'), _plex(), PLEX_HTTP, 'plex_1'),
    Route(PathPrefix('/status/sessions/'), _plex(), PLEX_HTTP, 'plex_prefix_1'),
    Route(PathExact('/identity'), _plex(), PLEX_HTTP, 'plex_2'),
    Route(PathExact('/plex'), _plex(), PLEX_HTTP, 'plex_3'),
]
