"""Plex Media Server routes (issue #284)."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import PLEX_HTTP


def _plex() -> type:
    from manyfaced.handlers.plex_handler import PlexHandler

    return PlexHandler


ROUTES: list[Route] = [
    # ---- Plex (issue #284) --------------------------------------------------
    Route(PathExact('/web'), _plex(), PLEX_HTTP, 'plex_web'),
    Route(PathExact('/:32400/web'), _plex(), PLEX_HTTP, 'plex_32400_web'),
    Route(PathExact('/identity'), _plex(), PLEX_HTTP, 'plex_identity'),
    Route(PathExact('/status/sessions'), _plex(), PLEX_HTTP, 'plex_status_sessions'),
    Route(PathPrefix('/myplex/'), _plex(), PLEX_HTTP, 'plex_myplex'),
    Route(PathPrefix('/library/'), _plex(), PLEX_HTTP, 'plex_library'),
    Route(PathPrefix('/plex/'), _plex(), PLEX_HTTP, 'plex_env'),
]
