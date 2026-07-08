"""Confluence routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ATLASSIAN_HTTP


def _atlassian() -> type:
    from manyfaced.handlers.atlassian_handler import AtlassianHandler

    return AtlassianHandler


ROUTES: list[Route] = [
    # ---- Confluence (issue #280) ----
    Route(PathExact('/wiki'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_0'),
    Route(PathExact('/login.action'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_1'),
    Route(PathExact('/setup.action'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_2'),
    Route(PathExact('/rest/api'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_3'),
    Route(PathPrefix('/rest/api/'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_prefix_3'),
]
