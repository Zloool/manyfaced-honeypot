"""Atlassian (Confluence / Jira) routes.

Routes mirror the production probe paths described in issue #280. Decoding of
path-escape probes (%2e -> '.', %2f -> '/') is handled inside the handler, so
the raw probe paths defined here match what bots actually send.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ATLASSIAN_HTTP


def _atlassian() -> type:
    from manyfaced.handlers.atlassian_handler import AtlassianHandler

    return AtlassianHandler


ROUTES: list[Route] = [
    # ---- Confluence / Jira (issue #280) ----------------------------------
    Route(PathExact('/login'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_login'),
    Route(PathExact('/confluence'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_confluence'),
    Route(PathExact('/wiki'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_wiki'),
    Route(PathExact('/jira'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_jira'),
    Route(PathPrefix('/rest/'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_rest'),
    Route(PathPrefix('/atlassian/'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_env'),
    Route(PathPrefix('/secure/'), _atlassian(), ATLASSIAN_HTTP, 'atlassian_secure'),
]
