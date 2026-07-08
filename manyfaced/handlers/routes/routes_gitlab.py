"""GitLab routes (issue #283).

Mirrors the production GitLab probe paths. Specific (exact) paths are listed
first so they win over the broad prefixes; %2e/%2f are decoded by the caller
before dispatch, so the /gitlab/ prefix catches /gitlab/%2eenv probes.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import GITLAB_HTTP


def _gitlab() -> type:
    from manyfaced.handlers.gitlab_handler import GitLabHandler

    return GitLabHandler


ROUTES: list[Route] = [
    # ---- GitLab (issue #283) ----
    # Specific paths first (exact match wins over prefixes).
    Route(PathExact('/users/sign_in'), _gitlab(), GITLAB_HTTP, 'gitlab_sign_in'),
    Route(PathExact('/api/v4/version'), _gitlab(), GITLAB_HTTP, 'gitlab_api_version'),
    Route(PathExact('/-/metrics'), _gitlab(), GITLAB_HTTP, 'gitlab_metrics'),
    Route(PathExact('/admin'), _gitlab(), GITLAB_HTTP, 'gitlab_admin'),
    # Prefixes next (broad coverage).
    Route(PathPrefix('/api/v4/'), _gitlab(), GITLAB_HTTP, 'gitlab_api'),
    Route(PathPrefix('/-/'), _gitlab(), GITLAB_HTTP, 'gitlab_dash'),
    Route(PathPrefix('/gitlab/'), _gitlab(), GITLAB_HTTP, 'gitlab_gitlab'),
    Route(PathPrefix('/explore'), _gitlab(), GITLAB_HTTP, 'gitlab_explore'),
    Route(PathPrefix('/assets/'), _gitlab(), GITLAB_HTTP, 'gitlab_assets'),
]
