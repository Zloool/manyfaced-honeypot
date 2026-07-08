"""GitLab routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import GITLAB_HTTP


def _gitlab() -> type:
    from manyfaced.handlers.gitlab_handler import GitLabHandler

    return GitLabHandler


ROUTES: list[Route] = [
    # ---- GitLab (issue #276) ----
    Route(PathExact('/sdk/weblanguage'), _gitlab(), GITLAB_HTTP, 'gitlab_0'),
    Route(PathPrefix('/sdk/weblanguage/'), _gitlab(), GITLAB_HTTP, 'gitlab_prefix_0'),
    Route(PathExact('/users/sign_in'), _gitlab(), GITLAB_HTTP, 'gitlab_1'),
    Route(PathPrefix('/users/sign_in/'), _gitlab(), GITLAB_HTTP, 'gitlab_prefix_1'),
    Route(PathExact('/api/v4'), _gitlab(), GITLAB_HTTP, 'gitlab_2'),
    Route(PathPrefix('/api/v4/'), _gitlab(), GITLAB_HTTP, 'gitlab_prefix_2'),
    Route(PathExact('/explore'), _gitlab(), GITLAB_HTTP, 'gitlab_3'),
]
