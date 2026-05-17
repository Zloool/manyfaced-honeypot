"""Jenkins routes — CI/CD endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route


def _jenkins() -> type:
    from manyfaced.handlers.jenkins_handler import JenkinsHandler

    return JenkinsHandler


ROUTES: list[Route] = [
    # ---- Jenkins -------------------------------------------------------------
    Route(PathExact('/jenkins'), _jenkins(), 1, 'jenkins_jenkins'),
    Route(PathPrefix('/jenkins/'), _jenkins(), 1, 'jenkins_jenkins_slash'),
    Route(PathExact('/jenkins/login'), _jenkins(), 1, 'jenkins_login'),
    Route(PathExact('/jenkins/script'), _jenkins(), 1, 'jenkins_script'),
    Route(PathExact('/jenkins/manage'), _jenkins(), 1, 'jenkins_manage'),
    Route(PathExact('/jenkins/api'), _jenkins(), 1, 'jenkins_api'),
    Route(PathExact('/jenkins/computer'), _jenkins(), 1, 'jenkins_computer'),
    Route(PathExact('/jenkins/view'), _jenkins(), 1, 'jenkins_view'),
    Route(PathExact('/jenkins/job'), _jenkins(), 1, 'jenkins_job'),
    Route(PathExact('/hudson'), _jenkins(), 1, 'jenkins_hudson'),
    Route(PathPrefix('/hudson/'), _jenkins(), 1, 'jenkins_hudson_slash'),
    Route(PathExact('/hudson/login'), _jenkins(), 1, 'jenkins_hudson_login'),
]
