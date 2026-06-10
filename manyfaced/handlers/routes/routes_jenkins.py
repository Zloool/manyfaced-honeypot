"""Jenkins routes — CI/CD endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import JENKINS_HTTP


def _jenkins() -> type:
    from manyfaced.handlers.jenkins_handler import JenkinsHandler

    return JenkinsHandler


ROUTES: list[Route] = [
    # ---- Jenkins -------------------------------------------------------------
    Route(PathExact('/jenkins'), _jenkins(), JENKINS_HTTP, 'jenkins_jenkins'),
    Route(PathPrefix('/jenkins/'), _jenkins(), JENKINS_HTTP, 'jenkins_jenkins_slash'),
    Route(PathExact('/jenkins/login'), _jenkins(), JENKINS_HTTP, 'jenkins_login'),
    Route(PathExact('/jenkins/script'), _jenkins(), JENKINS_HTTP, 'jenkins_script'),
    Route(PathExact('/jenkins/manage'), _jenkins(), JENKINS_HTTP, 'jenkins_manage'),
    Route(PathExact('/jenkins/api'), _jenkins(), JENKINS_HTTP, 'jenkins_api'),
    Route(PathExact('/jenkins/computer'), _jenkins(), JENKINS_HTTP, 'jenkins_computer'),
    Route(PathExact('/jenkins/view'), _jenkins(), JENKINS_HTTP, 'jenkins_view'),
    Route(PathExact('/jenkins/job'), _jenkins(), JENKINS_HTTP, 'jenkins_job'),
    Route(PathExact('/hudson'), _jenkins(), JENKINS_HTTP, 'jenkins_hudson'),
    Route(PathPrefix('/hudson/'), _jenkins(), JENKINS_HTTP, 'jenkins_hudson_slash'),
    Route(PathExact('/hudson/login'), _jenkins(), JENKINS_HTTP, 'jenkins_hudson_login'),
]
