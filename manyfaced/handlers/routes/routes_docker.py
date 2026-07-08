"""Docker Registry routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import DOCKER_HTTP


def _docker() -> type:
    from manyfaced.handlers.docker_handler import DockerHandler

    return DockerHandler


ROUTES: list[Route] = [
    # ---- Docker Registry (issue #275) ----
    Route(PathExact('/v2/_catalog'), _docker(), DOCKER_HTTP, 'docker_0'),
    Route(PathPrefix('/v2/_catalog/'), _docker(), DOCKER_HTTP, 'docker_prefix_0'),
    Route(PathExact('/v2'), _docker(), DOCKER_HTTP, 'docker_1'),
    Route(PathExact('/version'), _docker(), DOCKER_HTTP, 'docker_2'),
    Route(PathExact('/info'), _docker(), DOCKER_HTTP, 'docker_3'),
    Route(PathExact('/_ping'), _docker(), DOCKER_HTTP, 'docker_4'),
]
