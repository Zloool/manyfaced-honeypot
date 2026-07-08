"""Docker Registry v2 / daemon API routes (issue #275).

Real probe paths (URL-encoding decoded before matching by the router):
    /v2/                      Registry v2 ping / distribution check
    /v2/_catalog              List all repositories
    /v2/<name>/tags/list      List tags for a repository
    /info                     Daemon GET /info
    /version                  Daemon GET /version
    /containers/json          Daemon GET /containers/json
    /docker/.env              Leaked .env path-traversal probe
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import DOCKER_HTTP


def _docker() -> type:
    from manyfaced.handlers.docker_handler import DockerHandler

    return DockerHandler


ROUTES: list[Route] = [
    # ---- Docker Registry v2 / daemon API (issue #275) ----
    Route(PathExact('/v2/'), _docker(), DOCKER_HTTP, 'docker_v2_ping'),
    Route(PathExact('/v2/_catalog'), _docker(), DOCKER_HTTP, 'docker_catalog'),
    Route(PathExact('/version'), _docker(), DOCKER_HTTP, 'docker_version'),
    Route(PathExact('/info'), _docker(), DOCKER_HTTP, 'docker_info'),
    Route(PathPrefix('/v2/'), _docker(), DOCKER_HTTP, 'docker_v2_prefix'),
    Route(PathPrefix('/containers/'), _docker(), DOCKER_HTTP, 'docker_containers'),
    Route(PathPrefix('/docker/'), _docker(), DOCKER_HTTP, 'docker_docker_prefix'),
]
