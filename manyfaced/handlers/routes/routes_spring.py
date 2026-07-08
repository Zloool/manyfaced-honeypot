"""Spring Boot routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import SPRING_HTTP


def _spring() -> type:
    from manyfaced.handlers.spring_handler import SpringHandler

    return SpringHandler


ROUTES: list[Route] = [
    # ---- Spring Boot (issue #281) ----
    Route(PathExact('/actuator'), _spring(), SPRING_HTTP, 'spring_0'),
    Route(PathExact('/actuator/health'), _spring(), SPRING_HTTP, 'spring_1'),
    Route(PathPrefix('/actuator/health/'), _spring(), SPRING_HTTP, 'spring_prefix_1'),
    Route(PathExact('/api/env'), _spring(), SPRING_HTTP, 'spring_2'),
    Route(PathPrefix('/api/env/'), _spring(), SPRING_HTTP, 'spring_prefix_2'),
]
