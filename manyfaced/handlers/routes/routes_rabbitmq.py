"""RabbitMQ (Management UI / HTTP API) routes — issue #285.

Specific paths are registered before prefixes so the most-targeted probe
paths win.  Percent-encoded segments in probe paths (%2e -> '.', %2f -> '/')
are normalized by the handler before routing, so the matchers below use the
decoded forms where relevant.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import RABBITMQ_HTTP


def _rabbitmq() -> type:
    from manyfaced.handlers.rabbitmq_handler import RabbitMQHandler

    return RabbitMQHandler


ROUTES: list[Route] = [
    # ---- RabbitMQ Management UI / HTTP API (issue #285) -------------------
    # Specific paths first.
    Route(PathExact('/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_root'),
    Route(PathExact('/api/overview'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_overview'),
    Route(PathExact('/api/whoami'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_whoami'),
    Route(PathExact('/api/queues'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_queues'),
    Route(PathExact('/api/exchanges'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_exchanges'),
    Route(PathExact('/api/connections'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_connections'),
    Route(
        PathExact('/api/aliveness-test/%2f'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_aliveness'
    ),
    # Prefixes last.
    Route(PathPrefix('/api/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api'),
    Route(PathPrefix('/cli/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_cli'),
    Route(PathPrefix('/rabbitmq/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_env'),
]
