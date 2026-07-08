"""RabbitMQ routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import RABBITMQ_HTTP


def _rabbitmq() -> type:
    from manyfaced.handlers.rabbitmq_handler import RabbitMQHandler

    return RabbitMQHandler


ROUTES: list[Route] = [
    # ---- RabbitMQ (issue #298) ----
    Route(PathExact('/api/overview'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_0'),
    Route(PathPrefix('/api/overview/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_prefix_0'),
    Route(PathExact('/api/queues'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_1'),
    Route(PathPrefix('/api/queues/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_prefix_1'),
    Route(PathExact('/api/exchanges'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_2'),
    Route(PathPrefix('/api/exchanges/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_prefix_2'),
    Route(PathExact('/rabbitmq'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_3'),
]
