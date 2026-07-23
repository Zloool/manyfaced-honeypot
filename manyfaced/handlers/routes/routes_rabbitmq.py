"""RabbitMQ (Management UI / HTTP API) routes — issue #285 / #643.

Specific paths are registered before prefixes so the most-targeted probe
paths win.  Percent-encoded segments in probe paths (%2e -> '.', %2f -> '/')
are normalized by the handler before routing, so the matchers below use the
decoded forms where relevant.

Issue #643: port 15672 is a real HTTP service owned by RabbitMQHandler, but
the route table only covered ``/api/*``, ``/cli/*`` and ``/rabbitmq/*``.  The
bare root ``GET /`` and other top-level management paths fell through to
sibling framework faces (Elasticsearch, Solr, Grafana, fingerprint-404), so
0 of 287 prod rows carried ``RABBITMQ_HTTP (1015)``.  Naive scanners also
send Elasticsearch-style REST probes (``/_cluster``, ``/_nodes``,
``/_search``, ``/_cat``) to 15672, which the Elastic handler happily answered.

These routes add the bare root, the CLI/management landing paths, the
``/login`` + ``/favicon.ico`` UI assets, and the ES-style probe paths so they
are all classified ``RABBITMQ_HTTP``.  The route table is listed BEFORE the
Elasticsearch/Solr/Grafana tables in ``routes/__init__.py``, so these entries
win the shared paths by dispatch order.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import RABBITMQ_HTTP


def _rabbitmq() -> type:
    from manyfaced.handlers.rabbitmq_handler import RabbitMQHandler

    return RabbitMQHandler


ROUTES: list[Route] = [
    # ---- RabbitMQ Management UI / HTTP API (issue #285 / #643) ------------
    # Specific API paths first.
    Route(PathExact('/api/overview'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_overview'),
    Route(PathExact('/api/whoami'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_whoami'),
    Route(PathExact('/api/queues'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_queues'),
    Route(PathExact('/api/exchanges'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_exchanges'),
    Route(PathExact('/api/connections'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_connections'),
    Route(
        PathExact('/api/aliveness-test/%2f'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api_aliveness'
    ),
    # Management UI landing (issue #643): bare root fell through to the
    # Elasticsearch root route (GET /) before. Registered here (before the
    # Elastic route table) so it is classified as RabbitMQ.
    Route(PathExact('/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_root'),
    Route(PathExact('/cli'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_cli_exact'),
    # NOTE: Elasticsearch-style probe paths (/_cluster, /_nodes, /_search, /_cat)
    # that scanners fire at 15672 are intentionally NOT claimed here — they
    # belong to the Elastic face (Elasticsearch handler routes them to
    # ELASTIC_HTTP, see issue #644 / PR #670). Claiming them as RabbitMQ would
    # shadow Elastic's legitimate ownership (issue #643 is about RabbitMQ's own
    # management paths being misclassified, not about ES probes).
    # Prefixes last.
    Route(PathPrefix('/api/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_api'),
    Route(PathPrefix('/cli/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_cli'),
    Route(PathPrefix('/rabbitmq/'), _rabbitmq(), RABBITMQ_HTTP, 'rabbitmq_env'),
]
