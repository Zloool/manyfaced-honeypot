"""Elasticsearch routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ELASTIC_HTTP


def _elasticsearch() -> type:
    from manyfaced.handlers.elasticsearch_handler import ElasticsearchHandler

    return ElasticsearchHandler


ROUTES: list[Route] = [
    # ---- Elasticsearch (issue #278) ----
    Route(PathExact('/_cat'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_0'),
    Route(PathExact('/_search'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_1'),
    Route(PathExact('/_cluster'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_2'),
    Route(PathExact('/_nodes'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_3'),
    Route(PathExact('/query'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_4'),
]
