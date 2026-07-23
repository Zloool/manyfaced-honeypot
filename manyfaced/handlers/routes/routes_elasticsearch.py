"""Elasticsearch routes (issue #461/#468).

Port 9200 is a real HTTP service, so it is served by the HTTP router (see
``is_http_port`` in ``manyfaced/common/faces.py``) and NOT the non-HTTP face
registry. These routes wire 9200 to the feature-complete ``ElasticHandler``
(``manyfaced/handlers/elastic_handler.py``), which already emulates the ES REST
API and Kibana, so probes get genuine ES JSON instead of a static root reply.

A bare ``GET /`` returns the ES cluster-info JSON (the classic Elasticsearch
"you know, for search" document) — exactly what a real cluster answers.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ELASTIC_HTTP


def _elasticsearch() -> type:
    from manyfaced.handlers.elastic_handler import ElasticHandler

    return ElasticHandler


ROUTES: list[Route] = [
    # ---- Elasticsearch (issue #461/#468) ----
    # Root cluster-info document (GET /).
    Route(PathExact('/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_root'),
    Route(PathExact('/_cat'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_0'),
    Route(PathExact('/_search'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_1'),
    Route(PathExact('/_cluster'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_2'),
    Route(PathExact('/_nodes'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_3'),
    Route(PathExact('/query'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_4'),
    # Issue #644: these bare ES REST endpoints previously fell through to the
    # catch-all (UNKNOWN_HTTP) so attack traffic was not attributed to Elastic.
    Route(PathExact('/_aliases'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_aliases'),
    Route(PathExact('/_stats'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_stats'),
    Route(PathExact('/_status'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_status'),
    Route(PathExact('/_all/_mapping'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_all_mapping'),
    Route(PathPrefix('/_cat/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_cat_prefix'),
    Route(PathPrefix('/_cluster/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_cluster_prefix'),
    Route(PathPrefix('/_nodes/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_nodes_prefix'),
    Route(PathPrefix('/_search/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_search_prefix'),
    Route(PathPrefix('/_xpack/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_xpack_prefix'),
    Route(
        PathPrefix('/_snapshot/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_snapshot_prefix'
    ),
    Route(PathPrefix('/_license/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_license_prefix'),
    Route(PathPrefix('/_sql/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_sql_prefix'),
    Route(PathPrefix('/_bulk/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_bulk_prefix'),
    Route(PathPrefix('/_plugin/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_plugin_prefix'),
    Route(PathPrefix('/kibana'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_kibana_prefix'),
    Route(
        PathPrefix('/elasticsearch/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_env_prefix'
    ),
    Route(PathPrefix('/elastic/'), _elasticsearch(), ELASTIC_HTTP, 'elasticsearch_elastic_prefix'),
]
