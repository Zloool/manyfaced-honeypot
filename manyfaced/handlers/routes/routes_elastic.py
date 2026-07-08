"""Elastic (Elasticsearch REST API + Kibana) routes (issue #281).

Mirrors the Bitrix route table. Covers the production probe paths in the issue,
decoded from URL-encoded probes (%2e -> '.', %2f -> '/'):

  /_cat                 -> cat API index
  /_cluster/health      -> cluster health
  /_nodes               -> node listing
  /_search              -> search endpoint
  /_xpack               -> X-Pack info
  /_snapshot            -> snapshot/restore
  /_license             -> license info
  /kibana               -> Kibana frontend
  /app/kibana           -> Kibana app shell
  /_plugin/head         -> elasticsearch-head plugin
  /_sql                 -> SQL endpoint
  /_bulk                -> bulk endpoint
  /elasticsearch/%2eenv -> env disclosure probe (decoded .env)
  /elastic/%2eenv       -> env disclosure probe (decoded .env)

Specific paths are listed first; broad prefixes come last so they never shadow
the explicit routes above them.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ELASTIC_HTTP


def _elastic() -> type:
    from manyfaced.handlers.elastic_handler import ElasticHandler

    return ElasticHandler


ROUTES: list[Route] = [
    # ---- Elasticsearch REST API (issue #281) ------------------------------
    Route(PathExact('/_cat'), _elastic(), ELASTIC_HTTP, 'elastic_cat'),
    Route(PathExact('/_cluster/health'), _elastic(), ELASTIC_HTTP, 'elastic_cluster_health'),
    Route(PathExact('/_nodes'), _elastic(), ELASTIC_HTTP, 'elastic_nodes'),
    Route(PathExact('/_search'), _elastic(), ELASTIC_HTTP, 'elastic_search'),
    Route(PathExact('/_xpack'), _elastic(), ELASTIC_HTTP, 'elastic_xpack'),
    Route(PathExact('/_snapshot'), _elastic(), ELASTIC_HTTP, 'elastic_snapshot'),
    Route(PathExact('/_license'), _elastic(), ELASTIC_HTTP, 'elastic_license'),
    Route(PathExact('/kibana'), _elastic(), ELASTIC_HTTP, 'elastic_kibana'),
    Route(PathExact('/app/kibana'), _elastic(), ELASTIC_HTTP, 'elastic_app_kibana'),
    Route(PathExact('/_plugin/head'), _elastic(), ELASTIC_HTTP, 'elastic_plugin_head'),
    Route(PathExact('/_sql'), _elastic(), ELASTIC_HTTP, 'elastic_sql'),
    Route(PathExact('/_bulk'), _elastic(), ELASTIC_HTTP, 'elastic_bulk'),
    Route(PathExact('/elasticsearch/.env'), _elastic(), ELASTIC_HTTP, 'elastic_es_env'),
    Route(PathExact('/elastic/.env'), _elastic(), ELASTIC_HTTP, 'elastic_elastic_env'),
    # Broad prefixes — listed last so specific paths above win.
    Route(PathPrefix('/_'), _elastic(), ELASTIC_HTTP, 'elastic_underscore'),
    Route(PathPrefix('/kibana'), _elastic(), ELASTIC_HTTP, 'elastic_kibana_prefix'),
    Route(PathPrefix('/elastic'), _elastic(), ELASTIC_HTTP, 'elastic_elastic_prefix'),
]
