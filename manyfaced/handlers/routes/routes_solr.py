"""Apache Solr routes (issue #279).

Matches the production Solr probe paths observed in the wild:
  /solr
  /solr/admin/
  /solr/admin/cores
  /solr/admin/info/system
  /solr/collection1/select
  /solr/admin/authentication
  /solr/%2eenv   (decoded to /solr/.env inside the handler)
  /admin/cores
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import SOLR_HTTP


def _solr() -> type:
    from manyfaced.handlers.solr_handler import SolrHandler

    return SolrHandler


ROUTES: list[Route] = [
    # ---- Apache Solr (issue #279) ----
    Route(PathExact('/solr'), _solr(), SOLR_HTTP, 'solr_root'),
    Route(PathExact('/solr/admin/cores'), _solr(), SOLR_HTTP, 'solr_cores'),
    Route(PathExact('/solr/admin/info/system'), _solr(), SOLR_HTTP, 'solr_info_system'),
    Route(PathPrefix('/solr/'), _solr(), SOLR_HTTP, 'solr_prefix'),
    Route(PathPrefix('/admin/'), _solr(), SOLR_HTTP, 'solr_admin_prefix'),
]
