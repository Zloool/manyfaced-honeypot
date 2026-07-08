"""Apache Solr routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import SOLR_HTTP


def _solr() -> type:
    from manyfaced.handlers.solr_handler import SolrHandler

    return SolrHandler


ROUTES: list[Route] = [
    # ---- Apache Solr (issue #279) ----
    Route(PathExact('/solr/admin/info/system'), _solr(), SOLR_HTTP, 'solr_0'),
    Route(PathPrefix('/solr/admin/info/system/'), _solr(), SOLR_HTTP, 'solr_prefix_0'),
    Route(PathExact('/solr/admin/cores'), _solr(), SOLR_HTTP, 'solr_1'),
    Route(PathPrefix('/solr/admin/cores/'), _solr(), SOLR_HTTP, 'solr_prefix_1'),
    Route(PathExact('/solr'), _solr(), SOLR_HTTP, 'solr_2'),
]
