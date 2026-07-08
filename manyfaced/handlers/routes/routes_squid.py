"""Squid cache-manager (cachemgr) routes — issue #289.

Maps the production probe paths that bots use to enumerate a Squid proxy's
cache manager to the SquidHandler:

  /squid-internal-mgr/      -> HTML cache-manager page (root)
  /squid-internal-mgr/menu  -> HTML cache-manager menu page
  /squid-internal-mgr/info  -> plain-text info report
  /cachemgr.cgi             -> HTML cache-manager page (classic CGI name)
  /mgr/info                 -> plain-text info report (legacy /mgr alias)
  /cgi-bin/cachemgr.cgi     -> HTML cache-manager page (cgi-bin deployment)

Decoding of %2e/%2f encoded probes is handled inside the handler so the
exact/exact-prefix matchers here operate on the literal probe strings.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import SQUID_HTTP


def _squid() -> type:
    from manyfaced.handlers.squid_handler import SquidHandler

    return SquidHandler


ROUTES: list[Route] = [
    # ---- Squid cachemgr (issue #289) ----
    Route(PathExact('/squid-internal-mgr/'), _squid(), SQUID_HTTP, 'squid_mgr_root'),
    Route(PathExact('/squid-internal-mgr/menu'), _squid(), SQUID_HTTP, 'squid_mgr_menu'),
    Route(PathExact('/squid-internal-mgr/info'), _squid(), SQUID_HTTP, 'squid_mgr_info'),
    Route(PathExact('/cachemgr.cgi'), _squid(), SQUID_HTTP, 'squid_cachemgr_cgi'),
    Route(PathPrefix('/squid-internal-mgr/'), _squid(), SQUID_HTTP, 'squid_mgr_prefix'),
    Route(PathPrefix('/mgr/'), _squid(), SQUID_HTTP, 'squid_mgr_alias_prefix'),
    Route(PathPrefix('/cgi-bin/'), _squid(), SQUID_HTTP, 'squid_cgi_bin_prefix'),
]
