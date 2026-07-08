"""HNAP (Home Network Administration Protocol) routes — issue #288.

Mirrors the production probe paths bots use to locate the HNAP1 endpoint on
consumer routers. Encoded variants decode inside the handler.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import HNAP_HTTP


def _hnap() -> type:
    from manyfaced.handlers.hnap_handler import HNAPHandler

    return HNAPHandler


ROUTES: list[Route] = [
    # ---- HNAP (issue #288) ------------------------------------------------
    Route(PathExact('/HNAP1'), _hnap(), HNAP_HTTP, 'hnap_hnap1'),
    Route(PathExact('/hnap1'), _hnap(), HNAP_HTTP, 'hnap_hnap1_lower'),
    Route(PathExact('/HNAP1/'), _hnap(), HNAP_HTTP, 'hnap_hnap1_slash'),
    Route(PathExact('/cgi-bin/HNAP1'), _hnap(), HNAP_HTTP, 'hnap_cgi'),
    Route(PathExact('/PrivateHNAP'), _hnap(), HNAP_HTTP, 'hnap_private'),
    Route(PathPrefix('/HNAP1/'), _hnap(), HNAP_HTTP, 'hnap_prefix'),
]
