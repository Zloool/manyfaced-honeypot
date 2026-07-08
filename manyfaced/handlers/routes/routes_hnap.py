"""HNAP routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import HNAP_HTTP


def _hnap() -> type:
    from manyfaced.handlers.hnap_handler import HNAPHandler

    return HNAPHandler


ROUTES: list[Route] = [
    # ---- HNAP (issue #288) ----
    Route(PathExact('/HNAP1'), _hnap(), HNAP_HTTP, 'hnap_0'),
    Route(PathExact('/hnap'), _hnap(), HNAP_HTTP, 'hnap_1'),
    Route(PathExact('/post_login.xml'), _hnap(), HNAP_HTTP, 'hnap_2'),
]
