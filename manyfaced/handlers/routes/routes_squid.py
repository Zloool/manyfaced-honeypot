"""Squid routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import SQUID_HTTP


def _squid() -> type:
    from manyfaced.handlers.squid_handler import SquidHandler

    return SquidHandler


ROUTES: list[Route] = [
    # ---- Squid (issue #289) ----
    Route(PathExact('/squid'), _squid(), SQUID_HTTP, 'squid_0'),
    Route(PathExact('/cachemgr'), _squid(), SQUID_HTTP, 'squid_1'),
    Route(PathExact('/cgi-bin'), _squid(), SQUID_HTTP, 'squid_2'),
]
