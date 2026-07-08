"""Next.js routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import NEXTJS_HTTP


def _nextjs() -> type:
    from manyfaced.handlers.nextjs_handler import NextjsHandler

    return NextjsHandler


ROUTES: list[Route] = [
    # ---- Next.js (issue #277) ----
    Route(PathExact('/_next'), _nextjs(), NEXTJS_HTTP, 'nextjs_0'),
    Route(PathExact('/__nextjs_action'), _nextjs(), NEXTJS_HTTP, 'nextjs_1'),
    Route(PathExact('/vercel.json'), _nextjs(), NEXTJS_HTTP, 'nextjs_2'),
]
