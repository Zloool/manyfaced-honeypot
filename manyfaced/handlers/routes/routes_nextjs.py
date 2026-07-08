"""Next.js (Vercel) routes.

Matches the production probe paths observed in the wild (issue #277):
  /                 Next.js app shell home page
  /_next            Next.js production asset directory (/_next/static, /_next/image)
  /api              Next.js API routes (/api/health health probe)
  /vercel           Vercel platform probe
  /nextjs/          Next.js-specific probe namespace (.env / traversal probes,
                    e.g. /nextjs/%2eenv -> /nextjs/.env after decoding)
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import NEXTJS_HTTP


def _nextjs() -> type:
    from manyfaced.handlers.nextjs_handler import NextjsHandler

    return NextjsHandler


ROUTES: list[Route] = [
    # ---- Next.js (Vercel) (issue #277) ------------------------------------
    Route(PathExact('/api/health'), _nextjs(), NEXTJS_HTTP, 'nextjs_api_health'),
    Route(PathExact('/vercel'), _nextjs(), NEXTJS_HTTP, 'nextjs_vercel'),
    Route(PathPrefix('/_next/'), _nextjs(), NEXTJS_HTTP, 'nextjs_next_prefix'),
    Route(PathPrefix('/api/'), _nextjs(), NEXTJS_HTTP, 'nextjs_api_prefix'),
    Route(PathPrefix('/nextjs/'), _nextjs(), NEXTJS_HTTP, 'nextjs_probe_prefix'),
]
