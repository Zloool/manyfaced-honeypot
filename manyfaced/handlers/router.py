"""Router – explicit HTTP request dispatch.

Every HTTP request produces a response from exactly one handler via an ordered
route table.  The dispatch decision is visible in one ordered route table.

Usage::

    from manyfaced.handlers.router import Router, PathPrefix, PathExact, Any
    from manyfaced.handlers.routes import ROUTES

    router = Router(ROUTES)
    result = router.dispatch('/wp-login.php', raw_request, bot_ip, headers)
    # result is (response_bytes, detected_id) or None

The route table is defined in manyfaced.handlers.routes.ROUTES.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import NamedTuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Matcher base class
# ---------------------------------------------------------------------------


class Matcher(ABC):
    """Abstract base: matches(request_path) -> bool.

    ``request_path`` is the URL path *after* query-string stripping and
    lower-casing (the caller does this before calling dispatch).
    """

    @abstractmethod
    def match(self, request_path: str) -> bool: ...


# ---------------------------------------------------------------------------
# Concrete matchers
# ---------------------------------------------------------------------------


class PathPrefix(Matcher):
    """Matches if ``request_path.lower().startswith(prefix.lower())``."""

    __slots__ = ('_prefix',)

    def __init__(self, prefix: str) -> None:
        self._prefix = prefix.lower()

    def match(self, request_path: str) -> bool:
        return request_path.lower().startswith(self._prefix)

    def __repr__(self) -> str:
        return f'PathPrefix({self._prefix!r})'


class PathExact(Matcher):
    """Matches if ``request_path.lower() == path.lower()``."""

    __slots__ = ('_path',)

    def __init__(self, path: str) -> None:
        self._path = path.lower()

    def match(self, request_path: str) -> bool:
        return request_path.lower() == self._path

    def __repr__(self) -> str:
        return f'PathExact({self._path!r})'


class Any(Matcher):
    """Always matches.  Used for catch-all."""

    def match(self, request_path: str) -> bool:
        return True

    def __repr__(self) -> str:
        return 'Any()'


# ---------------------------------------------------------------------------
# Route and Router
# ---------------------------------------------------------------------------


class Route(NamedTuple):
    """A single route entry.

    Attributes:
        matcher:  Matcher instance that decides if this route applies.
        handler_cls:  Handler class (not instance) to instantiate on match.
        detected_id:  Integer detected-id for the report.
        name:  Human-readable name for debug/logging.
    """

    matcher: Matcher
    handler_cls: type
    detected_id: int
    name: str


class Router:
    """Holds an ordered list of Route.

    ``dispatch(path, raw_request, bot_ip, headers)`` walks the list and
    returns on first match's ``(response_bytes, detected_id)``.  Returns
    None only if no match (should not happen if the table ends with Any()).

    ``explain(path)`` returns a debug string like "matched route 3 (wordpress)".

    Handler instances are persisted across dispatch calls so that per-request
    state (BotProfile dicts, request history, escalation levels) survives
    within a single connection/session.
    """

    def __init__(self, routes: list[Route]) -> None:
        self._routes = routes
        # Persist handler instances keyed by route index so BotProfile state
        # survives across multiple requests on the same TCP connection.
        self._handler_instances: dict[int, object] = {}

    # -- public API --------------------------------------------------------

    def dispatch(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int] | None:
        """Return ``(response_bytes, detected_id)`` or ``None``.

        The matched handler instance is reused across calls so that per-request
        state (BotProfile dicts) persists within a session/connection.
        """
        for idx, route in enumerate(self._routes):
            if route.matcher.match(path):
                try:
                    # Reuse existing handler or create new one for this route
                    if idx not in self._handler_instances:
                        self._handler_instances[idx] = route.handler_cls()
                    handler = self._handler_instances[idx]
                    response_bytes, detected_flag = handler.generate_response(
                        path=path,
                        raw_request=raw_request,
                        bot_ip=bot_ip,
                        headers=headers,
                    )
                    logger.debug(
                        'Route %d (%s) matched – handler=%s, size=%d',
                        idx,
                        route.name,
                        handler.domain,
                        len(response_bytes),
                    )
                    return response_bytes, detected_flag
                except Exception as e:
                    logger.warning('Handler %s failed for path %s: %s', route.name, path, e)
        return None  # pragma: no cover – should never happen with Any() catch-all

    def clear_handler_instances(self) -> None:
        """Clear persisted handler instances (e.g., at end of connection)."""
        self._handler_instances.clear()

    def explain(self, path: str) -> str:
        """Return a debug string for the matched route."""
        for idx, route in enumerate(self._routes):
            if route.matcher.match(path):
                return f'matched route {idx} ({route.name})'
        return 'no match'

    @property
    def routes_count(self) -> int:
        """Number of routes in the table."""
        return len(self._routes)

    @property
    def routes(self) -> list[Route]:
        """The ordered list of Route objects."""
        return self._routes


# ---------------------------------------------------------------------------
# Singleton (populated by routes.py at import time)
# ---------------------------------------------------------------------------

router: Router | None = None  # set by routes.py after ROUTES is defined
