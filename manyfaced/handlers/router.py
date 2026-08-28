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
from threading import Lock
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, NamedTuple, cast
from urllib.parse import unquote

from manyfaced.common.metrics import incr, incr_response


def _decode_path(path: str) -> str:
    """Decode a request path for routing/dispatch (issue #443).

    Strips the query string (the Router matches on the path portion only) and
    percent-decodes path-escape probes so encoded dots/slashes (``%2e`` ->
    ``.``, ``%2f`` -> ``/``) match the exploit/config-disclosure routes instead
    of falling through to the catch-all monster page.

    ``urllib.parse.unquote`` is idempotent on an already-decoded path, so
    calling it here is safe even when handlers also unquote defensively.
    """
    clean = path.split('?', 1)[0]
    try:
        return unquote(clean)
    except Exception:  # pragma: no cover - urllib rarely raises
        return clean


if TYPE_CHECKING:
    from manyfaced.handlers.base_handler import HTTPHandlerBase  # noqa: F401

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
        ports:  Optional tuple of listen ports this route is scoped to. When
            set, the route only matches requests that arrived on one of those
            ports (issue #633 — stops ES admin routes leaking onto unrelated
            HTTP faces such as 9090/5000/7001). ``None`` (default) means the
            route is universal and matches on every HTTP port.
    """

    matcher: Matcher
    handler_cls: type
    detected_id: int
    name: str
    ports: tuple[int, ...] | None = None


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
        # Guards _handler_instances (mutated during dispatch and clear()) against
        # concurrent access from the per-connection daemon threads.
        self._lock = Lock()

    # -- public API --------------------------------------------------------

    def dispatch(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
        port: int | None = None,
    ) -> tuple[bytes, int] | None:
        """Return ``(response_bytes, detected_id)`` or ``None``.

        The matched handler instance is reused across calls so that per-request
        state (BotProfile dicts) persists within a session/connection.

        The path is percent-decoded once here (issue #443) so encoded
        path-escape probes (``%2e``, ``%2f``) match the right route regardless
        of which caller invokes dispatch.

        Args:
            port: The listen port the request arrived on. When a route declares
                an explicit ``ports`` scope (issue #633) it only matches if
                ``port`` is one of them; an unknown/zero port disables the
                filter so legacy port-less dispatch keeps its old behavior.
        """
        decoded_path = _decode_path(path)
        for idx, route in enumerate(self._routes):
            # Port scoping (issue #633): a route with an explicit ``ports``
            # tuple only matches when the request arrived on one of those ports.
            # Universal routes (ports=None) always match. An unknown/zero port
            # (port is None or 0) disables the filter so port-less dispatch and
            # the replay harness (listen_port=0) keep their legacy behavior.
            route_ports = route.ports
            if (
                route_ports is not None
                and isinstance(port, int)
                and port != 0
                and port not in route_ports
            ):
                continue
            if route.matcher.match(decoded_path):
                try:
                    # Reuse existing handler or create new one for this route
                    with self._lock:
                        if idx not in self._handler_instances:
                            self._handler_instances[idx] = route.handler_cls()
                        handler = cast('HTTPHandlerBase', self._handler_instances[idx])
                    response_bytes, detected_flag = handler.generate_response(
                        path=decoded_path,
                        raw_request=raw_request,
                        bot_ip=bot_ip,
                        headers=headers,
                    )

                    # Wire up record_interaction to build the dialogue artifact
                    self._record_interaction(
                        handler,
                        decoded_path,
                        raw_request,
                        bot_ip,
                        headers,
                        response_bytes,
                        detected_flag,
                    )

                    logger.debug(
                        'Route %d (%s) matched – handler=%s, size=%d',
                        idx,
                        route.name,
                        handler.domain,
                        len(response_bytes),
                    )
                    # Observability: count responses per handler domain (issue #166).
                    incr_response(handler.domain)
                    return response_bytes, detected_flag
                except Exception as e:
                    logger.warning('Handler %s failed for path %s: %s', route.name, path, e)
                    incr('handler_exception')
        return None  # pragma: no cover – should never happen with Any() catch-all

    def _record_interaction(
        self,
        handler: 'HTTPHandlerBase',  # noqa: F821
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None,
        response_bytes: bytes,
        detected_flag: int,
    ) -> None:
        """Record a full request/response interaction in the BotProfile.

        This wires up record_interaction() centrally so every handler benefits
        and it can't be forgotten per-handler.
        """
        # Extract HTTP method from raw request (same logic as handlers)
        parts = raw_request.split()
        method = parts[0].upper() if parts else 'GET'

        # Construct request_data dict (same structure as handlers use)
        request_data = {
            'path': path,
            'method': method,
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
        }

        # Get profile and record interaction
        profile = handler.get_profile(bot_ip)
        if profile is not None:
            try:
                profile.record_interaction(request_data, response_bytes, detected_flag)
            except Exception as e:
                logger.warning('Failed to record interaction for %s: %s', bot_ip, e)

    def clear_handler_instances(self) -> None:
        """Clear persisted handler instances (e.g., at end of connection)."""
        with self._lock:
            self._handler_instances.clear()

    def explain(self, path: str, port: int | None = None) -> str:
        """Return a debug string for the matched route."""
        decoded_path = _decode_path(path)
        for idx, route in enumerate(self._routes):
            # Mirror dispatch's port scoping (issue #633) so explain() reports
            # the route that would actually win for a given listen port.
            route_ports = route.ports
            if (
                route_ports is not None
                and isinstance(port, int)
                and port != 0
                and port not in route_ports
            ):
                continue
            if route.matcher.match(decoded_path):
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

    def get_all_profiles_for_ip(self, bot_ip: str) -> dict[str, Any]:
        """Collect BotProfile data for a given IP across all handler instances.

        Returns a dict keyed by domain name with each value being the full report
        from that handler's BotProfile (if one exists).  Only HTTPHandlerBase
        subclasses are inspected.
        """
        result: dict[str, Any] = {}
        # Snapshot under lock (thread safety), then release before calling
        # get_profile (which may do I/O and should not hold the lock).
        with self._lock:
            instances = list(self._handler_instances.items())
        for idx, instance in instances:
            get_profile = getattr(instance, 'get_profile', None)
            if get_profile is not None:
                profile = get_profile(bot_ip)
                if profile is not None:
                    domain = getattr(instance, 'domain', f'route_{idx}')
                    result[domain] = profile.get_full_report()
        return result


# ---------------------------------------------------------------------------
# Singleton (populated by routes.py at import time)
# ---------------------------------------------------------------------------

router: Router | None = None  # set by routes.py after ROUTES is defined
