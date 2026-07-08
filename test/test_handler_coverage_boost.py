"""Coverage boost: exercise every registered route's handler across its paths.

Hits each Route's matcher with a representative path so the handler's
dispatch branches and response builders are covered without duplicating the
per-service behavioural tests.
"""

from __future__ import annotations

from manyfaced.handlers.routes import ROUTES  # noqa: F401  (import side-effects)
from manyfaced.handlers.router import PathExact, PathPrefix, Route


def _sample_path(matcher) -> str:
    if isinstance(matcher, PathExact):
        return matcher._path
    if isinstance(matcher, PathPrefix):
        # strip trailing slash so it is a valid prefixed path
        return matcher._prefix.rstrip('/') or '/'
    return '/'


def test_every_route_responds() -> None:
    seen: set[tuple[str, type]] = set()
    for route in ROUTES:
        assert isinstance(route, Route)
        path = _sample_path(route.matcher)
        handler = route.handler_cls()
        raw = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: example.com\r\n'
            f'User-Agent: coverage-boost\r\n\r\n'
        )
        resp, detected = handler.generate_response(
            path=path, raw_request=raw, bot_ip='1.2.3.4'
        )
        assert isinstance(resp, (bytes, bytearray)) and len(resp) > 0
        seen.add((route.name, route.handler_cls))


def test_every_route_post_body() -> None:
    """POST against each route to cover credential-capture branches."""
    for route in ROUTES:
        path = _sample_path(route.matcher)
        handler = route.handler_cls()
        raw = (
            f'POST {path} HTTP/1.1\r\n'
            f'Host: example.com\r\n'
            f'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            f'user=admin&pass=secret&username=root&password=toor'
        )
        resp, _ = handler.generate_response(
            path=path, raw_request=raw, bot_ip='1.2.3.4'
        )
        assert isinstance(resp, (bytes, bytearray)) and len(resp) > 0
