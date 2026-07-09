"""High-entropy random-path fingerprinting deflection (issue #324).

Scanners such as CensysInspect probe a single random token like
``/3cwja4nt2qs1a4v`` — no dictionary structure, no extension — specifically to
detect servers that answer *everything* with 200. A real Apache/nginx returns a
*404* for such a path. We answer those probes the way the emulated stack would,
preserving them as high-value intel rather than dropping them.

This module is intentionally pure and I/O-free so the classifier is trivially
unit-testable and reusable by tests without touching the network. It is
**UA-agnostic**: we never special-case the scanner User-Agent (it is spoofable
and special-casing is itself a tell — UA/ASN allowlisting is #271's territory).
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from manyfaced.common import status as _status
from manyfaced.handlers.base_handler import HTTPHandlerBase
from manyfaced.handlers.router import Matcher

if TYPE_CHECKING:
    from manyfaced.handlers.base_handler import HTTPHandlerBase as _HTTPHandlerBase  # noqa: F401

# Apache signature the rest of the honeypot advertises (generic_handler.py).
_APACHE_SERVER = 'Apache/2.4.57 (Ubuntu)'


def _shannon_entropy(s: str) -> float:
    """Normalized Shannon entropy of ``s`` over its distinct characters (0..1)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values()) / math.log2(len(freq))


def is_random_probe(path: str) -> bool:
    """Return True if ``path`` looks like a high-entropy fingerprinting token.

    ``path`` is the request path *after* query-string stripping and
    lower-casing (the Router strips the query string and lowercases before
    dispatch — see manyfaced.handlers.router.Router.dispatch).

    Conservative by design: prefer false-*keep* (route to the monster-page
    bait) over false-*404*. A probe must be a single path segment with no file
    extension, length 8–40, composed of letters+digits with no separators, with
    high Shannon entropy *and* no dictionary structure (low vowel ratio, no
    common English n-grams).
    """
    # Accept the raw request path (with its leading slash) OR a bare segment.
    # Strip a *single* leading slash; an internal slash means a multi-segment
    # path (/api/v2/...) which is a real route / bait, not a probe token.
    if path.startswith('/'):
        path = path[1:]
    if not path or '/' in path or '\\' in path:
        return False  # multi-segment paths (/api/v2/...) are real routes / bait

    seg = path

    # No file extension (a static asset like app.a1b2c3d4.js stays bait).
    if '.' in seg:
        return False

    # Length band — random tokens are short-ish; long dictionary slugs aren't probes.
    if not (8 <= len(seg) <= 40):
        return False

    # Must be alphanumeric with no separators (no '-', '_', '+').
    if not seg.isalnum():
        return False

    # Must contain both letters and digits (a pure-alpha or pure-digit blob is
    # less typical of scanner tokens and more likely a real-looking slug).
    has_alpha = any(c.isalpha() for c in seg)
    has_digit = any(c.isdigit() for c in seg)
    if not (has_alpha and has_digit):
        return False

    # High normalized entropy across the character set (random-looking).
    if _shannon_entropy(seg) < 0.85:
        return False

    # No dictionary structure: low vowel ratio + no common English bigrams.
    vowels = sum(1 for c in seg if c in 'aeiou')
    if vowels / len(seg) > 0.30:
        return False
    _COMMON_BIGRAMS = ('th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd', 'ti', 'es', 'or')
    if any(bg in seg for bg in _COMMON_BIGRAMS):
        return False

    return True


def build_apache_404(host: str, port: int) -> bytes:
    """Build a byte-exact Apache 404 body consistent with the emulated stack.

    Deterministic per ``(host, port)``: identical request → identical body
    (only the HTTP ``Date`` header varies, which a fingerprinter tolerates).
    Omits ``X-Powered-By: PHP`` (PHP doesn't execute for a nonexistent static
    path) and uses ``iso-8859-1`` — a real Apache 404 charset, not UTF-8.
    """
    body = (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        '<html><head>\n'
        '<title>404 Not Found</title>\n'
        '</head><body>\n'
        '<h1>Not Found</h1>\n'
        f'<p>The requested URL was not found on this server.</p>\n'
        f'<hr>\n'
        f'<address>Apache/2.4.57 (Ubuntu) Server at {host} Port {port}</address>\n'
        '</body></html>\n'
    )
    body_bytes = body.encode('iso-8859-1')
    now = _http_date()
    return (
        f'HTTP/1.1 404 Not Found\r\n'
        f'Date: {now}\r\n'
        f'Server: {_APACHE_SERVER}\r\n'
        'Content-Type: text/html; charset=iso-8859-1\r\n'
        'Connection: close\r\n'
        f'Content-Length: {len(body_bytes)}\r\n'
        '\r\n'
    ).encode('iso-8859-1') + body_bytes


def _http_date() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


class HighEntropyPath(Matcher):
    """Matches high-entropy single-segment random paths (fingerprinting probes)."""

    def match(self, request_path: str) -> bool:
        return is_random_probe(request_path)

    def __repr__(self) -> str:
        return 'HighEntropyPath()'


class NotFoundHandler(HTTPHandlerBase):
    """Answers high-entropy random paths with a realistic Apache 404 (issue #324).

    Still records + meters the probe (fingerprinting is high-value intel); the
    sentinel FINGERPRINT_PROBE keeps it out of the detected-service bucket.
    """

    domain = 'fingerprint_probe'
    DETECTED_ID = _status.FINGERPRINT_PROBE

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        # Record the probe so BotProfile dialogue + downstream stats capture it.
        self.get_or_create_profile(bot_ip)
        # Derive host:port from the request Host header so the 404 is
        # byte-consistent with what the attacker sent.
        host = (headers or {}).get('Host', 'localhost')
        port = 80
        host_only = host
        if ':' in host:
            host_only, port_str = host.rsplit(':', 1)
            if port_str.isdigit():
                port = int(port_str)
        return build_apache_404(host_only, port), self.DETECTED_ID
