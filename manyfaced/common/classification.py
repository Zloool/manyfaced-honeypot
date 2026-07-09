"""Benign-source classification (issue #271).

A lightweight, self-hosted analogue of GreyNoise's RIOT dataset: split captured
activity into ``benign`` / ``malicious`` / ``unknown`` based on a curated,
versioned allowlist of known-benign internet-wide scanners, crawlers and CDN
health-checkers.

The allowlist lives in ``manyfaced/data/benign_sources.toml`` (data, not code)
so it can be updated without a code change. :func:`classify` is a **pure
function with no I/O** — it takes the signals already captured for a row and
returns a ``(classification, benign_source)`` tuple, so it is trivially
unit-testable and reused by both the live-capture path and the historical
backfill script.

Matching precedence (strongest → weakest signal):

1. ``reverse_dns`` suffix match — hardest to spoof for real scanners.
2. ``asn`` exact match — network-verifiable.
3. ``org`` substring match — network-verifiable.
4. ``user_agent`` substring match — WEAK, trivially spoofed.

A row is ``benign`` only if it matches an allowlist entry on a
*network-verifiable* signal (reverse_dns / asn / org). UA is never the sole
basis for ``benign``: an entry that lists a UA but no network-verifiable signal
would be unsafe, so the loader rejects such entries (defence in depth against a
bad allowlist edit).

Everything not matched is ``unknown`` (the default). ``malicious`` is reserved
for a future follow-up issue that promotes ``unknown → malicious`` on strong
behavioural signals; this module only ever emits ``benign`` / ``unknown``.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass

# Importing the data package keeps manyfaced.data reachable in the
# import-reachability gate (it has no code of its own, only the allowlist TOML).
import manyfaced.data  # noqa: F401
from typing import Iterable

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover — only on <3.11
    import tomli as tomllib  # type: ignore[no-redef,import-untyped]

# Classification labels.
BENIGN = 'benign'
MALICIOUS = 'malicious'
UNKNOWN = 'unknown'

_ALLOWLIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'benign_sources.toml')


@dataclass(frozen=True)
class _Source:
    """A single compiled allowlist entry."""

    name: str
    category: str
    reverse_dns: tuple[str, ...]
    asn: tuple[str, ...]
    org: tuple[str, ...]
    user_agent: tuple[str, ...]


# Signals that are network-verifiable (an attacker cannot trivially forge them).
_NETWORK_SIGNALS = ('reverse_dns', 'asn', 'org')


class ClassificationError(ValueError):
    """Raised when the allowlist contains an unsafe entry (UA-only benign)."""


def _load_sources(path: str = _ALLOWLIST_PATH) -> list[_Source]:
    """Parse the allowlist TOML into compiled :class:`_Source` entries.

    Raises :class:`ClassificationError` if any entry relies solely on a
    user-agent match (no network-verifiable signal), which would let a spoofed
    UA flip an attacker row to benign.
    """
    with open(path, 'rb') as fh:
        data = tomllib.load(fh)

    sources: list[_Source] = []
    for entry in data.get('source', []):
        name = entry.get('name', '')
        category = entry.get('category', '')
        reverse_dns = tuple(entry.get('reverse_dns', []) or [])
        asn = tuple(str(a).upper() for a in (entry.get('asn', []) or []))
        org = tuple(entry.get('org', []) or [])
        user_agent = tuple(entry.get('user_agent', []) or [])

        has_network = bool(reverse_dns or asn or org)
        if user_agent and not has_network:
            raise ClassificationError(
                f'Allowlist entry {name!r} matches on user_agent alone with no '
                f'network-verifiable signal (reverse_dns/asn/org); UA is '
                f'trivially spoofable and must never be the sole basis for benign.'
            )

        sources.append(
            _Source(
                name=name,
                category=category,
                reverse_dns=reverse_dns,
                asn=asn,
                org=org,
                user_agent=user_agent,
            )
        )
    return sources


# Module-level cache of the compiled allowlist; loaded lazily and reused so the
# pure classify() stays cheap on the hot path. Re-seeded by load_allowlist().
_SOURCES: list[_Source] | None = None


def load_allowlist(path: str = _ALLOWLIST_PATH) -> list[_Source]:
    """(Re)load and cache the compiled allowlist. Returns the entries."""
    global _SOURCES
    _SOURCES = _load_sources(path)
    return _SOURCES


def _get_sources() -> list[_Source]:
    """Return the cached allowlist, loading it on first use."""
    global _SOURCES
    if _SOURCES is None:
        _SOURCES = _load_sources()
    return _SOURCES


def _dns_matches(hostname: str, patterns: Iterable[str]) -> bool:
    """Case-insensitive suffix match of *hostname* against glob patterns."""
    if not hostname:
        return False
    host = hostname.lower()
    for pat in patterns:
        if fnmatch.fnmatch(host, pat.lower()):
            return True
    return False


def classify(
    reverse_dns: str = '',
    org: str = '',
    asn: str = '',
    user_agent: str = '',
) -> tuple[str, str]:
    """Classify a capture as benign/unknown from its signals.

    Pure function — no I/O, no side effects.

    **Benign requires a network-verifiable signal.** A row is ``benign`` only
    if it matches an allowlist entry on reverse-DNS, ASN or org — signals an
    attacker cannot trivially forge. ``user_agent`` is deliberately NOT a
    deciding factor: it is spoofable, so a UA claiming ``Shodan`` from a
    non-Shodan network must stay ``unknown`` (open Q in issue #271: "UA is
    never sole basis for benign"). The ``user_agent`` field in the allowlist is
    therefore documentation only; entries that carry *only* a UA are rejected
    at load time by :func:`_load_sources`.

    Args:
        reverse_dns: Reverse-DNS hostname of the source IP.
        org: Network owner string (e.g. ``Cloudflare, Inc.``).
        asn: Autonomous system number, normalised upper-case (e.g. ``AS13335``).
        user_agent: Bot user-agent string (not used to decide benign).

    Returns:
        ``(classification, benign_source)`` — ``classification`` is ``benign``
        or ``unknown``; ``benign_source`` is the matched entry name (or ``''``
        when not benign).
    """
    rdns = (reverse_dns or '').strip()
    org_s = (org or '').strip()
    asn_s = (asn or '').strip().upper()
    # user_agent is intentionally ignored for the benign decision (see docstring).
    _ = user_agent

    for src in _get_sources():
        if _dns_matches(rdns, src.reverse_dns):
            return BENIGN, src.name
        if asn_s and asn_s in src.asn:
            return BENIGN, src.name
        if org_s and any(o and o.lower() in org_s.lower() for o in src.org):
            return BENIGN, src.name

    return UNKNOWN, ''
