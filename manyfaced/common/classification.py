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

Matching precedence (strongest → weakest *verifiable* signal):

1. ``reverse_dns`` suffix / exact-host match — hardest to spoof for real
   scanners. The recorded PTR is a network-verifiable fact.
2. ``asn`` exact match — network-verifiable.

**``org`` substring matching is intentionally NOT used for benign.** An org
string is spoofable (an attacker can register an org containing ``AWS``/``Azure``
etc.) and, critically, cloud-hosted attacker infrastructure overwhelmingly
*shares* the org/ASN of legitimate providers — so an org-substring allowlist
would flip real attacks to ``benign``. Only the reverse-DNS PTR (or an exact,
curated ASN) is trusted.

``user_agent`` substring match is WEAK and trivially spoofed, so it is
**never** a deciding factor for ``benign``.

A row is ``benign`` only if it matches an allowlist entry on a
*network-verifiable, non-spoofable* signal — reverse-DNS PTR suffix/exact-host
or an exact curated ASN. UA is never the sole basis for ``benign``: an entry
that lists a UA but no network-verifiable signal would be unsafe, so the loader
rejects such entries (defence in depth against a bad allowlist edit).

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


# Signals that are network-verifiable and NON-SPOOFABLE (an attacker cannot
# trivially forge them). NOTE: ``org`` is deliberately EXCLUDED — an org string
# Note: benign classification requires a reverse-DNS PTR match or an exact,
# curated ASN (see classify()). An org-substring allowlist is intentionally
# avoided because org is spoofable (an attacker can register an org containing
# 'AWS'/'Azure' etc.) and cloud-hosted attacker infra shares the org/ASN of
# legit providers, so an org-substring allowlist would flip real attacks to
# benign (issue #352).


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
    """Case-insensitive match of *hostname* against glob PTR patterns.

    Two match styles are supported so the allowlist can describe both:

    * **Suffix match** via glob patterns that contain a ``*`` or ``?``
      (e.g. ``*.censys-scanner.com`` matches ``49.146.94.167.censys-scanner.com``).
    * **Exact-host match** for patterns without glob metacharacters
      (e.g. ``scan.visionheight.com`` matches only that precise PTR).

    A recorded reverse-DNS PTR is a network-verifiable fact, so either style is
    a trustworthy benign signal.
    """
    if not hostname:
        return False
    host = hostname.lower()
    for pat in patterns:
        pat_l = pat.lower()
        if '*' in pat_l or '?' in pat_l:
            if fnmatch.fnmatch(host, pat_l):
                return True
        elif host == pat_l:
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

    **Benign requires a network-verifiable, NON-SPOOFABLE signal.** A row is
    ``benign`` only if it matches an allowlist entry on reverse-DNS PTR or exact
    ASN — signals an attacker cannot trivially forge:

    1. ``reverse_dns`` — a recorded PTR suffix (glob, e.g. ``*.shodan.io``) or an
       exact PTR host (e.g. ``scan.visionheight.com``). The PTR is a
       network-verifiable fact, so it is the strongest benign signal.
    2. ``asn`` — an exact, curated ASN (e.g. ``AS398324``).

    **``org`` is intentionally NOT used to decide benign (issue #352).** An org
    string is spoofable (an attacker can register an org containing ``AWS`` /
    ``Azure`` etc.) and, critically, cloud-hosted attacker infrastructure
    overwhelmingly shares the org/ASN of legitimate providers — so an
    org-substring allowlist would flip real attacks to ``benign``. A row tagged
    ``DigitalOcean, LLC`` / ``AWS EC2`` / ``Google LLC`` / ``Microsoft Azure`` in
    prod with an EMPTY PTR must therefore stay ``unknown`` unless its PTR or ASN
    independently matches the curated allowlist.

    ``user_agent`` is deliberately NOT a deciding factor: it is spoofable, so a
    UA claiming ``Shodan`` from a non-Shodan network must stay ``unknown``. The
    ``user_agent`` field in the allowlist is therefore documentation only;
    entries that carry *only* a UA are rejected at load time by
    :func:`_load_sources`.

    Args:
        reverse_dns: Reverse-DNS hostname (PTR) of the source IP.
        org: Network owner string (e.g. ``Cloudflare, Inc.``) — NOT used to
            decide benign (see above).
        asn: Autonomous system number, normalised upper-case (e.g. ``AS13335``).
        user_agent: Bot user-agent string (not used to decide benign).

    Returns:
        ``(classification, benign_source)`` — ``classification`` is ``benign``
        or ``unknown``; ``benign_source`` is the matched entry name (or ``''``
        when not benign).
    """
    rdns = (reverse_dns or '').strip()
    # org is intentionally NOT consulted for the benign decision (issue #352):
    # it is spoofable and cloud-hosted attacker infra shares provider orgs.
    _ = org
    asn_s = (asn or '').strip().upper()
    # user_agent is intentionally ignored for the benign decision (see docstring).
    _ = user_agent

    for src in _get_sources():
        if _dns_matches(rdns, src.reverse_dns):
            return BENIGN, src.name
        if asn_s and asn_s in src.asn:
            return BENIGN, src.name

    return UNKNOWN, ''
