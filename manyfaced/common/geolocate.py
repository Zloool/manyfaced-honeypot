"""IP geolocation lookup for honeypot bot tracking.

Uses ip-api.com free tier (no API key required, 45 req/min limit).

Hot-path behavior:
- Cached results are returned immediately (zero latency).
- Uncached IPs return ("", "") instantly and a background worker is scheduled
  to perform the lookup asynchronously — never blocks the request handler.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request  # noqa: PLC0415 — imported at module level for test patching
from queue import Empty, Full, Queue

logger = logging.getLogger(__name__)

# Rate limiting: ip-api.com allows 45 requests per minute
_RATE_LIMIT_DELAY = 60 / 45  # ~1.33 seconds between requests
_last_geo_lookup_time: float = 0

# Bounded cache: a honeypot is hit by a high volume of distinct attacker IPs
# over its lifetime, so an unbounded module-level dict would grow monotonically
# and eventually OOM (see issue #175). Entries expire after _GEO_CACHE_TTL
# seconds and the dict is capped at _GEO_CACHE_MAX_SIZE entries (LRU eviction).
_GEO_CACHE_TTL = 24 * 60 * 60  # 24h
_GEO_CACHE_MAX_SIZE = 10_000
# value -> (country, continent, asn, org, expires_at)
_geo_cache: dict[str, tuple[str, str, str, str, float]] = {}
_geo_cache_lock = threading.Lock()

# Background worker for async geo lookups
_geo_queue: Queue[tuple[str, float] | None] | None = None
_geo_worker_thread: threading.Thread | None = None
# Serializes start/stop/lookup against the module globals so check-then-act
# on _geo_queue / _geo_worker_thread is atomic (issue #214 — completes the
# #171 TOCTOU fix that only guarded _geo_worker_loop()).
_geo_state_lock = threading.Lock()


# Canonical org strings for known scanners whose free-text org from ip-api.com
# arrives with inconsistent punctuation/spacing across responses (issue #462).
# The KEY is the collapsed-whitespace, case-folded, punctuation-stripped form of
# the raw org; the VALUE is the single canonical spelling. This dedupes the same
# ASN's org into one bucket for grouping/aggregation WITHOUT being used for the
# benign decision (benign is still PTR/ASN-only — issue #352).
_ORG_CANONICAL_MAP: dict[str, str] = {
    'censys inc': 'Censys, Inc.',
    'onyphe sas': 'Onyphe SAS',
    'modat bv': 'Modat B.V.',
}


def normalize_org(org: str) -> str:
    """Normalize a free-text network-owner (org) string for consistent grouping.

    ip-api.com returns the org field with inconsistent punctuation/spacing across
    responses (e.g. ``Censys, Inc.`` vs ``Censys Inc``), which fragments any
    ``bot_org``-based aggregation. This collapses internal whitespace and trims,
    then applies a small canonicalization map for known scanners so the same ASN
    yields one org string (issue #462).

    This is a *reporting/aggregation* normalization only — it is NEVER consulted
    for the benign classification decision (that stays PTR/ASN-only, issue #352).
    """
    if not org:
        return ''
    # Collapse internal whitespace and trim.
    collapsed = ' '.join(org.split())
    # Build the lookup key: case-folded, punctuation stripped.
    key = ''.join(c for c in collapsed.lower() if c.isalnum() or c.isspace())
    key = ' '.join(key.split())
    return _ORG_CANONICAL_MAP.get(key, collapsed)


def lookup_ip_geolocation(ip: str, timeout: float = 2.0) -> tuple[str, str, str, str]:
    """Look up geo + network attributes for an IP address.

    Uses ip-api.com free tier (no API key needed). The free tier returns
    ``country``, ``continent``, ``as`` (ASN, e.g. ``AS13335``) and ``org``
    (organisation, e.g. ``Cloudflare, Inc.``) in the *same* request — adding
    ``as``/``org`` costs no extra request or rate-limit budget.

    Results are cached to avoid repeated lookups for the same IP.
    Rate-limited to stay within ip-api.com's 45 req/min limit.

    **Hot-path safe:** if the IP is not yet cached, returns empty strings
    immediately and schedules a background lookup via start_geo_worker(). The
    actual geo data will be available on subsequent requests after the worker
    completes.

    Args:
        ip: IP address string.
        timeout: HTTP request timeout in seconds (used only for background lookups).

    Returns:
        Tuple of (country_name, continent_name, asn, org). Returns
        (``, ``, ``, ``) on any failure or if not yet cached.
    """
    global _last_geo_lookup_time

    # Skip loopback/private IPs — they won't have meaningful geo data
    if ip in ('127.0.0.1', '::1') or ip.startswith(('10.', '192.168.', '172.')):
        return ('', '', '', '')

    # Check cache first (thread-safe); entries past their TTL are treated as
    # a miss so stale geo data is eventually refreshed and memory is reclaimed.
    now = time.monotonic()
    with _geo_cache_lock:
        entry = _geo_cache.get(ip)
        if entry is not None and entry[4] > now:
            # Move to the end to mark as most-recently-used (LRU).
            del _geo_cache[ip]
            _geo_cache[ip] = entry
            return entry[0], entry[1], entry[2], entry[3]

    # Not cached — schedule background lookup and return empty immediately.
    # Capture the queue under the state lock so a concurrent stop_geo_worker()
    # can't leave us holding a stale/None reference (issue #214).
    queue = start_geo_worker()
    if queue is None:  # Worker failed to start; don't block the hot path
        return ('', '', '', '')
    queue.put((ip, timeout))  # noqa: SLF001
    return ('', '', '', '')


def _do_geo_lookup(ip: str, timeout: float = 2.0) -> tuple[str, str, str, str]:
    """Perform the actual HTTP geolocation lookup (called by worker thread)."""
    global _last_geo_lookup_time

    # Rate limiting — sleep in the worker thread so it doesn't block the hot path
    now = time.monotonic()
    elapsed = now - _last_geo_lookup_time
    if elapsed < _RATE_LIMIT_DELAY:
        wait_time = _RATE_LIMIT_DELAY - elapsed
        logger.debug('Geo lookup rate-limited, waiting %.1fs', wait_time)
        time.sleep(wait_time)

    try:
        # Request country/continent/as/org in one free-tier call — ip-api.com
        # returns all four without extra rate-limit cost (issue #271).
        url = f'http://ip-api.com/json/{ip}?fields=country,continent,as,org'
        req = urllib.request.Request(url, headers={'User-Agent': 'manyfaced-honeypot'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode())

        if data.get('status') == 'fail':
            logger.warning('Geo lookup returned failure for %s: %s', ip, data.get('message', ''))
            result = ('', '', '', '')
        else:
            country = data.get('country', '')
            continent = data.get('continent', '')
            asn = data.get('as', '') or ''
            org = normalize_org(data.get('org', '') or '')
            result = (country, continent, asn, org)

        # Update cache and rate-limit timestamp
        _store_geo(ip, result)
        _last_geo_lookup_time = time.monotonic()
        return result

    except Exception as e:
        logger.warning('Geo lookup failed for %s: %s', ip, e)
        # Observability: count geo-lookup failures (issue #166).
        from manyfaced.common.metrics import incr

        incr('geo_lookup_failure')
        # On failure, cache empty result to avoid repeated lookups
        _store_geo(ip, ('', '', '', ''))
        return ('', '', '', '')


def _store_geo(ip: str, result: tuple[str, str, str, str]) -> None:
    """Store a geo result in the bounded, TTL-scoped cache.

    Marks the entry as most-recently-used and evicts the oldest entries when
    the cache exceeds ``_GEO_CACHE_MAX_SIZE`` (LRU eviction) — this caps process
    memory regardless of how many distinct attacker IPs are seen (issue #175).
    """
    expires_at = time.monotonic() + _GEO_CACHE_TTL
    with _geo_cache_lock:
        _geo_cache.pop(ip, None)
        if len(_geo_cache) >= _GEO_CACHE_MAX_SIZE:
            # Evict the oldest entries; dicts preserve insertion order so the
            # first key is the least-recently-used.
            evict_count = len(_geo_cache) - _GEO_CACHE_MAX_SIZE + 1
            for stale_ip in list(_geo_cache)[:evict_count]:
                _geo_cache.pop(stale_ip, None)
        _geo_cache[ip] = (result[0], result[1], result[2], result[3], expires_at)


def start_geo_worker() -> Queue[tuple[str, float] | None] | None:
    """Start the background geolocation worker thread if not already running.

    Returns the live queue (never None on success) so callers can enqueue
    without re-reading the module global (issue #214). Callers must treat a
    None return as "worker unavailable".
    """
    global _geo_queue, _geo_worker_thread

    with _geo_state_lock:
        # Capture to a local first: a concurrent stop_geo_worker() setting the
        # global to None between the `is not None` check and `.is_alive()` would
        # otherwise raise AttributeError on the request-handling thread.
        worker = _geo_worker_thread
        if worker is not None and worker.is_alive():
            return _geo_queue

        queue: Queue[tuple[str, float] | None] = Queue()
        _geo_queue = queue
        _geo_worker_thread = threading.Thread(target=_geo_worker_loop, daemon=True)
        _geo_worker_thread.start()
        return queue


def _geo_worker_loop() -> None:
    """Background worker loop that processes geo lookup requests from the queue."""
    while True:
        try:
            queue = _geo_queue
            if queue is None:
                break  # Queue was destroyed during shutdown
            item = queue.get(timeout=1.0)  # Periodic wake to check for shutdown
            if item is None:
                break  # Shutdown signal
            ip, timeout = item
            _do_geo_lookup(ip, timeout=timeout)
        except Empty:
            continue
        except AttributeError:
            # _geo_queue was reset to None concurrently with the local capture;
            # treat as shutdown signal rather than crashing the worker (issue #171).
            break


def stop_geo_worker() -> None:
    """Signal the background geo worker to shut down."""
    global _geo_queue, _geo_worker_thread

    # Capture under the state lock so the queue we signal can't be swapped to a
    # new one (and the worker reference can't race) mid-shutdown (issue #214).
    with _geo_state_lock:
        queue = _geo_queue
        if queue is not None:
            # Unconditionally signal shutdown; swallow a full/closed queue rather
            # than masking other errors with a blanket except.
            try:
                queue.put(None, block=False)  # Shutdown signal
            except (Full, OSError):
                # Queue full or closed during shutdown — drop the signal rather
                # than masking unrelated errors.
                pass
        _geo_queue = None
        _geo_worker_thread = None


def batch_lookup_geolocation(
    ips: list[str], max_concurrent: int = 5
) -> dict[str, tuple[str, str, str, str]]:
    """Look up geolocation for multiple IPs.

    Useful for post-processing or analysis scripts.

    Args:
        ips: List of IP addresses to look up.
        max_concurrent: Max concurrent requests (ip-api.com doesn't support batch).

    Returns:
        Dict mapping IP -> (country, continent, asn, org) tuples.
    """
    results = {}
    for ip in ips:
        country, continent, asn, org = lookup_ip_geolocation(ip)
        results[ip] = (country, continent, asn, org)
    return results


def clear_geo_cache() -> None:
    """Clear the geolocation cache."""
    global _geo_cache
    with _geo_cache_lock:
        _geo_cache.clear()
