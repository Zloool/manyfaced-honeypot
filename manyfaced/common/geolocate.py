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
from queue import Empty, Queue

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
# value -> (country, continent, expires_at)
_geo_cache: dict[str, tuple[str, str, float]] = {}
_geo_cache_lock = threading.Lock()

# Background worker for async geo lookups
_geo_queue: Queue[tuple[str, float] | None] | None = None
_geo_worker_thread: threading.Thread | None = None


def lookup_ip_geolocation(ip: str, timeout: float = 2.0) -> tuple[str, str]:
    """Look up country and continent for an IP address.

    Uses ip-api.com free tier (no API key needed).
    Results are cached to avoid repeated lookups for the same IP.
    Rate-limited to stay within ip-api.com's 45 req/min limit.

    **Hot-path safe:** if the IP is not yet cached, returns ("", "") immediately
    and schedules a background lookup via start_geo_worker(). The actual geo data
    will be available on subsequent requests after the worker completes.

    Args:
        ip: IP address string.
        timeout: HTTP request timeout in seconds (used only for background lookups).

    Returns:
        Tuple of (country_name, continent_name), e.g. ("United States", "North America").
        Returns ("", "") on any failure or if not yet cached.
    """
    global _last_geo_lookup_time

    # Skip loopback/private IPs — they won't have meaningful geo data
    if ip in ('127.0.0.1', '::1') or ip.startswith(('10.', '192.168.', '172.')):
        return ('', '')

    # Check cache first (thread-safe); entries past their TTL are treated as
    # a miss so stale geo data is eventually refreshed and memory is reclaimed.
    now = time.monotonic()
    with _geo_cache_lock:
        entry = _geo_cache.get(ip)
        if entry is not None and entry[2] > now:
            # Move to the end to mark as most-recently-used (LRU).
            del _geo_cache[ip]
            _geo_cache[ip] = entry
            return entry[0], entry[1]

    # Not cached — schedule background lookup and return empty immediately
    start_geo_worker()
    assert _geo_queue is not None  # type: ignore[assertion-error]
    _geo_queue.put((ip, timeout))  # noqa: SLF001
    return ('', '')


def _do_geo_lookup(ip: str, timeout: float = 2.0) -> tuple[str, str]:
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
        url = f'http://ip-api.com/json/{ip}?fields=country,continent'
        req = urllib.request.Request(url, headers={'User-Agent': 'manyfaced-honeypot'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode())

        if data.get('status') == 'fail':
            logger.warning('Geo lookup returned failure for %s: %s', ip, data.get('message', ''))
            result = ('', '')
        else:
            country = data.get('country', '')
            continent = data.get('continent', '')
            result = (country, continent)

        # Update cache and rate-limit timestamp
        _store_geo(ip, result)
        _last_geo_lookup_time = time.monotonic()
        return result

    except Exception as e:
        logger.warning('Geo lookup failed for %s: %s', ip, e)
        # On failure, cache empty result to avoid repeated lookups
        _store_geo(ip, ('', ''))
        return ('', '')


def _store_geo(ip: str, result: tuple[str, str]) -> None:
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
        _geo_cache[ip] = (result[0], result[1], expires_at)


def start_geo_worker() -> None:
    """Start the background geolocation worker thread if not already running."""
    global _geo_queue, _geo_worker_thread

    if _geo_worker_thread is not None and _geo_worker_thread.is_alive():
        return

    _geo_queue = Queue()
    _geo_worker_thread = threading.Thread(target=_geo_worker_loop, daemon=True)
    _geo_worker_thread.start()


def _geo_worker_loop() -> None:
    """Background worker loop that processes geo lookup requests from the queue."""
    while True:
        try:
            if _geo_queue is None:
                break  # Queue was destroyed during shutdown
            item = _geo_queue.get(timeout=1.0)  # Periodic wake to check for shutdown
            if item is None:
                break  # Shutdown signal
            ip, timeout = item
            _do_geo_lookup(ip, timeout=timeout)
        except Empty:
            continue


def stop_geo_worker() -> None:
    """Signal the background geo worker to shut down."""
    global _geo_queue, _geo_worker_thread

    if _geo_queue is not None:
        try:
            _geo_queue.put(None, block=False)  # Shutdown signal
        except Exception:
            pass
        _geo_queue = None

    _geo_worker_thread = None


def batch_lookup_geolocation(ips: list[str], max_concurrent: int = 5) -> dict[str, tuple[str, str]]:
    """Look up geolocation for multiple IPs.

    Useful for post-processing or analysis scripts.

    Args:
        ips: List of IP addresses to look up.
        max_concurrent: Max concurrent requests (ip-api.com doesn't support batch).

    Returns:
        Dict mapping IP -> (country, continent) tuples.
    """
    results = {}
    for ip in ips:
        country, continent = lookup_ip_geolocation(ip)
        results[ip] = (country, continent)
    return results


def clear_geo_cache() -> None:
    """Clear the geolocation cache."""
    global _geo_cache
    with _geo_cache_lock:
        _geo_cache.clear()
