"""IP geolocation lookup for honeypot bot tracking.

Uses ip-api.com free tier (no API key required, 45 req/min limit).
Falls back to empty strings on failure — never blocks the hot path.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Rate limiting: ip-api.com allows 45 requests per minute
_RATE_LIMIT_DELAY = 60 / 45  # ~1.33 seconds between requests
_last_geo_lookup_time: float = 0
_geo_cache: dict[str, dict] = {}


def lookup_ip_geolocation(ip: str, timeout: float = 2.0) -> tuple[str, str]:
    """Look up country and continent for an IP address.

    Uses ip-api.com free tier (no API key needed).
    Results are cached to avoid repeated lookups for the same IP.
    Rate-limited to stay within ip-api.com's 45 req/min limit.

    Args:
        ip: IP address string.
        timeout: HTTP request timeout in seconds.

    Returns:
        Tuple of (country_name, continent_name), e.g. ("United States", "North America").
        Returns ("", "") on any failure.
    """
    global _last_geo_lookup_time

    # Skip loopback/private IPs — they won't have meaningful geo data
    if ip in ('127.0.0.1', '::1') or ip.startswith(('10.', '192.168.', '172.')):
        return ('', '')

    # Check cache first
    cached = _geo_cache.get(ip)
    if cached:
        return (cached['country'], cached['continent'])

    # Rate limiting
    now = time.monotonic()
    elapsed = now - _last_geo_lookup_time
    if elapsed < _RATE_LIMIT_DELAY:
        wait_time = _RATE_LIMIT_DELAY - elapsed
        logger.debug('Geo lookup rate-limited, waiting %.1fs', wait_time)
        time.sleep(wait_time)

    try:
        import urllib.request

        url = f'http://ip-api.com/json/{ip}?fields=country,continent'
        req = urllib.request.Request(url, headers={'User-Agent': 'manyfaced-honeypot'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode())

        if data.get('status') == 'fail':
            logger.warning('Geo lookup returned failure for %s: %s', ip, data.get('message', ''))
            _geo_cache[ip] = {'country': '', 'continent': ''}
            return ('', '')

        country = data.get('country', '')
        continent = data.get('continent', '')
        _geo_cache[ip] = {'country': country, 'continent': continent}
        _last_geo_lookup_time = time.monotonic()
        return (country, continent)

    except Exception as e:
        logger.warning('Geo lookup failed for %s: %s', ip, e)

    # On failure, cache empty result to avoid repeated lookups
    _geo_cache[ip] = {'country': '', 'continent': ''}
    return ('', '')


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
    _geo_cache.clear()
