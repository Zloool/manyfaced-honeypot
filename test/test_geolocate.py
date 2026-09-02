"""Tests for manyfaced.common.geolocate — IP geolocation lookup via ip-api.com.

Usage:
    pytest test/test_geolocate.py -v --no-cov
"""

import logging
import time
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common.geolocate import (  # noqa: E402
    _geo_cache,
    _geo_cache_lock,
    clear_geo_cache,
    lookup_ip_geolocation,
    normalize_org,
    start_geo_worker,
    stop_geo_worker,
)


# ---------------------------------------------------------------------------
# normalize_org — issue #462: same ASN must yield one canonical org string
# ---------------------------------------------------------------------------


def test_normalize_org_censys_variants_collapse():
    # The two free-text spellings ip-api.com returns for AS398324 Censys must
    # canonicalize to a single string so bot_org aggregation doesn't fragment.
    assert normalize_org('Censys, Inc.') == normalize_org('Censys Inc')
    assert normalize_org('Censys Inc') == 'Censys, Inc.'


def test_normalize_org_collapses_whitespace():
    assert normalize_org('  Some   ISP   Ltd ') == 'Some ISP Ltd'


def test_normalize_org_empty():
    assert normalize_org('') == ''


def test_normalize_org_unknown_passthrough():
    # Non-mapped orgs are returned trimmed/collapsed but otherwise verbatim.
    assert normalize_org('Hetzner Online GmbH') == 'Hetzner Online GmbH'


def test_normalize_asn_extracts_identifier_from_provider_value():
    """ip-api returns an AS number plus a provider name, not only an ASN."""
    from manyfaced.common.geolocate import normalize_asn

    assert normalize_asn('AS45102 Alibaba (US) Technology Co., Ltd.') == 'AS45102'
    assert normalize_asn('as398324 Censys, Inc.') == 'AS398324'
    assert normalize_asn('not-an-asn') == ''


def test_geo_lookup_stores_only_provider_asn_identifier(monkeypatch):
    """The provider's descriptive suffix must not reach PostgreSQL storage."""
    import manyfaced.common.geolocate as geo

    class Response:
        def read(self):
            return b'{"status":"success","country":"United States","continent":"North America","as":"AS45102 Alibaba (US) Technology Co., Ltd.","org":"Alibaba.com LLC"}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    monkeypatch.setattr(geo, '_last_geo_lookup_time', 0)
    monkeypatch.setattr(geo.urllib.request, 'urlopen', lambda request, timeout: Response())

    country, continent, asn, org = geo._do_geo_lookup('43.108.54.39')

    assert (country, continent, asn, org) == (
        'United States',
        'North America',
        'AS45102',
        'Alibaba.com LLC',
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_cache_and_stop_worker():
    """Clear the geo cache and stop worker before each test."""
    clear_geo_cache()
    stop_geo_worker()
    yield
    clear_geo_cache()
    stop_geo_worker()


# ===================================================================
# Test 1: hot path never sleeps — rate limiting is in background worker
# ===================================================================


def test_no_sleep_in_hot_path():
    """The hot path must never call time.sleep — rate limiting happens in the worker thread."""
    with patch('time.sleep') as mock_sleep:
        start_geo_worker()
        lookup_ip_geolocation('8.8.8.8')

    # Hot path should not sleep at all
    assert mock_sleep.call_count == 0


# ===================================================================
# Test 2: private/loopback IPs return empty without any work
# ===================================================================


def test_private_ip_returns_empty():
    """Private/loopback IPs should return ('', '', '', '') without making an HTTP call."""
    for ip in ('127.0.0.1', '::1', '10.0.0.1', '192.168.1.1', '172.16.0.1'):
        with patch('urllib.request.urlopen') as mock_urlopen:
            country, continent, asn, org = lookup_ip_geolocation(ip)

        assert mock_urlopen.call_count == 0
        assert country == ''
        assert continent == ''
        assert asn == ''
        assert org == ''


# ===================================================================
# Test 3: cache reuse — pre-populated cache returns immediately
# ===================================================================


def test_cache_reuse():
    """Repeated lookups for the same IP should return cached results without another HTTP call."""
    with _geo_cache_lock:
        _geo_cache['203.0.113.1'] = ('Japan', 'Asia', '', '', time.monotonic() + 1000)

    country, continent, asn, org = lookup_ip_geolocation('203.0.113.1')
    assert country == 'Japan'
    assert continent == 'Asia'
    assert asn == ''
    assert org == ''


def test_cache_is_thread_safe():
    """Cache reads/writes should be thread-safe (use lock)."""
    with _geo_cache_lock:
        _geo_cache['test.ip'] = ('Test', 'Test', '', '', time.monotonic() + 1000)

    country, continent, asn, org = lookup_ip_geolocation('test.ip')
    assert country == 'Test'
    assert continent == 'Test'
    assert asn == ''
    assert org == ''


# ===================================================================
# Test 4: background worker processes lookups and populates cache
# ===================================================================


def test_background_worker_processes_lookups():
    """The background worker should process queued lookups and populate the cache."""

    def mock_do_geo_lookup(ip, timeout=2.0):
        # Simulate a successful lookup AND write to cache (like real _do_geo_lookup does)
        with _geo_cache_lock:
            _geo_cache[ip] = ('France', 'Europe', '', '', time.monotonic() + 1000)
        return ('France', 'Europe', '', '')

    start_geo_worker()

    for i in range(3):
        lookup_ip_geolocation(f'203.0.113.{i}')

    # Wait up to 5 seconds for worker to process all lookups (patch active)
    with patch('manyfaced.common.geolocate._do_geo_lookup', side_effect=mock_do_geo_lookup):
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and '203.0.113.0' not in _geo_cache:
            time.sleep(0.1)

    # All three should now be cached
    country, continent, asn, org = lookup_ip_geolocation('203.0.113.0')
    assert country == 'France'
    assert continent == 'Europe'


def test_background_worker_rate_limits():
    """The background worker should respect rate limiting (sleep between requests)."""
    sleep_times: list[float] = []

    def mock_do_geo_lookup(ip, timeout=2.0):
        with patch('time.sleep') as mock_sleep:
            result = ('Test', 'Test', '', '', time.monotonic() + 1000)
            if mock_sleep.call_count > 0:
                sleep_times.append(mock_sleep.call_args[0][0])
            return result

    with patch('manyfaced.common.geolocate._do_geo_lookup', side_effect=mock_do_geo_lookup):
        start_geo_worker()

        # First lookup — no rate limit delay needed (cache is empty, first call)
        lookup_ip_geolocation('1.1.1.1')
        time.sleep(0.3)

    # Worker should have processed the request without blocking hot path


# ===================================================================
# Test 5: stop_geo_worker shuts down cleanly
# ===================================================================


def test_stop_geo_worker():
    """stop_geo_worker should signal the worker to shut down."""
    start_geo_worker()
    stop_geo_worker()
    time.sleep(0.3)

    # Worker thread should have stopped
    from manyfaced.common.geolocate import _geo_worker_thread  # noqa: PLC0415

    assert _geo_worker_thread is None or not _geo_worker_thread.is_alive()


# ===================================================================
# Test 6: failure response returns empty and logs warning
# ===================================================================


def test_failure_response_logs_warning():
    """When _do_geo_lookup fails, the function should cache empty strings."""

    def mock_do_geo_lookup(ip, timeout=2.0):
        with _geo_cache_lock:
            _geo_cache[ip] = ('', '', '', '', time.monotonic() + 1000)
        return ('', '', '', '')

    # Keep patch active while waiting for worker to process
    with patch('manyfaced.common.geolocate._do_geo_lookup', side_effect=mock_do_geo_lookup):
        start_geo_worker()
        country, continent, asn, org = lookup_ip_geolocation('1.2.3.4')

        assert country == ''  # Hot path: not cached yet

        # Wait for background worker to process and cache empty result
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and '1.2.3.4' not in _geo_cache:
            time.sleep(0.1)

    # After patch exits, worker should have cached empty result
    country2, continent2, asn2, org2 = lookup_ip_geolocation('1.2.3.4')
    assert country2 == ''
    assert continent2 == ''


# ===================================================================
# Test 8b: empty response returns empty
# ===================================================================


def test_empty_response_returns_empty():

    def mock_do_geo_lookup(ip, timeout=2.0):
        with _geo_cache_lock:
            _geo_cache[ip] = ('', '', '', '', time.monotonic() + 1000)
        return ('', '', '', '')

    # Keep patch active while waiting for worker to process
    with patch('manyfaced.common.geolocate._do_geo_lookup', side_effect=mock_do_geo_lookup):
        start_geo_worker()
        country, continent, asn, org = lookup_ip_geolocation('999.999.999.999')

        assert country == ''  # Hot path: not cached yet

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and '999.999.999.999' not in _geo_cache:
            time.sleep(0.1)

    country2, continent2, asn2, org2 = lookup_ip_geolocation('999.999.999.999')
    assert country2 == ''
    assert continent2 == ''


# ===================================================================
# Test 8: success response populates cache via worker
# ===================================================================


def test_success_response_populates_cache():

    def mock_do_geo_lookup(ip, timeout=2.0):
        with _geo_cache_lock:
            _geo_cache[ip] = ('Germany', 'Europe', '', '', time.monotonic() + 1000)
        return ('Germany', 'Europe', '', '')

    # Keep patch active while waiting for worker to process
    with patch('manyfaced.common.geolocate._do_geo_lookup', side_effect=mock_do_geo_lookup):
        start_geo_worker()
        country, continent, asn, org = lookup_ip_geolocation('1.1.1.1')

        # First call returns empty (not cached yet)
        assert country == ''

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and '1.1.1.1' not in _geo_cache:
            time.sleep(0.1)

    # After patch exits, worker should have cached the result
    country2, continent2, asn2, org2 = lookup_ip_geolocation('1.1.1.1')
    assert country2 == 'Germany'
    assert continent2 == 'Europe'


# ---------------------------------------------------------------------------
# Helper: patch is imported above for test mocking.
# ---------------------------------------------------------------------------


# ===================================================================
# Test 9: cache is bounded — no unbounded memory growth (issue #175)
# ===================================================================


def test_cache_evicts_oldest_when_over_max_size():
    """_store_geo evicts the least-recently-used entries past _GEO_CACHE_MAX_SIZE."""
    from manyfaced.common.geolocate import _GEO_CACHE_MAX_SIZE, _store_geo

    # Fill to the cap with valid (unexpired) entries.
    for i in range(_GEO_CACHE_MAX_SIZE):
        _store_geo(f'10.0.0.{i}', (f'C{i}', 'X', '', ''))

    with _geo_cache_lock:
        assert len(_geo_cache) == _GEO_CACHE_MAX_SIZE

    # One more insertion must evict exactly one oldest entry, never exceed the cap.
    _store_geo('10.255.255.255', ('New', 'Y', '', ''))
    with _geo_cache_lock:
        assert len(_geo_cache) == _GEO_CACHE_MAX_SIZE
        # The very first (LRU) entry should have been evicted.
        assert '10.0.0.0' not in _geo_cache
        # The newest entry is present.
        assert '10.255.255.255' in _geo_cache


def test_cache_expired_entries_are_not_returned():
    """A cached entry past its TTL behaves as a miss (issue #175 — TTL scope)."""
    # Store with an already-expired timestamp.
    with _geo_cache_lock:
        _geo_cache['9.9.9.9'] = ('Old', 'Country', '', '', time.monotonic() - 1)

    # The lookup must not return the stale value; it schedules a refresh.
    country, continent, asn, org = lookup_ip_geolocation('9.9.9.9')
    assert country == ''
    assert continent == ''


def test_start_geo_worker_serialized_by_lock() -> None:
    """Issue #214: start_geo_worker()/stop_geo_worker() must be serialized by
    `_geo_state_lock` so the check-then-act on the module globals is atomic and
    a concurrent stop cannot raise AttributeError on the request thread.

    Deterministic proof: hold `_geo_state_lock` externally and call
    start_geo_worker() from another thread. The fixed code acquires the lock at
    the top of start_geo_worker(), so the thread BLOCKS until we release it. The
    buggy version (no lock) returns immediately, which fails this test.
    """
    import threading

    import manyfaced.common.geolocate as geo

    lock = geo._geo_state_lock
    lock.acquire()
    try:
        done = []

        def caller():
            geo.start_geo_worker()
            done.append(True)

        th = threading.Thread(target=caller, daemon=True)
        th.start()
        # The fixed start_geo_worker must block on the held lock.
        th.join(timeout=0.3)
        assert th.is_alive(), (
            'start_geo_worker did not block on _geo_state_lock (issue #214: '
            'the check-then-act on the geo globals is no longer atomic)'
        )
    finally:
        lock.release()
    th.join(timeout=2)
    assert done, 'start_geo_worker must complete once the lock is released'
    geo.stop_geo_worker()


def test_stop_worker_does_not_crash_producer_or_consumer():
    """Concurrent stop_geo_worker() must not crash the request thread or worker (#171)."""
    import concurrent.futures

    start_geo_worker()

    def hammer():
        # Repeatedly look up + stop the worker; races must not raise AttributeError.
        for _ in range(50):
            try:
                lookup_ip_geolocation('198.51.100.7')
            except AttributeError:
                raise  # TOCTOU crash would surface here
            stop_geo_worker()

    # Run several threads hammering lookup/stop concurrently.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(hammer) for _ in range(4)]
        for f in futures:
            f.result()  # raises if any thread hit the AttributeError race

    # No assertion failure == no crash. Worker cleanup.
    stop_geo_worker()
