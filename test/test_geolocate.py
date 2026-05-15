"""Tests for manyfaced.common.geolocate — IP geolocation lookup via ip-api.com.

Usage:
    pytest test/test_geolocate.py -v --no-cov
"""

import logging
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
import os, sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common.geolocate import lookup_ip_geolocation, clear_geo_cache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_cache():
    """Clear the geo cache before each test to avoid cross-test pollution."""
    clear_geo_cache()
    yield
    clear_geo_cache()


# ===================================================================
# Test 1: field-restricted success response (no status key) extracts correctly
# ===================================================================

def test_field_restricted_success_no_status_key():
    """ip-api.com omits 'status' from successful responses when fields= is used.
    
    The code must treat a missing status as success and extract country/continent.
    Response shape: {"country": "United States", "continent": "North America"}
    """
    mock_response = b'{"country": "United States", "continent": "North America"}'

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        mock_urlopen.return_value = mock_resp

        country, continent = lookup_ip_geolocation('8.8.8.8')

    assert country == 'United States'
    assert continent == 'North America'


# ===================================================================
# Test 2: explicit failure response returns ('', '') and logs WARNING
# ===================================================================

def test_failure_response_logs_warning():
    """When ip-api.com returns status='fail', the function should log a warning,
    cache empty strings, and return ('', '')."""
    mock_response = b'{"status": "fail", "message": "invalid query"}'

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        mock_urlopen.return_value = mock_resp

        with patch('manyfaced.common.geolocate.logger') as mock_logger:
            country, continent = lookup_ip_geolocation('1.2.3.4')

    assert country == ''
    assert continent == ''
    mock_logger.warning.assert_called_once()
    call_args = mock_logger.warning.call_args[0]
    assert 'Geo lookup returned failure' in call_args[0]


# ===================================================================
# Test 3: full-status success response still works (backward compat)
# ===================================================================

def test_full_status_success_response():
    """When ip-api.com returns a full response with status='success', the function
    should extract country and continent correctly. This covers any non-field-restricted
    call sites or future API changes."""
    mock_response = b'{"status": "success", "country": "Germany", "continent": "Europe"}'

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        mock_urlopen.return_value = mock_resp

        country, continent = lookup_ip_geolocation('1.1.1.1')

    assert country == 'Germany'
    assert continent == 'Europe'


# ===================================================================
# Additional edge-case tests
# ===================================================================

def test_empty_response_returns_empty():
    """ip-api.com returns {} for invalid IPs — no status key, no data."""
    mock_response = b'{}'

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        mock_urlopen.return_value = mock_resp

        country, continent = lookup_ip_geolocation('999.999.999.999')

    assert country == ''
    assert continent == ''


def test_cache_reuse():
    """Repeated lookups for the same IP should return cached results without another HTTP call."""
    mock_response = b'{"country": "Japan", "continent": "Asia"}'

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        mock_urlopen.return_value = mock_resp

        lookup_ip_geolocation('203.0.113.1')
        country2, continent2 = lookup_ip_geolocation('203.0.113.1')

    # Second call should not trigger another HTTP request
    assert mock_urlopen.call_count == 1
    assert country2 == 'Japan'
    assert continent2 == 'Asia'


def test_private_ip_returns_empty():
    """Private/loopback IPs should return ('', '') without making an HTTP call."""
    for ip in ('127.0.0.1', '::1', '10.0.0.1', '192.168.1.1', '172.16.0.1'):
        with patch('urllib.request.urlopen') as mock_urlopen:
            country, continent = lookup_ip_geolocation(ip)

        assert mock_urlopen.call_count == 0
        assert country == ''
        assert continent == ''


# ---------------------------------------------------------------------------
# Helper: MagicMock is needed but not imported at module level to avoid
# pulling in urllib mocks before patching. Import here instead.
# ---------------------------------------------------------------------------
from unittest.mock import MagicMock
