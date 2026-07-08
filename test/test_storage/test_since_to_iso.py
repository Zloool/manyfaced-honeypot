"""Regression tests for ``_since_to_iso`` (issue #243 dashboard windowing).

The dashboard's ``_parse_range`` passes a *concrete* ISO-8601 cutoff into
``aggregate_stats(since=...)``, not a window token like ``'24h'``.
``_since_to_iso`` must pass those ISO strings through untouched, otherwise it
returns ``None`` (no WHERE clause) and every range shows the all-time total.
"""

from datetime import datetime

from manyfaced.db.storage import _since_to_iso


def test_none_is_unbounded():
    assert _since_to_iso(None) is None


def test_all_is_unbounded():
    assert _since_to_iso('all') is None


def test_window_token_is_converted():
    out = _since_to_iso('24h')
    assert out is not None
    # Must parse back as a valid timestamp cutoff.
    datetime.strptime(out, '%Y-%m-%d %H:%M:%S')


def test_iso_with_microseconds_passthrough():
    iso = '2026-07-08 21:00:00.123456'
    assert _since_to_iso(iso) == iso


def test_iso_without_microseconds_passthrough():
    iso = '2026-07-08 21:00:00'
    assert _since_to_iso(iso) == iso


def test_unknown_token_is_unbounded():
    assert _since_to_iso('bogus') is None
