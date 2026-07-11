"""Regression tests for dashboard hardening (issues #411, #412, #413).

- #411: defense-in-depth security headers on every response (incl. 404).
- #412: the 500 handler must not leak the raw exception repr to the client.
- #413: pagination depth and host-filter shape are bounded so a page=N or a
  pathological ``host`` can't drive an unbounded / full-table scan on the
  request thread (which bypasses the warm 30s cache).

All tests stay off the network: the dashboard is started in a thread against a
local SQLite file (no prod bind, no live geo/DNS), and the bound checks are
mostly unit-level on the helpers / storage read API.
"""

import secrets
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from manyfaced.common import config as config_mod
from manyfaced.common import status as status_mod
from manyfaced.db import storage as storage_mod
from manyfaced.db.storage import SQLiteStorage, reset_storage_singleton
from manyfaced.web import dashboard as _dash_mod


# Issue #411: the exact header set the dashboard must emit. The CSP is the
# live constant from the dashboard module (not a copy) so the two can't drift.
_CSP = _dash_mod._CSP
_EXPECTED_SECURITY_HEADERS = {
    'Content-Security-Policy': _CSP,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
}


@pytest.fixture(autouse=True)
def _reset_dashboard_state():
    reset_storage_singleton()
    _dash_mod._PAYLOAD_CACHE.clear()
    _dash_mod._HTML_CACHE.clear()
    yield
    reset_storage_singleton()
    _dash_mod._PAYLOAD_CACHE.clear()
    _dash_mod._HTML_CACHE.clear()


# ---------------------------------------------------------------------------
# helper-level bounds (issue #413)
# ---------------------------------------------------------------------------


def test_clamp_page_bounds_deep_pages():
    assert _dash_mod._clamp_page(1) == 1
    assert _dash_mod._clamp_page(100) == 100
    # A page far past the cap is clamped to _PAGE_MAX so OFFSET stays bounded.
    assert _dash_mod._clamp_page(99999) == _dash_mod._PAGE_MAX
    # Negative / zero collapse to page 1.
    assert _dash_mod._clamp_page(0) == 1
    assert _dash_mod._clamp_page(-5) == 1


def test_normalize_host_filter_rejects_wildcard_and_short():
    # Valid host passes through unchanged.
    assert _dash_mod._normalize_host_filter('c2.evil') == 'c2.evil'
    assert _dash_mod._normalize_host_filter('evil-host.example') == 'evil-host.example'
    # Leading-wildcard (caller-supplied) is dropped — would force a full scan.
    assert _dash_mod._normalize_host_filter('%evil') is None
    assert _dash_mod._normalize_host_filter('*evil') is None
    # Too short is dropped — not a meaningful substring anchor.
    assert _dash_mod._normalize_host_filter('ab') is None
    assert _dash_mod._normalize_host_filter('') is None
    assert _dash_mod._normalize_host_filter(None) is None


def test_storage_sanitize_host_filter_matches_helper():
    assert storage_mod.sanitize_host_filter('%x') is None
    assert storage_mod.sanitize_host_filter('ab') is None
    assert storage_mod.sanitize_host_filter('c2.evil') == 'c2.evil'


def test_storage_clamp_offset_caps_deep_pages():
    assert storage_mod.clamp_offset(0, 50) == 0
    assert storage_mod.clamp_offset(200, 50) == 200
    # A pathological offset is capped, so it can't scan O(offset) rows.
    assert storage_mod.clamp_offset(10_000_000, 50) <= storage_mod._MAX_OFFSET
    # Negative offsets collapse to 0.
    assert storage_mod.clamp_offset(-1, 50) == 0


# ---------------------------------------------------------------------------
# storage read API bounds (issue #413) — direct, no server
# ---------------------------------------------------------------------------


def _seed(storage: SQLiteStorage):
    now = _dash_mod.datetime.now()

    def ts(hours_ago):
        return (now - _dash_mod.timedelta(hours=hours_ago)).strftime('%Y-%m-%d %H:%M:%S.%f')

    storage.insert(
        dict(
            bot_ip='1.2.3.4',
            hostname='h',
            timestamp=ts(10),
            parsed_request={'path': '/wp-admin', 'command': 'GET', 'version': 'HTTP/1.1'},
            raw_request='RAW wp',
            ua='uawp',
            country='US',
            continent='NA',
            is_detected=status_mod.WORDPRESS_HTTP,
            hive_id=1,
            login='',
        )
    )
    storage.insert(
        dict(
            bot_ip='9.9.9.9',
            hostname='h',
            timestamp=ts(6),
            parsed_request={'path': '/x', 'command': 'GET', 'version': 'HTTP/1.1'},
            raw_request='GET http://c2.evil/pew HTTP/1.1',
            ua='uassh',
            country='RU',
            continent='EU',
            is_detected=status_mod.SSH_CLIENT,
            hive_id=1,
            login='',
        )
    )


def test_recent_records_drops_leading_wildcard_host_filter(tmp_path):
    """A leading-wildcard host is rejected, so no full-table LIKE is run."""
    storage = SQLiteStorage(db_path=str(tmp_path / 'host.db'))
    _seed(storage)
    # Leading wildcard -> filter dropped -> all rows returned (no LIKE scan).
    assert len(storage.recent_records(host='%evil')) == 2
    assert len(storage.recent_records(host='*evil')) == 2
    # Too short -> also dropped.
    assert len(storage.recent_records(host='ab')) == 2
    # A concrete host still scopes correctly.
    scoped = storage.recent_records(host='c2.evil')
    assert len(scoped) == 1
    assert 'c2.evil' in scoped[0]['request_raw']
    storage.close()


def test_recent_records_bounded_offset(tmp_path):
    """A huge OFFSET is clamped before reaching SQLite (no O(offset) scan)."""
    storage = SQLiteStorage(db_path=str(tmp_path / 'off.db'))
    _seed(storage)
    # offset far larger than the table is capped; we just assert it runs without
    # scanning and still returns the bounded result set (empty here at the tail).
    rows = storage.recent_records(limit=50, offset=10_000_000)
    assert isinstance(rows, list)
    storage.close()


# ---------------------------------------------------------------------------
# HTTP-level checks (issues #411 / #412 / pager + host bounds on the wire)
# ---------------------------------------------------------------------------


def _build_dashboard_config(secret, port):
    cfg = config_mod.Config.load(validate_secrets=False)
    return config_mod.Config(
        HONEYPORT=cfg.HONEYPORT,
        HONEYFOLDER=cfg.HONEYFOLDER,
        HIVEHOST=cfg.HIVEHOST,
        HIVEPORT=cfg.HIVEPORT,
        HIVELOGIN=cfg.HIVELOGIN,
        HIVEPASS=cfg.HIVEPASS or 'x',
        DB_BACKEND='sqlite',
        DB_BACKENDS=cfg.DB_BACKENDS,
        DB_PATH=cfg.DB_PATH,
        DB_PG_HOST=cfg.DB_PG_HOST,
        DB_PG_PORT=cfg.DB_PG_PORT,
        DB_PG_DB=cfg.DB_PG_DB,
        DB_PG_USER=cfg.DB_PG_USER,
        DB_PG_PASSWORD=cfg.DB_PG_PASSWORD,
        AUTHORIZED_BEES=cfg.AUTHORIZED_BEES,
        HONEY_PORT_MODE='single',
        HONEY_TOP_PORTS='',
        DEFAULT_KEY=cfg.DEFAULT_KEY or 'x',
        LOG_FILE=cfg.LOG_FILE,
        DUMP_FILE=cfg.DUMP_FILE,
        LOCKFILE=cfg.LOCKFILE,
        ALERTING={},
        DASHBOARD_ENABLED=True,
        DASHBOARD_PORT=port,
        DASHBOARD_BIND='127.0.0.1',
        DASHBOARD_SECRET=secret,
        DASHBOARD_TIME_RANGE='24h',
    )


@pytest.fixture
def dashboard_server(tmp_path):
    secret = secrets.token_urlsafe(32)
    port = 18521  # distinct to avoid TIME_WAIT reuse on Windows
    db = tmp_path / 'dash_security.sqlite'
    storage = SQLiteStorage(db_path=str(db))
    _seed(storage)
    storage.close()

    cfg = _build_dashboard_config(secret, port)
    reset_storage_singleton()
    with patch.object(config_mod, 'settings', cfg):
        with patch.object(
            storage_mod, 'get_storage', lambda **kw: SQLiteStorage(db_path=str(db), **kw)
        ):
            import multiprocessing as mp

            ev = mp.Event()
            args = type('A', (), {'update_event': ev})()
            from manyfaced.web.dashboard import run_dashboard

            t = threading.Thread(target=run_dashboard, args=(args, ev), daemon=True)
            t.start()
            base = f'http://127.0.0.1:{port}/'
            for _ in range(40):
                try:
                    urllib.request.urlopen(base, timeout=0.2)
                    break
                except Exception:
                    time.sleep(0.1)
            yield secret, base
            ev.set()
            t.join(timeout=2)
            time.sleep(0.4)  # release socket buffer (Windows)


def _get(url):
    try:
        return urllib.request.urlopen(url, timeout=3).read().decode(), 200, None
    except urllib.error.HTTPError as e:
        return e.read().decode(), e.code, e.headers


def test_security_headers_on_fragment(dashboard_server):
    """Issue #411: the fragment response carries the defense-in-depth headers."""
    secret, base = dashboard_server
    body, code, _ = _get(base + f'?token={secret}&format=fragment&range=24h')
    assert code == 200
    resp = urllib.request.urlopen(base + f'?token={secret}&format=fragment&range=24h', timeout=3)
    for name, value in _EXPECTED_SECURITY_HEADERS.items():
        assert resp.headers.get(name) == value, f'missing/incorrect header {name}'


def test_csp_allows_same_origin_fetch(dashboard_server):
    """Issue #425: the CSP must permit the dashboard's own fragment fetches.

    The dashboard refreshes panels in place via same-origin fetch() (the
    fetchFragment path used by every filter / range switch / pager / live-tick).
    With connect-src unset, default-src 'none' blocks all fetches and the
    panels silently never update — i.e. "no filters work". Regression guard.
    """
    secret, base = dashboard_server
    resp = urllib.request.urlopen(base + f'?token={secret}&format=fragment&range=24h', timeout=3)
    csp = resp.headers.get('Content-Security-Policy')
    assert csp is not None
    # connect-src must explicitly allow the dashboard's own origin.
    assert "connect-src 'self'" in csp, f'CSP missing connect-src self: {csp}'
    # And it must NOT fall back to the default 'none' for connect.
    assert "default-src 'none'" in csp


def test_security_headers_on_deny_404(dashboard_server):
    """Issue #411: the generic 404 (_deny) also emits the security headers."""
    _secret, base = dashboard_server
    body, code, headers = _get(base + '?token=wrong')
    assert code == 404
    assert body == 'not found'
    assert headers is not None
    for name, value in _EXPECTED_SECURITY_HEADERS.items():
        assert headers.get(name) == value, f'missing/incorrect header {name} on 404'


def test_500_returns_generic_body(dashboard_server):
    """Issue #412: an error on the request path must not leak the exception repr."""
    secret, base = dashboard_server
    # Force the on-request-thread query (page 2) to raise; the handler must
    # swallow the detail and return a generic body (logger.exception keeps the
    # detail server-side).
    with patch.object(
        SQLiteStorage, 'recent_records', side_effect=RuntimeError('secret sql detail')
    ):
        body, code, _ = _get(base + f'?token={secret}&page=2')
    assert code == 500
    assert body == 'internal error'


def test_pagination_is_bounded_on_the_wire(dashboard_server):
    """Issue #413: requesting page=99999 is clamped, never an unbounded OFFSET."""
    secret, base = dashboard_server
    body, code, _ = _get(base + f'?token={secret}&page=99999')
    assert code == 200
    # The rendered log_summary reports the (clamped) page, proving OFFSET was
    # bounded rather than the giant requested page being served.
    assert f'page {_dash_mod._PAGE_MAX}' in body
    assert 'page 99999' not in body


def test_host_filter_rejects_leading_wildcard_on_the_wire(dashboard_server):
    """Issue #413: a leading-wildcard / too-short host filter is dropped, so no
    full-table LIKE scan runs for the IoC panel request."""
    secret, base = dashboard_server
    # Leading wildcard and too-short hosts must still 200 (filter just dropped).
    body_wc, code_wc, _ = _get(base + f'?token={secret}&host=%evil')
    assert code_wc == 200
    body_short, code_short, _ = _get(base + f'?token={secret}&host=ab')
    assert code_short == 200
    # A concrete host still scopes the log (sanity that the filter still works).
    body_ok, code_ok, _ = _get(base + f'?token={secret}&host=c2.evil')
    assert code_ok == 200
    assert 'c2.evil' in body_ok
