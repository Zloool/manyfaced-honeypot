"""Tests for the read-only token-gated dashboard (issue #234) and the storage read API."""

import secrets
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
import urllib.error
import urllib.request

from manyfaced.common import config as config_mod
from manyfaced.common import status as status_mod
from manyfaced.common.config import Config
from manyfaced.db import storage as storage_mod
from manyfaced.db.storage import (
    SQLiteStorage,
    detected_id_name,
    is_detected,
    reset_storage_singleton,
)
from manyfaced.web import dashboard as _dash_mod


# Guarantee dashboard-test isolation across tests. The dashboard caches
# rendered payloads/page bytes in module-level globals (_PAYLOAD_CACHE /
# _HTML_CACHE) and reuses a process-wide storage singleton; a prior test that
# spun up run_dashboard can otherwise leak its (different) seeded DB into the
# next test's served payload (issue #234 test isolation).
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
# detected_id mapping
# ---------------------------------------------------------------------------


def test_detected_id_name_known_service():
    assert detected_id_name(status_mod.WORDPRESS_HTTP) == 'wordpress'
    assert detected_id_name(status_mod.PHPMYADMIN_HTTP) == 'phpmyadmin'
    assert detected_id_name(status_mod.BITRIX_HTTP) == 'bitrix'


def test_detected_id_name_sentinel():
    assert detected_id_name(status_mod.SSH_CLIENT) == 'ssh'
    assert detected_id_name(status_mod.EMPTY_CONNECTION) == 'empty_connection'
    assert detected_id_name(status_mod.UNKNOWN_VNC) == 'vnc'


def test_detected_id_name_unknown_and_none():
    assert detected_id_name(123456) == 'unknown'
    assert detected_id_name(None) == 'unknown'


def test_is_detected():
    assert is_detected(status_mod.WORDPRESS_HTTP)
    assert is_detected(status_mod.CONFIG_DISCLOSURE_HTTP)
    assert not is_detected(status_mod.SSH_CLIENT)
    assert not is_detected(None)


# ---------------------------------------------------------------------------
# storage read API (seeded via insert)
# ---------------------------------------------------------------------------


def _seed(storage: SQLiteStorage):
    # Timestamps are relative to "now" so the seeded rows always fall inside the
    # dashboard's rolling 24h capture-log window (recent_records filters by
    # vol_since = now-24h). Hardcoded fixed dates silently age out of the
    # window and make the rendering tests flaky depending on the run date.
    now = datetime.now()

    def ts(hours_ago: int) -> str:
        return (now - timedelta(hours=hours_ago)).strftime('%Y-%m-%d %H:%M:%S.%f')

    base = {
        'ip': '1.2.3.4',
        'hostname': 'h',
        'timestamp': ts(10),
        'parsed_request': {},
        'raw_request': 'RAW wp',
        'ua': 'uawp',
        'country': 'US',
        'continent': 'NA',
        'dns_name': 'dns',
        'is_detected': status_mod.WORDPRESS_HTTP,
        'hive_id': 1,
        'login': '',
    }
    storage.insert(
        dict(
            base,
            timestamp=ts(10),
            parsed_request={'path': '/wp-admin', 'command': 'GET', 'version': 'HTTP/1.1'},
            raw_request='RAW wp',
            country='US',
            continent='NA',
            is_detected=status_mod.WORDPRESS_HTTP,
            ua='uawp',
            dns_name='dns',
        )
    )
    storage.insert(
        dict(
            base,
            timestamp=ts(8),
            parsed_request={'path': '/phpmyadmin', 'command': 'GET', 'version': 'HTTP/1.1'},
            raw_request='RAW pm',
            country='US',
            continent='NA',
            is_detected=status_mod.PHPMYADMIN_HTTP,
            ua='uapm',
            dns_name='dns',
        )
    )
    storage.insert(
        dict(
            base,
            timestamp=ts(6),
            ip='9.9.9.9',
            parsed_request={},
            raw_request='RAW ssh',
            country='RU',
            continent='EU',
            is_detected=status_mod.SSH_CLIENT,
            ua='uassh',
            dns_name='dns',
        )
    )


def test_recent_records_returns_newest_first(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'r.db'))
    _seed(storage)
    recs = storage.recent_records(limit=10)
    assert len(recs) == 3
    # newest first (the SSH row is seeded last / most recent)
    assert recs[0]['bot_ip'] == '9.9.9.9'
    # timestamps are ordered descending
    assert recs[0]['timestamp'] >= recs[1]['timestamp'] >= recs[2]['timestamp']


def test_recent_records_limit(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'r2.db'))
    _seed(storage)
    assert len(storage.recent_records(limit=2)) == 2


def test_recent_records_since_filter(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'r3.db'))
    _seed(storage)
    # The most-recent seed row is ~6h old. A cutoff 7h ago (older than the 6h
    # row but newer than the 8h row) includes only it; a 5h-ago cutoff (newer
    # than every seeded row) excludes everything.
    cutoff_recent = (datetime.now() - timedelta(hours=7)).strftime('%Y-%m-%d %H:%M:%S.%f')
    cutoff_old = (datetime.now() - timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S.%f')
    recs = storage.recent_records(since=cutoff_recent)
    assert len(recs) == 1
    assert recs[0]['bot_ip'] == '9.9.9.9'
    assert len(storage.recent_records(since=cutoff_old)) == 0


def test_aggregate_stats(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'a.db'))
    _seed(storage)
    stats = storage.aggregate_stats()
    assert stats['total'] == 3
    assert stats['detected'] == 2
    assert stats['undetected'] == 1
    services = {row['key']: row['count'] for row in stats['by_service']}
    assert services['wordpress'] == 1
    assert services['phpmyadmin'] == 1
    assert services['ssh'] == 1
    # top source IPs
    ips = {row['key']: row['count'] for row in stats['by_ip']}
    assert ips['1.2.3.4'] == 2
    assert ips['9.9.9.9'] == 1
    # countries
    countries = {row['key']: row['count'] for row in stats['by_country']}
    assert countries['US'] == 2
    assert countries['RU'] == 1
    # volume series non-empty
    assert len(stats['volume']) >= 1


def test_aggregate_stats_empty(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'empty.db'))
    stats = storage.aggregate_stats()
    assert stats['total'] == 0
    assert stats['by_service'] == []


# ---------------------------------------------------------------------------
# config section
# ---------------------------------------------------------------------------


def test_generated_config_has_dashboard_section_with_secret():
    cfg = Config.load(validate_secrets=False)
    path = cfg.generate_config_file()
    text = path.read_text()
    assert '[dashboard]' in text
    assert 'enabled = false' in text
    # secret must be auto-generated and non-trivial (not a static default)
    import re

    m = re.search(r'secret = "([^"]+)"', text)
    assert m, 'dashboard secret line missing from generated config'
    secret = m.group(1)
    assert len(secret) >= 32
    # regenerate to confirm it's freshly generated each time
    path2 = cfg.generate_config_file()
    secret2 = re.search(r'secret = "([^"]+)"', path2.read_text()).group(1)
    assert secret2 != secret  # secrets.token_urlsafe -> unique each call


def test_config_loads_dashboard_fields_defaults():
    cfg = Config.load(validate_secrets=False)
    assert cfg.DASHBOARD_ENABLED is False
    assert cfg.DASHBOARD_PORT == 8443
    assert cfg.DASHBOARD_BIND == '127.0.0.1'
    assert isinstance(cfg.DASHBOARD_SECRET, str)
    assert cfg.DASHBOARD_TIME_RANGE == '24h'


# ---------------------------------------------------------------------------
# token-gated HTTP surface (spin up run_dashboard in a thread)
# ---------------------------------------------------------------------------


def _build_dashboard_config(secret, port):
    cfg = Config.load(validate_secrets=False)
    return Config(
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


def _free_port() -> int:
    # Fixed test port (avoid bind(0) probing, which exhausts the Windows
    # ephemeral-port buffer under rapid bind/close cycles). HTTPServer sets
    # allow_reuse_address=True so reuse is safe between sequential tests.
    return 18511


@pytest.fixture
def dashboard_server(tmp_path):
    secret = secrets.token_urlsafe(32)
    port = _free_port()
    db = tmp_path / 'dash.sqlite'
    storage = SQLiteStorage(db_path=str(db))
    _seed(storage)
    storage.close()

    cfg = _build_dashboard_config(secret, port)
    # Drop any cached storage singleton / rendered payloads so the get_storage
    # mock below is actually exercised (issue #234 test isolation).
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
            # wait for bind
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
            # Brief cooldown so the OS releases the socket buffer (Windows is
            # slow to reclaim ephemeral ports under rapid bind/close cycles).
            time.sleep(0.4)


def _get(url):
    try:
        return urllib.request.urlopen(url, timeout=3).read().decode(), 200
    except urllib.error.HTTPError as e:
        return e.read().decode(), e.code


def test_dashboard_token_gating(dashboard_server):
    """Missing/wrong tokens -> generic 404; valid token -> 200 with stats."""
    secret, base = dashboard_server
    no_token, code_missing = _get(base)
    assert code_missing == 404
    bad, code_bad = _get(base + '?token=wrong')
    assert code_bad == 404
    body, code_ok = _get(base + f'?token={secret}')
    assert code_ok == 200
    assert 'wordpress' in body
    assert 'phpmyadmin' in body
    assert 'ssh' in body


def test_dashboard_fragment_requires_token(dashboard_server):
    """The fragment endpoint is the same token-gated route, not a separate open one."""
    _secret, base = dashboard_server
    body, code = _get(base + '?format=fragment&range=24h')
    assert code == 404
    assert body == 'not found'


def test_dashboard_fragment_returns_boundary_delimited_sections(dashboard_server):
    """format=fragment returns a random-boundary payload with vol/intel/log/meta chunks."""
    secret, base = dashboard_server
    body, code = _get(base + f'?token={secret}&format=fragment&range=24h')
    assert code == 200
    lines = body.split('\n', 1)
    boundary = lines[0]
    assert boundary.startswith('MFB')
    assert f'{boundary}:vol-box\n' in body
    assert f'{boundary}:intel-grid\n' in body
    assert f'{boundary}:log-rows\n' in body
    assert f'{boundary}:meta\n' in body
    assert 'wordpress' in body


def test_dashboard_fragment_invalid_range_falls_back(dashboard_server):
    """An unrecognised ?range= value must not 500 — falls back to 24h."""
    secret, base = dashboard_server
    body, code = _get(base + f'?token={secret}&format=fragment&range=not-a-range')
    assert code == 200
    assert 'MFB' in body.splitlines()[0]


def test_dashboard_volume_bars_rise_with_data():
    """Bars must carry a real (non-floor) height when data exists, and the
    chart must have a definite height so the percentage chain resolves.

    Regression guard for the broken-volume-graph bug: with only min-height on
    .vol-chart the bar heights (height:N%) collapsed to the 2px min-height, so
    numbers rendered but bars never rose.
    """
    from manyfaced.web import dashboard_render as dr
    from manyfaced.web import dashboard_assets as da

    bars = [
        {'start': 0, 'end': 1, 'label': '0h', 'count': 3},
        {'start': 1, 'end': 2, 'label': '1h', 'count': 30},
        {'start': 2, 'end': 3, 'label': '2h', 'count': 1},
    ]
    payload = {'volume_bars': bars}
    box = dr.render_vol_box(payload)
    # Tallest bar should exceed the 2% floor (30 vs max 30 -> 100%).
    heights = [float(h) for h in __import__('re').findall(r'height:([\d.]+)%', box)]
    assert heights, 'no bar heights emitted'
    assert max(heights) >= 99.0, f'tallest bar did not rise: {heights}'
    # Chart must have a definite pixel height for the % chain to resolve.
    assert 'height:200px' in da.CSS


def test_dashboard_fragment_port_filter_scopes_volume(dashboard_server):
    """?port=<n> recomputes the volume bars without erroring for an unknown/empty port."""
    secret, base = dashboard_server
    body, code = _get(base + f'?token={secret}&format=fragment&range=24h&port=80')
    assert code == 200
    boundary = body.splitlines()[0]
    assert f'{boundary}:vol-box\n' in body


def test_dashboard_escapes_raw_capture(tmp_path):
    """Raw captures must be HTML-escaped so a captured <script> can't execute."""
    import sqlite3

    secret = secrets.token_urlsafe(32)
    port = 18512  # distinct from the fixture's port (18511) to avoid TIME_WAIT reuse on Windows
    db = tmp_path / 'dash_inject.sqlite'
    # The basetemp dir is reused across runs, so a leftover db from a prior run
    # would otherwise leak rows into this test. Start from a clean file.
    if db.exists():
        db.unlink()
    # Seed with an HTML-injection payload BEFORE the server starts (no concurrent
    # writer, which would block on the WAL DB under load).
    storage = SQLiteStorage(db_path=str(db))
    storage.insert(
        {
            'ip': '1.1.1.1',
            'hostname': 'h',
            'timestamp': (datetime.now() - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S.%f'),
            'parsed_request': {'path': '/x', 'command': 'GET', 'version': 'HTTP/1.1'},
            'raw_request': '<script>alert(1)</script>',
            'ua': 'ua',
            'country': 'US',
            'continent': 'NA',
            'dns_name': 'dns',
            'is_detected': status_mod.PHPMYADMIN_HTTP,
            'hive_id': 1,
            'login': '',
        }
    )
    storage.close()

    cfg = _build_dashboard_config(secret, port)
    # Drop any cached storage singleton / rendered payloads so the get_storage
    # mock below is actually exercised (issue #234 test isolation).
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
            body, code = _get(base + f'?token={secret}')
            frag_body, frag_code = _get(base + f'?token={secret}&format=fragment&range=24h')
            ev.set()
            t.join(timeout=2)
            time.sleep(0.4)  # release socket buffer (Windows)

    assert code == 200
    # The injected script must be escaped, never rendered live.
    assert '<script>alert(1)</script>' not in body
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in body
    # Same guarantee on the fetch-based live-refresh channel (log-rows section).
    assert frag_code == 200
    assert '<script>alert(1)</script>' not in frag_body
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in frag_body


def test_dashboard_disabled_when_not_enabled():
    cfg = Config.load(validate_secrets=False)
    disabled = Config(
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
        DASHBOARD_ENABLED=False,
        DASHBOARD_PORT=8512,
        DASHBOARD_BIND='127.0.0.1',
        DASHBOARD_SECRET=secrets.token_urlsafe(32),
        DASHBOARD_TIME_RANGE='24h',
    )
    with patch.object(config_mod, 'settings', disabled):
        import multiprocessing as mp

        ev = mp.Event()
        args = type('A', (), {'update_event': ev})()
        from manyfaced.web.dashboard import run_dashboard

        # Should return immediately without binding (disabled).
        run_dashboard(args, ev)
        ev.set()


# ---------------------------------------------------------------------------
# Top Ports card shows external attacker-facing ports (issue #329)
# ---------------------------------------------------------------------------

from manyfaced.web import dashboard_render as _render  # noqa: E402


def test_render_intel_grid_top_ports_resolves_external_and_merges():
    """Top Ports must show the external port, and merge direct+redirected hits (issue #329)."""
    payload = {
        'by_port': [
            {'key': 22, 'count': 40},  # SSH, hit directly on external port
            {'key': 10022, 'count': 308},  # SSH, iptables-redirected bound port
            {'key': 10110, 'count': 59},  # POP3 redirected -> 110
            {'key': 9090, 'count': 47},  # non-redirect, stays 9090
        ],
        'by_country': [],
        'by_service': [],
        'by_ip': [],
    }
    html = _render.render_intel_grid(payload)
    # External ports 22 and 10022 both resolve to 22 and must merge into ONE row.
    assert '22' in html
    assert '10022' not in html  # never shown as a bound port
    assert '110' in html  # 10110 -> 110
    assert '9090' in html
    # The merged SSH row should carry the summed count (40 + 308 = 348).
    # render_intel_grid emits data-count per row; locate the 22 row's count.
    import re

    m = re.search(r'data-count="(\d+)" data-label="22"', html)
    assert m and int(m.group(1)) == 348


# ---------------------------------------------------------------------------
# Hero stats report requests/hour, not a fake per-minute rate (issue #328)
# ---------------------------------------------------------------------------


def test_build_payload_reports_hour_total(tmp_path, monkeypatch):
    """_build_payload exposes stats['hour_total'] (real last-60m count), no dead recent_rate."""
    from manyfaced.db import storage as storage_mod

    db_path = str(tmp_path / 'hour.db')
    monkeypatch.setenv('HONEY_DB_PATH', db_path)
    storage_mod.reset_storage_singleton()
    storage = SQLiteStorage(db_path=db_path)
    _seed(storage)
    # All seeded rows are within the last ~10h; move them into the last hour so
    # they fall inside the 60m window the hero rate is computed from.
    storage._conn.execute('DELETE FROM honeypot_bears')
    storage._conn.commit()
    now = datetime.now()

    def stamp(mins):
        return (now - timedelta(minutes=mins)).strftime('%Y-%m-%d %H:%M:%S.%f')

    for i in range(3):
        storage.insert(
            {
                'ip': f'5.5.5.{i}',
                'hostname': 'h',
                'timestamp': stamp(i),
                'parsed_request': {},
                'raw_request': 'x',
                'is_detected': status_mod.WORDPRESS_HTTP,
                'listen_port': 80,
            }
        )
    storage._conn.commit()

    payload = _dash_mod._build_payload('24h', 'tok')
    assert 'hour_total' in payload['stats']
    assert 'recent_rate' not in payload['stats']
    assert payload['stats']['hour_total'] == 3
    # The hero stat-card label is Requests/hour.
    cards = _render._render_stat_cards(payload)
    assert 'Requests/hour' in cards
    assert 'Requests/min' not in cards
    storage.close()
    storage_mod.reset_storage_singleton()


def test_build_payload_renders_benign_unknown_split(tmp_path, monkeypatch):
    """The stat grid surfaces the benign/unknown classification split (issue #271)."""
    from manyfaced.db import storage as storage_mod

    db_path = str(tmp_path / 'cls.db')
    monkeypatch.setenv('HONEY_DB_PATH', db_path)
    storage_mod.reset_storage_singleton()
    storage = SQLiteStorage(db_path=db_path)
    _seed(storage)
    # Seed one known-benign + one explicit-unknown row directly so the split
    # has both sides (the _seed() rows are classification NULL, so GROUP BY
    # excludes them — exactly what the backfill script is for).
    storage._conn.execute(
        'INSERT INTO honeypot_bears '
        '(bot_ip, hostname, timestamp, request_raw, detected_id, classification, benign_source) '
        "VALUES ('9.9.9.9', 'h', datetime('now'), 'x', 1, 'benign', 'shodan')"
    )
    storage._conn.execute(
        'INSERT INTO honeypot_bears '
        '(bot_ip, hostname, timestamp, request_raw, detected_id, classification, benign_source) '
        "VALUES ('8.8.8.8', 'h2', datetime('now'), 'y', 1, 'unknown', '')"
    )
    storage._conn.commit()

    payload = _dash_mod._build_payload('24h', 'tok')
    # split reaches the payload
    cls = {r['key']: r['count'] for r in payload['by_classification']}
    assert cls.get('benign', 0) >= 1
    assert cls.get('unknown', 0) >= 1
    # the card renders the benign/unknown counts
    cards = _render._render_stat_cards(payload)
    assert 'Benign / Unknown' in cards
    assert 'stat-benign' in cards
    storage.close()
    storage_mod.reset_storage_singleton()
