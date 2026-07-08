"""Tests for the read-only token-gated dashboard (issue #234) and the storage read API."""

import secrets
import threading
import time
from unittest.mock import patch

import pytest
import urllib.error
import urllib.request

from manyfaced.common import config as config_mod
from manyfaced.common import status as status_mod
from manyfaced.common.config import Config
from manyfaced.db import storage as storage_mod
from manyfaced.db.storage import SQLiteStorage, detected_id_name, is_detected


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
    base = {
        'ip': '1.2.3.4',
        'hostname': 'h',
        'timestamp': '2026-07-08 10:00:00.000',
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
            timestamp='2026-07-08 10:00:00.000',
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
            timestamp='2026-07-08 11:00:00.000',
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
            timestamp='2026-07-08 12:00:00.000',
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
    # newest first
    assert recs[0]['timestamp'] == '2026-07-08 12:00:00.000'
    assert recs[0]['bot_ip'] == '9.9.9.9'


def test_recent_records_limit(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'r2.db'))
    _seed(storage)
    assert len(storage.recent_records(limit=2)) == 2


def test_recent_records_since_filter(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'r3.db'))
    _seed(storage)
    recs = storage.recent_records(since='2026-07-08 11:30:00.000')
    assert len(recs) == 1
    assert recs[0]['bot_ip'] == '9.9.9.9'


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
    with patch.object(config_mod, 'settings', cfg):
        with patch.object(storage_mod, 'get_storage', lambda: SQLiteStorage(db_path=str(db))):
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


def test_dashboard_escapes_raw_capture(tmp_path):
    """Raw captures must be HTML-escaped so a captured <script> can't execute."""
    import sqlite3

    secret = secrets.token_urlsafe(32)
    port = 18512  # distinct from the fixture's port (18511) to avoid TIME_WAIT reuse on Windows
    db = tmp_path / 'dash_inject.sqlite'
    # Seed with an HTML-injection payload BEFORE the server starts (no concurrent
    # writer, which would block on the WAL DB under load).
    storage = SQLiteStorage(db_path=str(db))
    storage.insert(
        {
            'ip': '1.1.1.1',
            'hostname': 'h',
            'timestamp': '2026-07-08 23:00:00.000',
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
    with patch.object(config_mod, 'settings', cfg):
        with patch.object(storage_mod, 'get_storage', lambda: SQLiteStorage(db_path=str(db))):
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
            ev.set()
            t.join(timeout=2)
            time.sleep(0.4)  # release socket buffer (Windows)

    assert code == 200
    # The injected script must be escaped, never rendered live.
    assert '<script>alert(1)</script>' not in body
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in body


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
