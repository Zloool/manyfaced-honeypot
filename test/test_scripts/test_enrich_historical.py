"""Tests for scripts/enrich_historical.py (issue #271 backfill).

Verifies: migrate adds the new columns idempotently; backfill classifies rows
correctly from in-row signals without network; idempotency (second run is a
no-op); resumability (interrupted run leaves rows reprocessable). Network ASN
resolution is stubbed so the test never hits ip-api.com.
"""

from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from unittest.mock import patch  # noqa: E402

import pytest  # noqa: E402

# Import the script as a module (it inserts repo root onto sys.path itself).
SCRIPT = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'enrich_historical.py')
sys.path.insert(0, os.path.dirname(SCRIPT))
import enrich_historical as eh  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_geo():
    """Never hit ip-api.com in tests — geo lookups are real network calls that
    hang CI on sandboxed runners with no egress. The backfill only resolves ASN/
    org when a row has neither, so stub it globally to keep runs fast + hermetic."""
    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        yield


def _make_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        'CREATE TABLE honeypot_bears ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        ' bot_ip TEXT, bot_dns_name TEXT, bot_user_agent TEXT,'
        ' bot_asn TEXT, bot_org TEXT, classification TEXT, benign_source TEXT)'
    )
    conn.commit()
    conn.close()


def _insert(conn, rows):
    conn.executemany(
        'INSERT INTO honeypot_bears (bot_ip, bot_dns_name, bot_user_agent, '
        'bot_asn, bot_org) VALUES (?,?,?,?,?)',
        rows,
    )
    conn.commit()


def test_migrate_adds_columns_idempotently(tmp_path):
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    assert eh.migrate(str(db), backup=False) == 0
    conn = sqlite3.connect(str(db))
    cols = {r[1] for r in conn.execute('PRAGMA table_info(honeypot_bears)').fetchall()}
    assert {'bot_asn', 'bot_org', 'classification', 'benign_source'} <= cols
    # Second run is a no-op, not an error.
    assert eh.migrate(str(db), backup=False) == 0
    conn.close()


def test_backfill_classifies_from_row_signals(tmp_path):
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    eh.migrate(str(db), backup=False)
    conn = sqlite3.connect(str(db))
    # Two benign (in-row signal), one unknown.
    _insert(
        conn,
        [
            ('1.2.3.4', 'census.shodan.io', '', '', ''),
            ('5.6.7.8', '', '', 'AS398324', 'Censys, Inc.'),
            ('9.9.9.9', 'my-router.isp.net', 'curl/8.0', 'AS12345', 'My ISP'),
        ],
    )
    conn.close()

    # Stub geo lookup so no network; ASN/org come from the row anyway.
    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        assert eh.backfill(str(db), dry_run=False) == 0

    conn = sqlite3.connect(str(db))
    rows = conn.execute(
        'SELECT bot_ip, classification, benign_source FROM honeypot_bears ORDER BY id'
    ).fetchall()
    conn.close()
    by_ip = {ip: (c, b) for ip, c, b in rows}
    assert by_ip['1.2.3.4'] == ('benign', 'shodan')
    assert by_ip['5.6.7.8'] == ('benign', 'censys')
    assert by_ip['9.9.9.9'] == ('unknown', '')


def test_backfill_idempotent_second_run_is_noop(tmp_path):
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    eh.migrate(str(db), backup=False)
    conn = sqlite3.connect(str(db))
    _insert(conn, [('1.2.3.4', 'census.shodan.io', '', '', '')])
    conn.close()
    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        assert eh.backfill(str(db), dry_run=False) == 0
        # Second run: nothing pending.
        assert eh.backfill(str(db), dry_run=False) == 0

    conn = sqlite3.connect(str(db))
    # Exactly one row, still classified (no duplicate writes / errors).
    n = conn.execute(
        "SELECT COUNT(*) FROM honeypot_bears WHERE classification='benign'"
    ).fetchone()[0]
    conn.close()
    assert n == 1


def test_backfill_resumable_after_interrupt(tmp_path):
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    eh.migrate(str(db), backup=False)
    conn = sqlite3.connect(str(db))
    _insert(
        conn,
        [
            ('1.1.1.1', 'census.shodan.io', '', '', ''),
            ('2.2.2.2', 'census.shodan.io', '', '', ''),
        ],
    )
    conn.close()

    # Simulate an interrupt: process only the first row, then crash the loop
    # by raising on the second pass. Easiest: monkeypatch _classify_row to set
    # the first row then stop. Instead, we run backfill with a limit of 1 to
    # mimic a partial run, then run again to finish.
    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        assert eh.backfill(str(db), dry_run=False, limit=1) == 0
        # Resume — remaining row must be classified.
        assert eh.backfill(str(db), dry_run=False) == 0

    conn = sqlite3.connect(str(db))
    n = conn.execute(
        "SELECT COUNT(*) FROM honeypot_bears WHERE classification='benign'"
    ).fetchone()[0]
    conn.close()
    assert n == 2


def test_backfill_dry_run_does_not_write(tmp_path):
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    eh.migrate(str(db), backup=False)
    conn = sqlite3.connect(str(db))
    _insert(conn, [('1.2.3.4', 'census.shodan.io', '', '', '')])
    conn.close()
    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        assert eh.backfill(str(db), dry_run=True) == 0
    conn = sqlite3.connect(str(db))
    n = conn.execute(
        'SELECT COUNT(*) FROM honeypot_bears WHERE classification IS NOT NULL'
    ).fetchone()[0]
    conn.close()
    assert n == 0


def test_backfill_classifies_all_null_rows(tmp_path):
    """Issue #349: every NULL row across the whole table is classified — no gap
    left behind after a single backfill run (regression for the 1,580-NULL gap).
    """
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    eh.migrate(str(db), backup=False)
    conn = sqlite3.connect(str(db))
    # A large mixed set spanning many commit-sized batches (batch default 5000).
    rows = []
    for i in range(12000):
        if i % 2 == 0:
            rows.append((f'10.0.{i % 250}.{i % 255}', 'census.shodan.io', '', '', ''))
        else:
            rows.append((f'10.1.{i % 250}.{i % 255}', 'host.example.net', 'curl/8', 'AS7', 'x'))
    _insert(conn, rows)
    conn.close()

    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        # Small batch size to exercise the multi-batch drain loop.
        assert eh.backfill(str(db), batch_size=500, dry_run=False) == 0

    conn = sqlite3.connect(str(db))
    null_left = conn.execute(
        'SELECT COUNT(*) FROM honeypot_bears WHERE classification IS NULL'
    ).fetchone()[0]
    total = conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()[0]
    benign = conn.execute(
        "SELECT COUNT(*) FROM honeypot_bears WHERE classification='benign'"
    ).fetchone()[0]
    conn.close()
    assert total == 12000
    assert null_left == 0  # complete: no unclassified rows remain
    assert benign == 6000  # every shodan row classified benign


def test_backfill_twice_is_noop_does_not_recompute(tmp_path):
    """Issue #349: running the backfill a second time must not touch or change
    already-classified rows (idempotent). We prove no rewrite by mutating a
    classified row's value and asserting the second run leaves it untouched.
    """
    db = tmp_path / 'h.sqlite'
    _make_db(str(db))
    eh.migrate(str(db), backup=False)
    conn = sqlite3.connect(str(db))
    _insert(conn, [('1.2.3.4', 'census.shodan.io', '', '', '')])
    conn.close()

    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        assert eh.backfill(str(db), dry_run=False) == 0

    # Tamper with the already-classified row: give benign_source a sentinel that
    # classify() would never produce. A second run must NOT overwrite it, since
    # the row is no longer NULL and idempotent backfill only touches NULL rows.
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE honeypot_bears SET benign_source='SENTINEL' WHERE bot_ip='1.2.3.4'")
    conn.commit()
    conn.close()

    with patch('enrich_historical.lookup_ip_geolocation', return_value=('', '', '', '')):
        assert eh.backfill(str(db), dry_run=False) == 0

    conn = sqlite3.connect(str(db))
    src = conn.execute(
        "SELECT benign_source FROM honeypot_bears WHERE bot_ip='1.2.3.4'"
    ).fetchone()[0]
    conn.close()
    assert src == 'SENTINEL'  # untouched — no recompute/rewrite on second run


class _FakePgCursor:
    """Minimal psycopg2-style cursor over an in-memory SQLite table.

    Supports the ``with`` context-manager protocol so it behaves like a real
    psycopg2 cursor (which the backfill relies on).
    """

    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        # The backfill's SQL is already valid for sqlite (same table/columns,
        # inlined LIMIT) — only the UPDATE uses psycopg2 %s params, which we
        # translate to sqlite ? placeholders.
        if sql.strip().upper().startswith('UPDATE'):
            _asn, _org, _cls, _src, _rid = params
            self._conn.execute(
                'UPDATE honeypot_bears SET bot_asn=?, bot_org=?, classification=?, '
                'benign_source=? WHERE id=?',
                (_asn, _org, _cls, _src, _rid),
            )
        else:
            self._rows = self._conn.execute(sql).fetchall()
        return self

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0]


class _FakePgConn:
    """Psycopg2-connection-like wrapper around a real sqlite3 connection."""

    def __init__(self, sqlite_conn):
        self._sqlite = sqlite_conn

    def cursor(self):
        return _FakePgCursor(self._sqlite)

    def commit(self):
        self._sqlite.commit()

    def rollback(self):
        self._sqlite.rollback()


class _FakePgStorage:
    """Duck-typed stand-in for PostgreSQLStorage with a psycopg2-like conn."""

    def __init__(self, sqlite_conn):
        self._conn = _FakePgConn(sqlite_conn)

    @property
    def __class__(self):
        # Make store.__class__.__name__ == 'PostgreSQLStorage' so the backfill's
        # backend guard passes.
        return type('PostgreSQLStorage', (), {})

    @property
    def connection(self):
        return self._conn


def test_backfill_pg_drains_all_null_rows(tmp_path):
    """Issue #349 prod path: _backfill_pg drains every NULL row via the live
    PostgreSQL backend (exercised here with a fake psycopg2-like connection)."""
    import sqlite3

    db = tmp_path / 'pg.sqlite'
    raw = sqlite3.connect(str(db))
    raw.execute(
        'CREATE TABLE honeypot_bears ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        ' bot_ip TEXT, bot_dns_name TEXT, bot_user_agent TEXT,'
        ' bot_asn TEXT, bot_org TEXT, classification TEXT, benign_source TEXT)'
    )
    rows = []
    for i in range(3000):
        if i % 2 == 0:
            rows.append((f'10.0.{i % 250}.{i % 255}', 'census.shodan.io', '', '', ''))
        else:
            rows.append((f'10.1.{i % 250}.{i % 255}', 'host.example.net', 'curl/8', 'AS7', 'x'))
    raw.executemany(
        'INSERT INTO honeypot_bears (bot_ip, bot_dns_name, bot_user_agent, bot_asn, bot_org)'
        ' VALUES (?,?,?,?,?)',
        rows,
    )
    raw.commit()

    fake = _FakePgStorage(raw)
    with patch('enrich_historical.get_storage', return_value=fake):
        assert eh._backfill_pg(batch_size=500, dry_run=False) == 0

    null_left = raw.execute(
        'SELECT COUNT(*) FROM honeypot_bears WHERE classification IS NULL'
    ).fetchone()[0]
    benign = raw.execute(
        "SELECT COUNT(*) FROM honeypot_bears WHERE classification='benign'"
    ).fetchone()[0]
    raw.close()
    assert null_left == 0  # complete drain — no gap left
    assert benign == 1500
