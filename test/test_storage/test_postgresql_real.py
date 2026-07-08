"""Real PostgreSQL integration tests (issue #243 #10).

These run ONLY when a real Postgres server is reachable (the CI ``postgres``
job provides a ``postgres:16`` service container). They are skipped
automatically in the normal ``test`` job, where psycopg2 is mocked and no
server exists, so they never break the default suite.

The whole point is to exercise the actual wire protocol / transactions / schema
behavior that the mocked ``test_postgresql.py`` cannot cover.
"""

import os

import pytest

psycopg2 = pytest.importorskip('psycopg2')

from manyfaced.db.storage import (
    PostgreSQLStorage,
    get_storage,
    reset_storage_singleton,
)


def _real_pg_params() -> dict:
    """Connection params from env (mirrors PostgreSQLStorage resolution)."""
    return {
        'host': os.environ.get('HONEY_PG_HOST', '127.0.0.1'),
        'port': int(os.environ.get('HONEY_PG_PORT', '5432')),
        'database': os.environ.get('HONEY_PG_DB', 'honeypot'),
        'user': os.environ.get('HONEY_PG_USER', 'postgres'),
        'password': os.environ.get('HONEY_PG_PASSWORD', 'postgres'),
        'sslmode': os.environ.get('HONEY_PG_SSLMODE', 'prefer'),
    }


# Skip the entire module if no reachable server (normal `test` job).
@pytest.fixture(scope='module', autouse=True)
def _require_real_pg():
    try:
        conn = psycopg2.connect(**_real_pg_params())
    except Exception as exc:  # noqa: BLE001 — no server here
        pytest.skip(f'No reachable PostgreSQL server: {exc}')
    conn.close()


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_storage_singleton()
    yield
    reset_storage_singleton()


@pytest.fixture()
def storage():
    reset_storage_singleton()
    s = PostgreSQLStorage()
    # Ensure a clean table for each test.
    with s._conn.cursor() as cur:
        cur.execute('DELETE FROM honeypot_bears')
    s._conn.commit()
    yield s
    with s._conn.cursor() as cur:
        cur.execute('DELETE FROM honeypot_bears')
    s._conn.commit()


def test_real_insert_and_query(storage):
    rec = {
        'ip': '203.0.113.5',
        'timestamp': '2026-07-08T12:00:00',
        'detected_id': 1,
        'path': '/admin',
        'raw_request': 'GET /admin HTTP/1.1',
    }
    storage.insert(rec)
    rows = storage.recent_records(limit=10)
    assert len(rows) == 1
    assert rows[0]['bot_ip'] == '203.0.113.5'
    assert rows[0]['request_path'] == '/admin'


def test_real_get_storage_singleton(storage):
    again = get_storage()
    assert again is storage
    assert isinstance(again, PostgreSQLStorage)


def test_real_delete_old_records(storage):
    old = {
        'ip': '198.51.100.7',
        'timestamp': '2000-01-01T00:00:00',
        'detected_id': 1,
        'path': '/old',
        'raw_request': 'GET /old HTTP/1.1',
    }
    new = {
        'ip': '198.51.100.8',
        'timestamp': '2026-07-08T12:00:00',
        'detected_id': 1,
        'path': '/new',
        'raw_request': 'GET /new HTTP/1.1',
    }
    storage.insert(old)
    storage.insert(new)
    deleted = storage.delete_old_records(days=90)
    assert deleted == 1
    rows = storage.recent_records(limit=100)
    assert len(rows) == 1
    assert rows[0]['bot_ip'] == '198.51.100.8'


def test_real_aggregate_stats(storage):
    storage.insert(
        {
            'ip': '203.0.113.9',
            'timestamp': '2026-07-08T12:00:00',
            'detected_id': 2,
            'path': '/x',
            'raw_request': 'GET /x HTTP/1.1',
        }
    )
    stats = storage.aggregate_stats(since='all')
    assert stats['total'] == 1
    assert 'by_service' in stats
