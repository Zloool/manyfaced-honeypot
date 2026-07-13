"""Focused regression tests for dashboard issues #538 / #541 / #584 / #585.

These exercise the four dashboard/UX fixes shipped on branch
``fix/dash-538-541-584-585``:

* #538 — capture-log pager advertises pages beyond ``_PAGE_MAX``.
* #541 — switching the time range leaves the capture-log pager stale.
* #584 — liveness badge flips to STALE/OFFLINE on timezone-less UTC timestamps.
* #585 — capture-log search + method filter only matched the loaded DOM page
  instead of scoping at the SQL level.
"""

import re

import pytest

from manyfaced.db.storage import SQLiteStorage
from manyfaced.web import dashboard as _dash_mod
from manyfaced.web import dashboard_assets as _da
from manyfaced.web import dashboard_data
from manyfaced.web import dashboard_render as _render


# ---------------------------------------------------------------------------
# #538 — pager depth is clamped to _PAGE_MAX
# ---------------------------------------------------------------------------


def test_render_log_pager_clamps_depth_to_page_max():
    """render_log_pager must never advertise pages past _PAGE_MAX=100 (#538)."""
    page_size = 50
    # 10_000 rows / 50 per page = 200 pages, far past _PAGE_MAX.
    payload = {
        'page': 1,
        'log_page_size': page_size,
        'log_window_total': 10_000,
    }
    html = _render.render_log_pager(payload)
    # The pager advertises at most _PAGE_MAX pages.
    assert f'data-total-pages="{dashboard_data._PAGE_MAX}"' in html
    assert '201' not in html
    assert '200' not in html


def test_render_log_pager_advertises_exact_pages_when_small():
    """Within the cap the pager still reports the true page count (#538)."""
    payload = {
        'page': 1,
        'log_page_size': 50,
        'log_window_total': 250,  # 5 pages
    }
    html = _render.render_log_pager(payload)
    assert 'data-total-pages="5"' in html


def test_page_max_constant_shared_with_dashboard():
    """_PAGE_MAX is the single source of truth used by both modules (#538)."""
    assert dashboard_data._PAGE_MAX == 100
    assert _dash_mod._PAGE_MAX == 100
    # dashboard_render imports the same constant object.
    assert _render._PAGE_MAX is dashboard_data._PAGE_MAX


# ---------------------------------------------------------------------------
# #541 — range switch re-renders the pager
# ---------------------------------------------------------------------------


def test_apply_fragment_list_includes_log_pager_on_range_switch():
    """The range-row click handler must re-render #log-pager on range switch (#541)."""
    js = _da.JS
    # Locate the range-row click handler's applyFragment section list.
    m = re.search(
        r"rangeRow\.addEventListener\('click'.*?applyFragment\(frag,\s*\[([^\]]+)\]", js, re.S
    )
    assert m, 'range-row handler applyFragment list not found'
    sections = [s.strip().strip('\'"') for s in m.group(1).split(',')]
    assert 'log-pager' in sections
    assert 'log-rows' in sections


# ---------------------------------------------------------------------------
# #584 — UTC timestamps get an explicit Z so the badge doesn't lie
# ---------------------------------------------------------------------------


def test_last_capture_ts_appends_z(tmp_path):
    """last_capture_ts() emits a trailing Z for timezone-less UTC rows (#584)."""
    db_path = str(tmp_path / 'ts.db')
    store = SQLiteStorage(db_path=db_path)
    store.insert(
        {
            'ip': '1.2.3.4',
            'hostname': 'h',
            'timestamp': '2026-07-13 11:00:00.123456',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'bot_country': 'UA',
            'listen_port': 80,
            'is_detected': 1,
        }
    )
    ts = store.last_capture_ts()
    store.close()
    assert ts is not None
    assert ts.endswith('Z')
    assert ts == '2026-07-13 11:00:00.123456Z'


def test_last_capture_ts_passthrough_when_already_offset(tmp_path):
    """An already-offset timestamp is left untouched (#584)."""
    db_path = str(tmp_path / 'ts2.db')
    store = SQLiteStorage(db_path=db_path)
    store.insert(
        {
            'ip': '1.2.3.4',
            'hostname': 'h',
            'timestamp': '2026-07-13 11:00:00.000000+00:00',
            'parsed_request': {},
            'raw_request': 'GET / HTTP/1.1',
            'bot_country': 'UA',
            'listen_port': 80,
            'is_detected': 1,
        }
    )
    ts = store.last_capture_ts()
    store.close()
    assert ts == '2026-07-13 11:00:00.000000+00:00'


def test_refresh_alive_parses_utc_without_offset():
    """refreshAlive must treat a Z-less UTC string as UTC, not browser-local (#584)."""
    js = _da.JS
    # The parse must append 'Z' when no offset/Z is present.
    assert "var norm = lastCapture ? lastCapture.replace(' ', 'T') : '';" in js
    assert "norm += 'Z'" in js
    assert 'Date.parse(norm)' in js


# ---------------------------------------------------------------------------
# #585 — search + method filter scope at the SQL level
# ---------------------------------------------------------------------------


def _seed_rows(tmp_path, rows):
    db_path = str(tmp_path / 'search.db')
    store = SQLiteStorage(db_path=db_path)
    for r in rows:
        store.insert(r)
    return store


def _rec(ip, raw, command, detected_id=1, ts='2026-07-13 11:00:00.000000'):
    return {
        'ip': ip,
        'hostname': 'h',
        'timestamp': ts,
        'parsed_request': {},
        'raw_request': raw,
        'bot_country': 'UA',
        'listen_port': 80,
        'is_detected': detected_id,
        'request_command': command,
    }


def test_search_filter_scopes_at_sql_level(tmp_path):
    """search= matches across the same columns the client data-search folds (#585)."""
    store = _seed_rows(
        tmp_path,
        [
            _rec('9.9.9.9', 'GET /wp-admin HTTP/1.1', 'GET', ts='2026-07-13 11:00:01.000000'),
            _rec('1.1.1.1', 'POST /login HTTP/1.1', 'POST', ts='2026-07-13 11:00:02.000000'),
            _rec('2.2.2.2', 'GET /index HTTP/1.1', 'GET', ts='2026-07-13 11:00:03.000000'),
        ],
    )
    # Case-insensitive substring match across raw/UA/ip/path.
    hit = store.recent_records(limit=50, search='wp-admin')
    store.close()
    assert len(hit) == 1
    assert hit[0]['bot_ip'] == '9.9.9.9'


def test_search_short_term_rejected(tmp_path):
    """A too-short search term is dropped so it can't drive a full-table scan (#585)."""
    store = _seed_rows(
        tmp_path,
        [_rec('9.9.9.9', 'GET /wp-admin HTTP/1.1', 'GET')],
    )
    # 'a' is below the 2-char minimum -> no LIKE clause -> all rows returned.
    assert len(store.recent_records(limit=50, search='a')) == 1
    store.close()


def test_method_filter_get_post_other(tmp_path):
    """method=GET/POST/OTHER scope matches the dashboard's data-method buckets (#585)."""
    store = _seed_rows(
        tmp_path,
        [
            _rec('1.1.1.1', 'GET /a HTTP/1.1', 'GET', ts='2026-07-13 11:00:01.000000'),
            _rec('2.2.2.2', 'POST /b HTTP/1.1', 'POST', ts='2026-07-13 11:00:02.000000'),
            _rec('3.3.3.3', 'RAW connection', None, ts='2026-07-13 11:00:03.000000'),
        ],
    )
    gets = store.recent_records(limit=50, method='GET')
    posts = store.recent_records(limit=50, method='POST')
    others = store.recent_records(limit=50, method='OTHER')
    store.close()
    assert [r['bot_ip'] for r in gets] == ['1.1.1.1']
    assert [r['bot_ip'] for r in posts] == ['2.2.2.2']
    # OTHER = not GET/POST, including null command (RAW).
    assert sorted(r['bot_ip'] for r in others) == ['3.3.3.3']


def test_search_and_method_combine(tmp_path):
    """search + method compose with AND (#585)."""
    store = _seed_rows(
        tmp_path,
        [
            _rec('1.1.1.1', 'GET /secret HTTP/1.1', 'GET', ts='2026-07-13 11:00:01.000000'),
            _rec('2.2.2.2', 'POST /secret HTTP/1.1', 'POST', ts='2026-07-13 11:00:02.000000'),
            _rec('3.3.3.3', 'GET /public HTTP/1.1', 'GET', ts='2026-07-13 11:00:03.000000'),
        ],
    )
    hit = store.recent_records(limit=50, search='secret', method='GET')
    store.close()
    assert [r['bot_ip'] for r in hit] == ['1.1.1.1']


def test_fetch_fragment_passes_search_and_method():
    """The client fetchFragment sends search/method query params to the server (#585)."""
    js = _da.JS
    assert "if (search) url += '&search='" in js
    assert "if (method && method !== 'ALL') url += '&method='" in js


def test_refresh_log_threads_search_and_method():
    """refreshLog() forwards the current search + method to the server fetch (#585)."""
    js = _da.JS
    m = re.search(r'function refreshLog\(\)\{.*?fetchFragment\(([^)]*)\)', js, re.S)
    assert m, 'refreshLog() not found'
    args = m.group(1)
    assert 'state.search' in args
    assert 'state.method' in args


def test_clear_filter_search_method_refetch_from_server():
    """Clearing the search/method filter re-fetches from the server (#585)."""
    js = _da.JS
    # clearFilter must call refreshLog() (not just applyFilters) for both
    # the method and search branches so filtering reverts at the SQL level.
    assert "kind === 'method'" in js
    assert "kind === 'search'" in js
    # Each branch ends with refreshLog(); return; (method branch shown).
    assert (
        "kind === 'method'){ state.method = 'ALL'; setActive(methodRow, 'data-method', 'ALL'); refreshLog(); return; }"
        in js
    )
