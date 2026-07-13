"""Read-only token-gated stats dashboard for the honeypot (issue #234, #326 redesign).

Design / threat model
----------------------
This is a *second* network-facing surface on a box whose entire purpose is to
attract scanners, so the access model is deliberately minimal and hostile to
probing:

* **Off by default.** Only starts when ``[dashboard] enabled = true``.
* **Non-standard port** from the ``[dashboard]`` TOML section / ``HONEY_DASHBOARD_*``
  env vars (three-layer config, consistent with the rest of the project).
* **Auto-generated secret** (``secrets.token_urlsafe``, *not* a static default
  like the legacy ``HIVEPASS``). Persisted to ``config.toml`` by
  ``generate_config_file``. Every request must carry ``?token=<secret>``; the
  value is compared with :func:`hmac.compare_digest` to avoid timing leaks.
* **Loopback by default** (``127.0.0.1``); bind address is defense-in-depth —
  the token is the real control.
* **No auth flow to probe.** A missing or wrong token returns a *generic 404*
  with no "unauthorized" hint, so the endpoint doesn't advertise itself as an
  admin panel.
* **Read-only.** No config editing, no mutation, no user management.
* **Single route.** Every request (full page, and the client's fetch-based
  section refresh) hits the same ``/`` path, distinguished only by query
  params (``range``, ``port``, ``format=fragment``) — there is still exactly
  one URL that isn't a generic 404, matching the original single-route model.
* **Separate access log.** Dashboard hits go to ``manyfaced.web.dashboard.access``
  so viewing the dashboard never pollutes the honeypot's own ``honeypot_bears``
  capture dataset.
* **No third-party framework.** Stdlib ``http.server`` only — CSS/JS are
  plain strings inlined into the one response (see ``dashboard_assets.py``),
  no build step, no separate static-asset route.

The capture log's "raw capture" panel shows *uncensored* raw captures (full
``request_raw``, ``bot_ip``, ``bot_user_agent``, ``timestamp``,
``request_path``, ``bot_country``) — it is an internal capture view;
redacting it would defeat the point. All dynamic values are HTML-escaped on
render (see ``dashboard_render._esc``).
"""

from __future__ import annotations

import hmac
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from manyfaced.common import config as _config
from manyfaced.common import ports as _ports
from manyfaced.db import storage as _storage
from manyfaced.web import dashboard_data as _data
from manyfaced.web import dashboard_render as _render
from manyfaced.web.payload_decode import decode_payload  # noqa: F401 (issue #368)

logger = logging.getLogger(__name__)
# Separate logger so dashboard access doesn't pollute bear captures.
access_logger = logging.getLogger('manyfaced.web.dashboard.access')

# The honeypot writer holds the WAL lock heavily on a multi-million-row DB, so a
# fresh read can block for several seconds waiting for the lock. To keep the
# dashboard responsive we refresh the cached payload/page on a background
# thread and serve the cached copy on every request — the request path never
# touches SQLite except for a cheap, index-bound port-filtered volume query.
_REFRESH_INTERVAL = 30.0
_STALE_SERVE_SECONDS = 300.0

_VOLUME_RANGES = ('1h', '24h', '7d', '30d')
_VOLUME_BUCKETS = {'1h': 'minute5', '24h': 'hour', '7d': 'day', '30d': 'day'}
_VOLUME_BAR_COUNTS = {'1h': 12, '24h': 24, '7d': 7, '30d': 30}
_VOLUME_STEP_SECONDS = {'1h': 300, '24h': 3600, '7d': 86400, '30d': 86400}

# Populated by the background refresher; guarded by _CACHE_LOCK.
_PAYLOAD_CACHE: dict[str, tuple[float, dict]] = {}  # range -> (built_at, payload)
_HTML_CACHE: dict[str, tuple[float, bytes]] = {}  # range -> (built_at, full page bytes)
_CACHE_LOCK = threading.Lock()
_REFRESHER: threading.Thread | None = None
_REFRESHER_STOP = threading.Event()

# The all-time "Total Captures" total is an unbounded COUNT(*) over the whole
# prod table (~18s on 1.1M rows). It barely moves minute-to-minute, so cache it
# on a slow TTL and refresh it off the hot 30s path instead of on every build.
_ALLTIME_TOTAL_TTL = 300.0
_ALLTIME_TOTAL_CACHE: tuple[float, int] | None = None  # (built_at, total)

# Set once the background primer has completed its first full pass, so the
# server can refuse traffic until the cache is warm (issue #409 follow-up).
_PRIMED = threading.Event()

_TRAFFIC_MULTIPLIER = 6  # hero animation spawn-rate amplifier (visual only)

# Capture-log page size (issue #316) — one page is rendered server-side per
# request; older rows are reached via the paginator (offset-based).
_LOG_PAGE_SIZE = 50
_PAYLOADS_LIMIT = 25

# Issue #413: cap pager depth so a page=N request can't drive an unbounded
# OFFSET scan on the request thread (which bypasses the warm 30s cache).
# Beyond this we clamp to the last allowed page; OFFSET stays bounded at
# (_PAGE_MAX - 1) * _LOG_PAGE_SIZE.
from manyfaced.web.dashboard_data import _PAGE_MAX

# Issue #413: minimum host-filter length / leading-wildcard guard. A host
# shorter than this — or one the caller prefixed with a wildcard — would force
# a leading-wildcard LIKE scan across the whole capture table; reject it so the
# substring match stays meaningful (the IoC panel still matches real hosts).
_HOST_FILTER_MIN_LEN = 3

# Issue #411: defense-in-depth HTTP security headers. All assets are inlined
# (CSS/JS are plain strings in dashboard_assets.py), so a tight CSP is safe: no
# external resources, only inline style/script (already HTML-escaped) and
# self-hosted images. connect-src 'self' is REQUIRED: the dashboard refreshes
# its panels in place via same-origin fetch() calls (fetchFragment), and without
# it the browser blocks every fragment request under default-src 'none' — which
# silently breaks all filtering / range switching / pagination / live-ticks.
# See issue #425.
_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self'; connect-src 'self'"
_SECURITY_HEADERS = (
    ('Content-Security-Policy', _CSP),
    ('X-Content-Type-Options', 'nosniff'),
    ('X-Frame-Options', 'DENY'),
    ('Referrer-Policy', 'no-referrer'),
)


def _clamp_page(page: int) -> int:
    """Issue #413: bound pager depth so OFFSET stays finite and cheap.

    Callers run the capped page's query on the request thread (bypassing the
    30s warm cache), so an unbounded OFFSET would be an O(offset) scan the
    caller can drive to exhaustion. Any request past ``_PAGE_MAX`` is clamped to
    the last page instead of producing an unbounded skip.
    """
    if page < 1:
        return 1
    if page > _PAGE_MAX:
        return _PAGE_MAX
    return page


def _normalize_host_filter(host: str | None) -> str | None:
    """Issue #413: keep the host filter out of a full-table LIKE scan.

    Returns the host unchanged when it is a safe trailing-substring match, or
    ``None`` (filter dropped) when it is too short (< ``_HOST_FILTER_MIN_LEN``)
    or begins with a wildcard (``%`` / ``*``), either of which forces a
    leading-wildcard scan that the index can't satisfy. The IoC panel always
    sends a concrete, sufficiently long C2 host, so dropping pathological values
    only removes the DoS vector, never a legitimate match.
    """
    if not host:
        return None
    if host.startswith(('%', '*')):
        return None
    if len(host) < _HOST_FILTER_MIN_LEN:
        return None
    return host


def _token_valid(token: str | None) -> bool:
    """Constant-time compare of the request token against the configured secret."""
    secret = _config.settings.DASHBOARD_SECRET
    if not secret or not token:
        return False
    return hmac.compare_digest(token, secret)


def _parse_window(range_str: str) -> tuple[str | None, str]:
    """Resolve a human window ('24h'/'7d'/'30d'/'all'/'Nh'/'Nd') to (since, bucket)."""
    range_str = (range_str or '24h').strip().lower()
    now = datetime.now()
    if range_str in ('all', '0', '*'):
        return None, 'day'
    try:
        if range_str.endswith('h'):
            hours = int(range_str[:-1])
            since = now - timedelta(hours=hours)
            bucket = 'hour'
        elif range_str.endswith('d'):
            days = int(range_str[:-1])
            since = now - timedelta(days=days)
            bucket = 'day' if days >= 7 else 'hour'
        else:
            since = now - timedelta(hours=24)
            bucket = 'hour'
    except ValueError:
        since = now - timedelta(hours=24)
        bucket = 'hour'
    return since.strftime('%Y-%m-%d %H:%M:%S.%f'), bucket


def _volume_window(range_str: str) -> str:
    """ISO cutoff for a validated volume range token (already in _VOLUME_RANGES)."""
    since, _bucket = _parse_window(range_str)
    return since or ''


def _shape_volume_bars(volume_raw: list[dict], range_str: str) -> list[dict]:
    """Turn sparse GROUP BY rows into a fixed, continuous set of display bars."""
    bucket = _VOLUME_BUCKETS[range_str]
    counts = {row['bucket']: row['count'] for row in volume_raw}
    n = _VOLUME_BAR_COUNTS[range_str]
    step = _VOLUME_STEP_SECONDS[range_str]
    now = datetime.now()
    bars = []
    for i in range(n - 1, -1, -1):
        end_dt = now - timedelta(seconds=step * i)
        start_dt = end_dt - timedelta(seconds=step)
        if bucket == 'minute5':
            slot = start_dt.replace(second=0, microsecond=0)
            slot -= timedelta(minutes=slot.minute % 5)
            key = slot.strftime('%Y-%m-%d %H:%M:00')
            label = slot.strftime('%H:%M')
        elif bucket == 'hour':
            slot = start_dt.replace(minute=0, second=0, microsecond=0)
            key = slot.strftime('%Y-%m-%d %H:00')
            label = slot.strftime('%H:00')
        else:
            slot = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            key = slot.strftime('%Y-%m-%d')
            label = slot.strftime('%m/%d')
        bars.append(
            {
                'start': int(start_dt.timestamp()),
                'end': int(end_dt.timestamp()),
                'label': label,
                'count': counts.get(key, 0),
            }
        )
    return bars


# ---------------------------------------------------------------------------
# Data orchestration
# ---------------------------------------------------------------------------


# Bound the C2-host scan so a busy production DB can't stall the refresher
# (issue #351). The operator ranks by frequency and decides what to blocklist.
_C2_RAW_SCAN_LIMIT = 20000
_C2_TOP_N = 15

# C2 / malware-download hosts. We want bare hosts only (no scheme, path, port,
# or credentials) so the panel reads as a blocklist, not raw payload text.
#
# False-positive guard (operator feedback): the raw request contains MANY
# benign URLs — the honeypot's own response links, attacker-referenced legit
# sites, reflected `Host:`/`Referer` headers, etc. So we DO NOT match every
# `http(s)://host`. We only count a host when it appears in a *download*
# context — preceded by a fetch tool (wget/curl/tftp/ftp/busybox) or command
# substitution (`$(...)` / backticks), which is exactly how Mirai-style router
# RCE drops its payload. Everything else is noise and is ignored.
_C2_HOST_RE = re.compile(
    r'(?:'
    r'(?:\$\(|`|\b(?:wget|curl|tftp|ftp|busybox|tftpget|nc)\b[^\\n]{0,80}?)'
    r'https?://([0-9A-Za-z.\-]+)(?::\d+)?'
    r')',
    re.IGNORECASE,
)

# Hosts that are never real C2 drop targets — skip them so the panel isn't
# polluted by the honeypot's own infra or private/reserved space.
_C2_IGNORE_HOSTS = frozenset(
    {
        'localhost',
        '127.0.0.1',
        '0.0.0.0',  # nosec B104 - ignore-list entry, not a bind address
        '::1',
    }
)


def _is_plausible_c2_host(host: str) -> bool:
    if not host or host.lower() in _C2_IGNORE_HOSTS:
        return False
    # Drop private / loopback / link-local / reserved IP ranges.
    if re.fullmatch(
        r'(10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3}'
        r'|169\.254\.\d{1,3}\.\d{1,3}',
        host,
    ):
        return False
    if host.lower().endswith(('.local', '.internal', '.example', '.invalid', '.test')):
        return False
    return True


def _extract_c2_hosts(store: Any, since: str | None, top_n: int = _C2_TOP_N) -> list[dict]:
    """Rank C2 / malware-download hosts across two sources (issue #520).

    Two complementary surfaces feed the panel:

    1. ``request_raw`` text — hosts seen in a *download* context (a fetch tool
       or command substitution immediately before the URL). Filters out the
       benign URLs that otherwise flood the panel (the honeypot's own links,
       reflected attacker URLs, `Host:`/`Referer` headers, etc.).
    2. Handler-extracted ``c2_host`` values persisted in ``bot_profile_data``
       (via :meth:`StorageBackend.fetch_profile_c2_hosts`). A handler may have
       structurally extracted the C2 drop host from a probe whose raw request
       line didn't carry a fetch-tool prefix (or was truncated). Those hosts
       ride on the report's ``request_history`` list and are merged here, so
       they surface even when the raw-text scan alone would miss them.

    In both cases hosts in private/reserved space or on the ignore list are
    dropped before counting.
    """
    counts: Counter[str] = Counter()
    try:
        rows = store.fetch_request_raws(since=since, limit=_C2_RAW_SCAN_LIMIT)
    except Exception:  # noqa: BLE001 — never let the IoC scan break the dashboard
        logger.exception('C2 host request_raw extraction failed')
        rows = []
    for raw in rows:
        # Issue #368: decode URL/base64 first so IOCs hidden inside encoded
        # payloads (e.g. `%ADd+...%3dphp://input` -> `wget https://1.2.3.4/sh`)
        # are extracted, not missed by the raw-byte scan.
        decoded = decode_payload(raw or '')
        for m in _C2_HOST_RE.finditer(decoded):
            host = m.group(1)
            if _is_plausible_c2_host(host):
                counts[host] += 1
    # Issue #520: merge the handler-extracted C2 hosts that never reach a
    # fetch-tool-prefixed raw line (e.g. truncated payloads, or drop hosts the
    # Exploit-CGI handler pulled out of a /tmUnblock.cgi probe). Error-safe so
    # a backend without this method can't break the IoC panel.
    try:
        handler_hosts = store.fetch_profile_c2_hosts(since=since, limit=_C2_RAW_SCAN_LIMIT)
    except Exception:  # noqa: BLE001 — never let the IoC scan break the dashboard
        logger.exception('C2 host profile-data extraction failed')
        handler_hosts = []
    for host in handler_hosts:
        if _is_plausible_c2_host(host):
            counts[host] += 1
    return [{'host': h, 'count': c} for h, c in counts.most_common(top_n)]


# Cap raw payload display length so a multi-KB captured request (or a giant
# injected string) can't blow out the Payloads panel layout.
_PAYLOAD_PREVIEW_CHARS = 400

# Paths whose presence marks a row as benign probe noise rather than a real
# exploit payload (issue #362).
_NOISE_PATH_MARKERS = (
    '/favicon.ico',
    '/robots.txt',
    '/healthz',
    '/health',
    '/ping',
)

# Methods that, with no payload-bearing characters, are just connectivity
# probes (the connective tissue of scanners), not juicy findings.
_BARE_PROBE_METHODS = {'HEAD', 'OPTIONS', 'TRACE'}


def _truncate_payload(raw: str) -> str:
    """Return a display-safe, length-bounded copy of a raw request payload."""
    raw = (raw or '').replace('\r\n', '\n').replace('\r', '\n')
    if len(raw) > _PAYLOAD_PREVIEW_CHARS:
        raw = raw[:_PAYLOAD_PREVIEW_CHARS] + '…'
    return raw


def _is_payload_noise(row: dict) -> bool:
    """True if a raw request row is favicon/noise rather than a real payload."""
    raw = (row.get('raw') or '').lower()
    path = (row.get('request_path') or '').lower()
    if '/favicon.ico' in raw or any(m in path for m in _NOISE_PATH_MARKERS):
        return True
    # A bare HEAD/OPTIONS probe with no real payload body and no interesting
    # path is noise — it's the connective tissue of scanners, not an exploit.
    method = (row.get('request_command') or '').upper()
    if method in _BARE_PROBE_METHODS and not any(
        marker in raw for marker in ('://', '=', "'", '"', '<', ';')
    ):
        return True
    return False


# severity ranking: crit > warn > info (feeding _data.severity_for)
_SEV_RANK = {'crit': 2, 'warn': 1, 'info': 0}


def _build_payloads(rows: list[dict]) -> list[dict]:
    """Shape interesting raw rows into truncated display payloads (issue #362).

    Drops benign-scanner rows (already excluded in SQL) plus favicon/noise
    probes, then ranks survivors by severity (crit > warn > info) and recency
    and truncates the top ``_PAYLOADS_LIMIT`` for display.

    Each returned dict carries ``raw`` (truncated text) plus ``bot_ip`` /
    ``listen_port`` / ``bot_country`` / ``request_command`` / ``detected_id``
    so the dashboard's toolbar filters (port/country/service/method/search)
    can match Payloads panel rows the same way they match capture-log rows
    (issue #368) instead of leaving the panel static. ``decoded`` is the
    best-effort URL/base64-decoded view (issue #368) shown in a second pane.
    """
    survivors = [
        r for r in rows if r.get('classification') != 'benign' and not _is_payload_noise(r)
    ]
    survivors.sort(
        key=lambda r: (_SEV_RANK.get(_data.severity_for(r), 0), r.get('raw') or ''),
        reverse=True,
    )
    return [
        {
            'raw': _truncate_payload(r.get('raw') or ''),
            'decoded': _truncate_payload(decode_payload(r.get('raw') or '')),
            'bot_ip': r.get('bot_ip') or '',
            'listen_port': _data.display_port(r.get('listen_port')),
            'bot_country': r.get('bot_country') or '',
            'request_command': r.get('request_command') or '',
            'detected_id': r.get('detected_id'),
        }
        for r in survivors[:_PAYLOADS_LIMIT]
    ]


def _build_payload(
    range_str: str,
    token: str,
    page: int = 1,
    ip: str | None = None,
    host: str | None = None,
    search: str | None = None,
    method: str | None = None,
    shared: Any | None = None,
) -> dict:
    """Run the (slow) queries once and shape a full render payload.

    ``range_str`` scopes the volume chart + capture log candidate set. The
    hero counters and threat-intel top-lists intentionally use a separate,
    fixed window (``DASHBOARD_TIME_RANGE``) — they're a standing overview,
    not tied to the volume section's local picker (matches the original
    prototype's always-accumulating aggregate).

    ``page`` is the 1-based capture-log page (issue #316). ``ip``/``host``
    optionally scope the *capture log* to a single attacker IP or to
    requests that carried a C2/download host — the server-side pivot from
    an IoC panel entry to the actual requests it was extracted from
    (issue #366). ``search``/``method`` additionally scope the log at the
    SQL level (issue #585). All four are passed through to
    ``count_recent``/``recent_records``.
    """
    range_str = range_str if range_str in _VOLUME_RANGES else '24h'
    page = max(1, int(page or 1))
    store = _storage.get_storage(integrity_check=False, busy_timeout=60000, init_schema=False)
    try:
        shared = shared or _build_shared(store, token)
        overview = shared.overview
        c2_hosts = shared.c2_hosts
        all_time_total = shared.all_time_total
        day_total = shared.day_total
        hour_total = shared.hour_total
        payloads = shared.payloads
        display_ports = shared.display_ports
        configured_ports = shared.configured_ports
        last_capture = shared.last_capture
        overview_since = shared.overview_since

        vol_since = _volume_window(range_str)
        volume_raw = store.volume_series(
            since=vol_since, bucket=_VOLUME_BUCKETS[range_str], port=None
        )
        volume_bars = _shape_volume_bars(volume_raw, range_str)

        # Capture-log pagination (issue #316): the full time-range window can
        # hold far more than one rendered page. We count the whole window once
        # (cheap, index-bound) and page the raw rows by offset so older
        # captures stay reachable.
        window_total = store.count_recent(
            since=vol_since, ip=ip, host=host, search=search, method=method
        )
        log_offset = max(0, page - 1) * _LOG_PAGE_SIZE
        raw_recent = store.recent_records(
            limit=_LOG_PAGE_SIZE,
            since=vol_since,
            offset=log_offset,
            ip=ip,
            host=host,
            search=search,
            method=method,
        )
        log_rows = _data.group_log_rows(raw_recent)
    finally:
        # Do NOT close: get_storage() returns the shared singleton also used by
        # the capture writer. Closing it here drops the writer's connection and
        # leaves this query on a broken transaction (aggregate_stats -> 0).
        # The connection is self-healing (issue #243), so just leave it open.
        pass

    return {
        'token': token,
        'range': range_str,
        'page': page,
        'log_page_size': _LOG_PAGE_SIZE,
        'log_window_total': window_total,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': socket.gethostname(),
        'mult': _TRAFFIC_MULTIPLIER,
        'display_ports': display_ports,
        'nonbenign_active_count': len(display_ports),
        'listening_count': len(configured_ports),
        'last_capture': last_capture,
        'stats': {
            'total': all_time_total,
            'day': day_total,
            'unique_ips': overview['unique_ips'],
            'hour_total': hour_total,
        },
        'by_port': overview['by_port'],
        'by_country': overview['by_country'],
        'by_service': overview['by_service'],
        'by_ip': overview['by_ip'],
        'by_classification': overview.get('by_classification', {}),
        'c2_hosts': c2_hosts,
        'ioc_since': overview_since,
        'volume_bars': volume_bars,
        'log_rows': log_rows,
        'payloads': payloads,
        'log_summary': f'{window_total} captures in this window · {len(log_rows)} rows shown (page {page})',
    }


class _Shared:
    """Range-independent dashboard data, computed ONCE per refresh pass.

    The overview hero stats, C2 hosts, all-time total, day/hour totals,
    Payloads panel, port chips and last-seen are identical for every volume
    range (they use DASHBOARD_TIME_RANGE / since=None, not the range picker).
    Building them once and reusing across all 4 ranges removes ~9 of the 12
    aggregate passes that used to run serially on every cold start — the root
    cause of the ~30-50s dashboard warm-up that raced the deploy health gate
    (issue #416 follow-up).
    """

    __slots__ = (
        'overview',
        'overview_since',
        'c2_hosts',
        'all_time_total',
        'day_total',
        'hour_total',
        'interesting',
        'payloads',
        'display_ports',
        'configured_ports',
        'last_capture',
    )


def _build_shared(store: Any, token: str) -> _Shared:
    """Build the range-independent dashboard bundle once (issue #416 perf)."""
    overview_since, _b = _parse_window(_config.settings.DASHBOARD_TIME_RANGE)
    overview = store.aggregate_stats(since=overview_since, bucket='day')

    # Indicators of Compromise (issue #351): top attacker IPs come straight
    # from `overview['by_ip']` (already aggregated in aggregate_stats); the
    # C2 / download hosts are scanned out of request_raw text and ranked by
    # frequency. Both surfaces are blocklist candidates for the operator.
    c2_hosts = _extract_c2_hosts(store, since=overview_since)

    # Genuinely unbounded — the "Total Captures" card claims "all-time",
    # unlike `overview` above which is scoped to DASHBOARD_TIME_RANGE.
    # This is the single most expensive query on a large prod table
    # (unbounded COUNT(*) ~18s), so it comes from a slow-TTL cache, not a
    # fresh run on every build (issue #409 follow-up).
    all_time_total = _get_alltime_total(store)

    day_since, _b = _parse_window('24h')
    day_total = store.aggregate_stats(since=day_since, bucket='hour')['total']

    # Real per-hour request rate: raw capture count over the last 60
    # minutes (issue #328). A stable, readable number that reconciles with
    # Captures/24h ÷ 24, replacing the dead-looking per-60s "Requests/min".
    hour_since = (datetime.now() - timedelta(seconds=3600)).strftime('%Y-%m-%d %H:%M:%S.%f')
    hour_total = store.aggregate_stats(since=hour_since, bucket='hour')['total']

    # Raw captured payloads (issue #350 follow-up, refined by #362): surface
    # the actual attacker request bytes in a dedicated "Payloads" panel right
    # after the capture log, so operators can eyeball exploit payloads
    # (wget drops, SQLi, traversal) without expanding each log entry.
    # fetch_interesting_raws drops benign scanners + favicon noise and ranks
    # survivors by severity; the SQL keeps it confined to URL-bearing rows.
    # Stays all-time (since=None) by design — it's a standing top-severity
    # list, not tied to the volume/log range picker — but ip/host DO scope
    # it, so clicking an IoC entry filters Payloads along with the capture
    # log instead of leaving it showing unrelated all-time findings
    # (issue #368).
    interesting = store.fetch_interesting_raws(since=None, limit=_PAYLOADS_LIMIT * 20)
    payloads = _build_payloads(interesting)

    configured_ports = _config.settings.resolve_ports()
    # Hero / port chips: surface every port that has taken a real hit from
    # a non-benign sender (issue #409). `nonbenign_ports` already filters
    # benign research scanners out of the `by_port` aggregate; we resolve
    # each bound high port to its EXTERNAL (attacker-visible) port and
    # de-duplicate so e.g. direct 22 + redirected 10022 collapse to one
    # port. Falls back to the configured listening ports only when no
    # non-benign traffic has been seen yet.
    nonbenign_local = store.nonbenign_ports()
    active_external = sorted({_ports.external_port(p) for p in nonbenign_local if p})
    # Weight keyed by EXTERNAL port (resolve_display_ports returns external
    # ports; by_port keys are the bound ports the captures were stored on —
    # map them through display_port so weights line up with the hero LEDs).
    weight_by_port = {
        _data.display_port(int(r['key'])): r['count']
        for r in overview['by_port']
        if r.get('key') is not None
    }
    display_ports = [
        (p, max(1, weight_by_port.get(p, 0)))
        for p in _data.resolve_display_ports(active_external, configured_ports)
    ]
    # Real last-seen time across the WHOLE table (not the overview window),
    # so the "SYSTEM ONLINE" badge reflects actual honeypot liveness
    # instead of a hard-coded string (issue #409).
    last_capture = store.last_capture_ts()

    s = _Shared()
    s.overview = overview
    s.overview_since = overview_since
    s.c2_hosts = c2_hosts
    s.all_time_total = all_time_total
    s.day_total = day_total
    s.hour_total = hour_total
    s.interesting = interesting
    s.payloads = payloads
    s.display_ports = display_ports
    s.configured_ports = configured_ports
    s.last_capture = last_capture
    return s


def _payload_with_scope(
    payload: dict,
    page: int,
    ip: str | None,
    host: str | None,
    search: str | None = None,
    method: str | None = None,
) -> dict:
    """Cheap on-request override: recompute just the page/ip/host-scoped log +
    payloads sections against an already-cached base (range, page=1, no ip/host)
    payload, instead of rebuilding the whole thing from scratch.

    The overview stats, C2 host scan, and volume bars in ``payload`` don't
    depend on page/ip/host/search/method at all (see ``_build_payload``), so
    re-running them on every pager click or IoC-row click was pure waste — and,
    worse, it hits SQLite directly on the request thread, which can block for
    seconds behind the live writer's WAL lock (the exact thing the
    background-cache refresher exists to avoid; see the module docstring /
    comment above ``_REFRESH_INTERVAL``).
    """
    store = _storage.get_storage(integrity_check=False, busy_timeout=60000, init_schema=False)
    try:
        vol_since = _volume_window(payload['range'])
        window_total = store.count_recent(
            since=vol_since, ip=ip, host=host, search=search, method=method
        )
        log_offset = max(0, page - 1) * _LOG_PAGE_SIZE
        raw_recent = store.recent_records(
            limit=_LOG_PAGE_SIZE,
            since=vol_since,
            offset=log_offset,
            ip=ip,
            host=host,
            search=search,
            method=method,
        )
        log_rows = _data.group_log_rows(raw_recent)
        interesting = store.fetch_interesting_raws(
            since=None, limit=_PAYLOADS_LIMIT * 20, ip=ip, host=host
        )
        payloads = _build_payloads(interesting)
    finally:
        # Do NOT close: see _build_payload's identical comment.
        pass
    scoped = dict(payload)
    scoped.update(
        {
            'page': page,
            'log_window_total': window_total,
            'log_rows': log_rows,
            'payloads': payloads,
            'log_summary': f'{window_total} captures in this window · {len(log_rows)} rows shown (page {page})',
        }
    )
    return scoped


def _payload_with_port(payload: dict, port_filter: int) -> dict:
    """Cheap on-request override: recompute just the volume bars for one port.

    ``port_filter`` is the EXTERNAL port a user clicked (from the volume chip's
    ``data-port``). Resolve it through :func:`internal_ports` so redirected
    privileged ports also count the traffic stored under their bound high port
    (issue #330).
    """
    store = _storage.get_storage(integrity_check=False, busy_timeout=60000, init_schema=False)
    try:
        vol_since = _volume_window(payload['range'])
        volume_raw = store.volume_series(
            since=vol_since,
            bucket=_VOLUME_BUCKETS[payload['range']],
            port=_ports.internal_ports(port_filter),
        )
    finally:
        # Do NOT close: get_storage() returns the shared singleton also used by
        # the capture writer. Closing it here drops the writer's connection and
        # leaves this query on a broken transaction (aggregate_stats -> 0).
        # The connection is self-healing (issue #243), so just leave it open.
        pass
    scoped = dict(payload)
    scoped['volume_bars'] = _shape_volume_bars(volume_raw, payload['range'])
    return scoped


# ---------------------------------------------------------------------------
# Background cache refresh (keeps request path off SQLite)
# ---------------------------------------------------------------------------


def _get_alltime_total(store: Any) -> int:
    """All-time capture total, served from a slow-TTL cache.

    An exact ``COUNT(*)`` over the entire prod table is ~18s on 1.1M rows and
    is the dominant cost of every dashboard build. The "Total Captures" card
    doesn't need second-level freshness, so we refresh it at most once per
    ``_ALLTIME_TOTAL_TTL`` seconds instead of on every 30s refresh / cold
    request (issue #409 follow-up).
    """
    global _ALLTIME_TOTAL_CACHE
    now = time.time()
    cached = _ALLTIME_TOTAL_CACHE
    if cached is not None and (now - cached[0]) <= _ALLTIME_TOTAL_TTL:
        return cached[1]
    try:
        total = store.aggregate_stats(since=None, bucket='day')['total']
    except Exception:  # noqa: BLE001 — fall back to the last good value
        logger.exception('Dashboard all-time total refresh failed')
        return cached[1] if cached is not None else 0
    _ALLTIME_TOTAL_CACHE = (now, total)
    return total


def _refresh_cache(token: str) -> None:
    """Refresh the cached payload + full page for every supported range.

    Only page 1 is pre-cached in the background refresher; deeper pages are
    built on-demand from ``?page=`` requests (issue #316).

    Warm-up is accelerated three ways (issue #416 follow-up):

    * The range-independent bundle (overview hero stats, C2 hosts, all-time
      total, day/hour totals, Payloads panel, port chips, last-seen) is
      built ONCE via ``_build_shared`` and reused for every range, instead of
      being recomputed 4× serially.
    * The default range (``_DASHBOARD_DEFAULT_RANGE``) is built first and the
      server is marked ``_PRIMED`` immediately, so the dashboard socket opens
      as soon as the range the page actually loads is ready — the other ranges
      finish in the background.
    * The remaining ranges are built concurrently in a ``ThreadPoolExecutor``.
      This is safe because PostgreSQLStorage now gives each thread its own
      read-only connection (``_read_cursor``); see storage.py.
    """
    store = _storage.get_storage(integrity_check=False, busy_timeout=60000, init_schema=False)
    # Build the shared, range-independent bundle once.
    try:
        shared = _build_shared(store, token)
    except Exception:  # noqa: BLE001 — if the shared base fails, fall back to per-range
        logger.exception('Dashboard shared-data build failed; building per-range')
        shared = None

    def _build_range(r: str) -> None:
        try:
            payload = _build_payload(r, token, page=1, shared=shared)
            html_bytes = _render.render_page(payload).encode('utf-8')
        except Exception:  # noqa: BLE001 — keep serving stale copies on failure
            logger.exception('Dashboard cache refresh failed for range %s', r)
            return
        now = time.time()
        with _CACHE_LOCK:
            _PAYLOAD_CACHE[r] = (now, payload)
            _HTML_CACHE[r] = (now, html_bytes)

    # Prime the default range first; open the socket as soon as it's ready so
    # the dashboard is reachable without waiting for the slower ranges.
    _build_range(_DASHBOARD_DEFAULT_RANGE)
    _PRIMED.set()

    # Build the remaining ranges concurrently.
    others = [r for r in _VOLUME_RANGES if r != _DASHBOARD_DEFAULT_RANGE]
    if others:
        with ThreadPoolExecutor(max_workers=len(others), thread_name_prefix='dash-refresh') as ex:
            list(ex.map(_build_range, others))


# Default range the dashboard loads on first paint — primed first so the
# socket opens without waiting for the slower (7d/30d) ranges (issue #416).
_DASHBOARD_DEFAULT_RANGE = '24h'


def _cache_key(
    range_str: str,
    page: int,
    ip: str | None = None,
    host: str | None = None,
    search: str | None = None,
    method: str | None = None,
) -> str:
    # Include the IoC scoping filters (issue #366) and the capture-log
    # search/method filters (issue #585) so a cached payload built for one
    # scope is never served to a different filter (or to the unfiltered log).
    scope = ''
    if ip:
        scope += f'#ip={ip}'
    if host:
        scope += f'#host={host}'
    if search:
        scope += f'#search={search}'
    if method:
        scope += f'#method={method}'
    return f'{range_str}#p{page}{scope}'


def _start_refresher(token: str) -> None:
    """Spin up the background refresh loop (idempotent)."""
    global _REFRESHER
    if _REFRESHER is not None and _REFRESHER.is_alive():
        return
    _PRIMED.clear()

    def _loop() -> None:
        _refresh_cache(token)
        while not _REFRESHER_STOP.is_set():
            _REFRESHER_STOP.wait(_REFRESH_INTERVAL)
            if _REFRESHER_STOP.is_set():
                break
            _refresh_cache(token)

    _REFRESHER = threading.Thread(target=_loop, name='dashboard-refresh', daemon=True)
    _REFRESHER.start()


def _get_cached(cache: dict[str, tuple[float, Any]], key: str) -> Any | None:
    with _CACHE_LOCK:
        entry = cache.get(key)
        if entry is None:
            return None
        built_at, value = entry
    if time.time() - built_at > _STALE_SERVE_SECONDS:
        return None
    return value


class _DashboardHandler(BaseHTTPRequestHandler):
    # Quieter than the default (which logs to stderr via the bear logger).
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        access_logger.info('%s - %s', self.client_address[0], format % args)

    def _scoped_payload(
        self,
        range_str: str,
        token: str,
        page: int,
        ip: str | None,
        host: str | None,
        search: str | None = None,
        method: str | None = None,
    ) -> dict:
        """Return the payload for (range, page, ip, host, search, method).

        Unscoped page 1 uses the background-refreshed cache directly. Any
        pager/IoC/scope reuses that same cached base payload and layers the
        cheap ``_payload_with_scope`` override on top, instead of running the
        full aggregate/C2 rebuild on the request thread for every page click
        or IP/host filter (that rebuild used to run on *every* such request,
        including the 20s live-poll tick — see _payload_with_scope docstring).
        """
        if page == 1 and not ip and not host and not search and not method:
            key = _cache_key(range_str, page, ip, host)
            cached = _get_cached(_PAYLOAD_CACHE, key)
            if cached is not None:
                return cached
            payload = _build_payload(range_str, token, page=page, ip=ip, host=host)
            with _CACHE_LOCK:
                _PAYLOAD_CACHE[key] = (time.time(), payload)
            return payload

        base = _get_cached(_PAYLOAD_CACHE, _cache_key(range_str, 1, None, None))
        if base is not None:
            return _payload_with_scope(base, page, ip, host, search, method)

        # Cold start (background refresher hasn't primed this range yet) —
        # fall back to a full rebuild just this once.
        return _build_payload(range_str, token, page=page, ip=ip, host=host)

    def _deny(self) -> None:
        # Generic 404 — do NOT reveal that this is an auth-gated endpoint.
        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        # Issue #411: apply the same defense-in-depth headers as _send().
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(b'not found')

    def _send(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        # Issue #411: defense-in-depth headers (tight CSP, nosniff, frame-deny,
        # no referrer). All assets are inlined, so no external resource is needed.
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        token = (qs.get('token') or [None])[0]

        if parsed.path.rstrip('/') not in ('', '/'):
            self._deny()
            return
        if not _token_valid(token):
            self._deny()
            return

        range_str = (qs.get('range') or ['24h'])[0]
        if range_str not in _VOLUME_RANGES:
            range_str = '24h'
        fmt = (qs.get('format') or [''])[0]
        port_raw = (qs.get('port') or [''])[0]
        port_filter = int(port_raw) if port_raw.isdigit() else None
        page_raw = (qs.get('page') or [''])[0]
        page = int(page_raw) if page_raw.isdigit() and int(page_raw) >= 1 else 1
        # Issue #413: bound pager depth so a page=N request can't drive an
        # unbounded OFFSET scan on the request thread (which bypasses the warm
        # 30s cache). Clamp to the last allowed page instead.
        page = _clamp_page(page)
        # IoC-panel scoping (issue #366): an IP or C2 host clicked in the
        # dashboard re-queries the capture log server-side for that indicator.
        ip_filter = (qs.get('ip') or [None])[0] or None
        # Issue #413: drop a host filter that would force a leading-wildcard
        # full-table LIKE scan (too short, or caller-supplied wildcard prefix).
        host_filter = _normalize_host_filter((qs.get('host') or [None])[0] or None)
        # Issue #585: capture-log free-text search + method filter scope at the
        # SQL level (like ip/host) instead of only matching the loaded page.
        search_filter = (qs.get('search') or [None])[0] or None
        method_filter = (qs.get('method') or [None])[0] or None
        if method_filter not in ('GET', 'POST', 'OTHER', None):
            method_filter = None

        try:
            if fmt == 'fragment':
                payload = self._scoped_payload(
                    range_str,
                    token or '',
                    page,
                    ip_filter,
                    host_filter,
                    search_filter,
                    method_filter,
                )
                if port_filter is not None:
                    payload = _payload_with_port(payload, port_filter)
                body = _render.render_fragment(payload)
                self._send(body, 'text/plain; charset=utf-8')
                return

            if page > 1:
                # Deeper pages aren't pre-cached; reuse the range's cached
                # overview/volume/C2 data and only re-query the paged rows.
                payload = self._scoped_payload(
                    range_str,
                    token or '',
                    page,
                    ip_filter,
                    host_filter,
                    search_filter,
                    method_filter,
                )
                body = _render.render_page(payload).encode('utf-8')
                self._send(body, 'text/html; charset=utf-8')
                return

            body = _get_cached(_HTML_CACHE, range_str)
            if body is None:
                payload = _build_payload(
                    range_str,
                    token or '',
                    page=1,
                    ip=ip_filter,
                    host=host_filter,
                    search=search_filter,
                    method=method_filter,
                )
                body = _render.render_page(payload).encode('utf-8')
                with _CACHE_LOCK:
                    _HTML_CACHE[range_str] = (time.time(), body)
            self._send(body, 'text/html; charset=utf-8')
        except Exception:  # noqa: BLE001 — surface as 500, never crash
            logger.exception('Dashboard query failed')
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            # Issue #412: never leak the exception repr (SQL/paths/DB detail)
            # to the client — log server-side above, return a generic body.
            self.end_headers()
            self.wfile.write(b'internal error')


def run_dashboard(args: Any, update_event: Any) -> None:
    """Dashboard process entry point.

    Blocks until ``update_event`` is set (clean shutdown). Reads the honeypot
    DB directly (read-only); the SQLite WAL backend allows concurrent readers.
    """
    from threading import Event as _Event

    # Under a spawned worker (Windows multiprocessing default) the parent's
    # config.settings isn't inherited, so load it if missing. Under fork it is
    # already set and this is a no-op.
    if _config.settings is None:
        from manyfaced.common.config import Config

        _config.settings = Config.load()

    bind = _config.settings.DASHBOARD_BIND
    port = int(_config.settings.DASHBOARD_PORT)
    if not _config.settings.DASHBOARD_SECRET:
        logger.warning(
            'Dashboard disabled: no DASHBOARD_SECRET configured (generate config or set HONEY_DASHBOARD_SECRET)'
        )
        return
    if not _config.settings.DASHBOARD_ENABLED:
        logger.info('Dashboard disabled (_config.settings.DASHBOARD_ENABLED is false)')
        return

    token = _config.settings.DASHBOARD_SECRET or ''
    # Prime + maintain a cached payload/page on a background thread so the
    # request path never blocks on the live writer's WAL lock.
    _start_refresher(token)

    # Warm the cache BEFORE opening the port (issue #409 follow-up). Previously
    # the server accepted traffic the instant it started, so the first hits
    # landed on an empty cache and ran the full ~20s build synchronously on the
    # request thread — under nginx's short upstream timeout that surfaced as
    # 502/504 "slow spin up". Waiting for _PRIMED means the dashboard comes up
    # already-warm. The timeout is a safety valve: if priming somehow stalls,
    # still serve rather than hang the whole process.
    _PRIMED.wait(timeout=120)

    httpd = ThreadingHTTPServer((bind, port), _DashboardHandler)
    logger.info('Dashboard listening on http://%s:%d/', bind, port)

    # Run the accept loop in a background thread so we can observe update_event.
    import threading

    stop = _Event()

    def _serve() -> None:
        try:
            httpd.serve_forever()
        except Exception:  # noqa: BLE001
            logger.exception('Dashboard serve_forever crashed')

    t = threading.Thread(target=_serve, name='dashboard-http', daemon=True)
    t.start()

    try:
        # Treat args.update_event (multiprocessing Event) or our own stop Event.
        ev = getattr(args, 'update_event', None) or update_event or stop
        # Poll because multiprocessing.Event isn't always waitable with timeout cross-impl.
        while not (ev is not None and ev.is_set()):
            if stop.is_set():
                break
            import time

            time.sleep(0.5)
    finally:
        logger.info('Dashboard shutting down')
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:  # noqa: BLE001
            # Best-effort shutdown; the refresher is being stopped regardless.
            pass
        _REFRESHER_STOP.set()
        t.join(timeout=2)
