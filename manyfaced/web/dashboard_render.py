"""HTML assembly for the dashboard (issue #234 redesign).

Every dynamic value that came from the database (IPs, paths, user-agents, raw
captures, ...) is passed through :func:`_esc` before it touches the output —
this is an internal *read-only* view of raw, uncensored bot input, so it must
never be trusted as markup. Numbers/keys that are server-controlled (port
numbers, static labels, config) are safe to inline directly.

Two entry points:

* :func:`render_page` — the full HTML document (first paint / no-JS view).
* :func:`render_fragment` — a compact multi-section payload used by the
  client JS to refresh the volume/intel/log panels in place (range switch,
  port filter, and the periodic live-tick poll) without a full reload.
"""

from __future__ import annotations

import html
import json
import secrets
from collections import Counter
from typing import Any

from manyfaced.db.storage import detected_id_name
from manyfaced.web import dashboard_data as _data
from manyfaced.web.dashboard_assets import CSS, JS
from manyfaced.web.dashboard_data import port_service_name

_RANGES = (('1h', '1H'), ('24h', '24H'), ('7d', '7D'), ('30d', '30D'))


def _esc(value: Any) -> str:
    if value is None:
        return ''
    return html.escape(str(value))


def fmt(n: float) -> str:
    return format(round(n), ',')


def fmt_k(n: float) -> str:
    if n >= 1_000_000:
        return f'{n / 1_000_000:.2f}M'
    if n >= 10_000:
        return f'{n / 1_000:.1f}k'
    return fmt(n)


# ---------------------------------------------------------------------------
# Hero
# ---------------------------------------------------------------------------


def _render_stat_cards(payload: dict) -> str:
    s = payload['stats']
    # by_classification is a list of {key, count} (same shape as by_country);
    # fold it into a {classification: count} map for the split card.
    cls = {row['key']: row['count'] for row in payload.get('by_classification', []) if 'key' in row}
    cards = [
        ('stat-total', 'Total Captures', fmt_k(s['total']), 'all-time reports', '#d3ffe4'),
        ('stat-day', 'Captures / 24h', fmt(s['day']), 'rolling window', '#83f5ae'),
        ('stat-uniq', 'Unique Sources', fmt(s['unique_ips']), 'distinct bot_ip', '#83f5ae'),
        (
            'stat-ports',
            'Active Ports',
            str(payload['listening_count']),
            'faces listening',
            '#ffcf5c',
        ),
        (
            'stat-rate',
            'Requests/hour',
            f'{s.get("hour_total", 0)}',
            'last 60m, real',
            '#3dff88',
        ),
        (
            'stat-benign',
            'Benign / Unknown',
            f'{cls.get("benign", 0)} / {cls.get("unknown", 0)}',
            'known-benign vs unidentified (issue #271)',
            '#5cc8ff',
        ),
    ]
    out = []
    for cid, label, value, sub, color in cards:
        out.append(
            f'<div class="stat-card"><div class="stat-label">{_esc(label)}</div>'
            f'<div class="stat-value" id="{cid}" style="color:{color}">{_esc(value)}</div>'
            f'<div class="stat-sub">{_esc(sub)}</div></div>'
        )
    return ''.join(out)


def _render_hero(payload: dict) -> str:
    port_json = _esc(
        json.dumps(
            [{'p': p, 's': port_service_name(p), 'w': w} for p, w in payload['display_ports']]
        )
    )
    return f"""
<section id="top" class="hero">
  <div class="hero-head">
    <div>
      <div class="hero-title">HIVE&nbsp;TELEMETRY<span class="blink-cursor">_</span></div>
      <div class="hero-sub">node <b>{_esc(payload['hostname'])}</b> &nbsp;·&nbsp; listening on
        <b>{payload['listening_count']}</b> ports</div>
    </div>
    <div class="hero-mult">
      <div>PACKET STREAM &times;{payload['mult']}</div>
      <div class="dim">amplified for visibility &middot; rate shown is real</div>
    </div>
  </div>

  <div class="hero-canvas-wrap" id="hero-canvas-wrap" data-ports='{port_json}' data-mult="{payload['mult']}" data-rph="{payload['stats'].get('hour_total', 0)}">
    <canvas id="srv-canvas"></canvas>
    <div class="hero-flag"><span class="dot"></span>SYSTEM ONLINE</div>
    <div class="hero-legend">
      <span><i class="sw probe"></i>probe</span>
      <span><i class="sw scan"></i>scan</span>
      <span><i class="sw exploit"></i>exploit</span>
    </div>
    <div class="hero-hint">green port = open &middot; flare = incoming hit</div>
  </div>

  <div class="stat-grid" id="stat-grid">{_render_stat_cards(payload)}</div>
</section>
"""


# ---------------------------------------------------------------------------
# Volume
# ---------------------------------------------------------------------------


def render_vol_box(payload: dict) -> str:
    """Render request volume as a proper time-series bar chart.

    Time runs left→right along a shared horizontal (x) axis; bar height is the
    count (y axis). Before issue #315 the panel was a vertical list of
    horizontal bars keyed by a per-row time label, which read like a table and
    hid the shape-over-time. The underlying ``by_bucket``/``vol_since`` data is
    already time-ordered, so this is a pure render change.
    """
    bars = payload['volume_bars']
    bmax = max((b['count'] for b in bars), default=1) or 1
    cells = []
    for b in bars:
        pct = max(2.0, b['count'] / bmax * 100)
        cells.append(
            '<div class="vol-col" '
            f'data-start="{b["start"]}" data-end="{b["end"]}" data-label="{_esc(b["label"])}">'
            f'<div class="vol-bars"><div class="vol-bar" style="height:{pct:.1f}%" '
            f'title="{_esc(b["label"])}: {fmt_k(b["count"])}"></div></div>'
            f'<div class="vol-xlabel">{_esc(b["label"])}</div>'
            f'<div class="vol-xcount">{fmt_k(b["count"])}</div></div>'
        )
    return (
        '<div class="vol-chart">' + ''.join(cells) + '</div>'
        if bars
        else '<p class="section-hint">no data for this window</p>'
    )


def _render_range_row(payload: dict) -> str:
    out = []
    for key, label in _RANGES:
        active = ' active' if key == payload['range'] else ''
        out.append(f'<button class="seg-btn{active}" data-range="{key}">{label}</button>')
    return ''.join(out)


def _render_port_chip_row(payload: dict) -> str:
    out = ['<button class="seg-btn sm chip-port active" data-port="">ALL PORTS</button>']
    for p, _w in payload['display_ports']:
        out.append(
            f'<button class="seg-btn sm chip-port" data-port="{p}">{p} {_esc(port_service_name(p))}</button>'
        )
    return ''.join(out)


def _render_volume_section(payload: dict) -> str:
    return f"""
<section id="volume" class="section">
  <div class="section-head">
    <div class="section-title">REQUEST VOLUME</div>
    <div class="rule"></div>
    <div class="seg-row" id="range-row">{_render_range_row(payload)}</div>
  </div>
  <div class="section-hint">click a bar to inspect that window &middot; filter the stream by port below</div>
  <div class="chip-row" id="port-chip-row">{_render_port_chip_row(payload)}</div>
  <div class="vol-box" id="vol-box">{render_vol_box(payload)}</div>
</section>
"""


# ---------------------------------------------------------------------------
# Intel / top lists
# ---------------------------------------------------------------------------


def _intel_card(
    key: str,
    title: str,
    rows: list[dict],
    label_fn: Any,
    sub_fn: Any,
    filter_type: str,
    danger_fn: Any = None,
) -> str:
    ranked = sorted(rows, key=lambda r: r['count'], reverse=True)[:8]
    mx = max((r['count'] for r in ranked), default=1) or 1
    items = []
    for i, r in enumerate(ranked):
        label = label_fn(r)
        pct = max(3.0, r['count'] / mx * 100)
        danger = bool(danger_fn and danger_fn(r, rows))
        label_class = ' repeat-offender' if danger else ''
        fill_class = ' danger' if danger else ''
        items.append(
            '<div class="intel-row" '
            f'data-filter-type="{filter_type}" data-filter-value="{_esc(label)}" '
            f'data-count="{r["count"]}" data-label="{_esc(label)}">'
            f'<div class="intel-rank">{i + 1}</div>'
            '<div><div class="intel-label-row">'
            f'<span class="intel-label{label_class}">{_esc(label)}</span>'
            f'<span class="intel-sub">{_esc(sub_fn(r))}</span></div>'
            f'<div class="intel-track"><div class="intel-fill{fill_class}" style="width:{pct:.1f}%"></div></div>'
            f'</div><div class="intel-count">{fmt_k(r["count"])}</div></div>'
        )
    body = ''.join(items) if items else '<p class="section-hint">no data</p>'
    return (
        f'<div class="intel-card" data-key="{key}">'
        f'<div class="intel-head"><div class="intel-title">{_esc(title)}</div>'
        f'<button class="seg-btn sm intel-sort-btn" data-mode="count">BY VOLUME</button></div>'
        f'<div class="intel-list">{body}</div></div>'
    )


def _repeat_offender(row: dict, all_rows: list[dict]) -> bool:
    counts = [r['count'] for r in all_rows]
    if len(counts) < 3:
        return False
    mean = sum(counts) / len(counts)
    return mean > 0 and row['count'] > mean * 2 and row['count'] >= 20


def render_intel_grid(payload: dict) -> str:
    # Top Ports must show the *external* attacker-facing port, not the
    # container-internal bound port (issue #329). And because external_port()
    # is many-to-one (a port hit both directly and via redirect both map to the
    # same external port), re-aggregate by the resolved port and sum counts, so
    # e.g. listen_port=22 (direct) + 10022 (redirected) merge into one row.
    port_resolved: Counter[int] = Counter()
    for r in payload['by_port']:
        port_resolved[_data.display_port(int(r['key']))] += r['count']
    port_rows = [{'key': k, 'count': c} for k, c in port_resolved.items()]
    return ''.join(
        [
            _intel_card(
                'ports',
                'TOP PORTS',
                port_rows,
                lambda r: str(r['key']),
                lambda r: port_service_name(r['key']),
                'port',
            ),
            _intel_card(
                'countries',
                'TOP COUNTRIES',
                payload['by_country'],
                lambda r: r['key'],
                lambda _r: '',
                'country',
            ),
            _intel_card(
                'services',
                'TOP SERVICES HIT',
                payload['by_service'],
                lambda r: r['key'],
                lambda _r: '',
                'service',
            ),
            _intel_card(
                'ips',
                'TOP SOURCE IPS',
                payload['by_ip'],
                lambda r: r['key'],
                lambda _r: '',
                'ip',
                danger_fn=_repeat_offender,
            ),
        ]
    )


def _render_intel_section(payload: dict) -> str:
    return f"""
<section id="intel" class="section">
  <div class="section-head"><div class="section-title">THREAT INTEL</div><div class="rule"></div></div>
  <div class="intel-grid" id="intel-grid">{render_intel_grid(payload)}</div>
</section>
"""


# ---------------------------------------------------------------------------
# Capture log
# ---------------------------------------------------------------------------

_SEV_COLOR = {'crit': '#ff6b74', 'warn': '#ffcf5c', 'info': '#3dff88'}
_METHOD_CLASS = {'GET': 'get', 'POST': 'post'}


def _method_badge(method: str) -> tuple[str, str]:
    m = (method or '').upper()
    if m in _METHOD_CLASS:
        return m, _METHOD_CLASS[m]
    return (m or 'RAW'), 'other'


def _search_blob(rec: dict) -> str:
    parts = [
        rec.get('bot_ip') or '',
        rec.get('target') or '',
        detected_id_name(rec.get('detected_id')),
        rec.get('bot_user_agent') or '',
        rec.get('request_raw') or '',
        str(rec.get('listen_port') or ''),
        rec.get('bot_country') or '',
    ]
    return ' '.join(parts).lower()


def _raw_wrap(rec: dict) -> str:
    service = detected_id_name(rec.get('detected_id'))
    return (
        '<div class="log-raw-wrap" hidden>'
        '<div class="log-raw-meta">'
        f'<span>bot_ip <b>{_esc(rec.get("bot_ip"))}</b></span>'
        f'<span>sensor <b>{_esc(rec.get("sensor"))}</b></span>'
        f'<span>detected <b>{_esc(service)}</b></span>'
        f'<span>bytes <b>{rec.get("bytes", 0)}</b></span>'
        f'<span>ua <b>{_esc(rec.get("bot_user_agent") or "—")}</b></span>'
        '</div>'
        f'<pre class="log-raw">{_esc(rec.get("request_raw") or "")}</pre>'
        '</div>'
    )


def _single_row(rec: dict, *, child: bool = False) -> str:
    method_label, method_cls = _method_badge(rec.get('request_command') or '')
    service = detected_id_name(rec.get('detected_id'))
    sev_color = _SEV_COLOR.get(rec['sev'], '#3dff88')
    port = rec.get('display_port') or rec.get('listen_port') or 0
    row_cls = 'log-child-row' if child else 'log-row-main'
    body = (
        f'<div class="{row_cls}" style="border-left-color:{sev_color}">'
        f'<div class="log-time">{_esc(rec.get("_time"))}</div>'
        f'<div><span class="log-port">{port}</span> <span class="log-svc">{_esc(rec.get("svc"))}</span></div>'
        '<div class="log-req">'
        f'<span class="badge-method {method_cls}">{_esc(method_label)}</span>'
        f'<span class="log-target">{_esc(rec.get("target"))}</span>'
        f'<span class="badge-face">{_esc(service)}</span></div>'
        f'<div class="log-source"><span class="log-cc">{_esc(rec.get("bot_country"))}</span> '
        f'<span class="log-ip">{_esc(rec.get("bot_ip"))}</span></div>'
        f'<div class="log-sensor">{_esc(rec.get("sensor"))}</div>'
        '<div class="log-caret">&#9656;</div></div>'
    )
    if child:
        return body + _raw_wrap(rec)
    ts = int(rec['_ts_epoch'])
    search = _esc(_search_blob(rec))
    data_method = method_label if method_label in ('GET', 'POST') else 'OTHER'
    entry_attrs = (
        f'data-kind="single" data-ts="{ts}" data-ports="{port}" data-method="{data_method}" '
        f'data-cc="{_esc(rec.get("bot_country"))}" data-ip="{_esc(rec.get("bot_ip"))}" '
        f'data-service="{_esc(service)}" data-search="{search}" data-count="1" data-sort-port="{port}"'
    )
    return f'<div class="log-entry" {entry_attrs}>{body}{_raw_wrap(rec)}</div>'


_BADGE_CLASS = {'SCAN': 'scan', 'REPEAT': 'repeat', 'BURST': 'burst'}


def _group_summary(members: list[dict], badge: str) -> str:
    if badge == 'SCAN':
        ports = sorted({m.get('display_port') or m.get('listen_port') or 0 for m in members})
        shown = ', '.join(str(p) for p in ports[:6])
        more = f', +{len(ports) - 6}' if len(ports) > 6 else ''
        return f'{len(ports)} ports &middot; {shown}{more}'
    if badge == 'REPEAT':
        m0 = members[0]
        label, _cls = _method_badge(m0.get('request_command') or '')
        return f'{label} {m0.get("target")}'
    ports = {m.get('display_port') or m.get('listen_port') or 0 for m in members}
    return f'{len(members)} requests &middot; {len(ports)} ports'


def _group_row(group: dict) -> str:
    members = group['members']
    badge = group['badge']
    badge_cls = _BADGE_CLASS[badge]
    sev_color = _SEV_COLOR.get(group['sev'], '#3dff88')
    m0 = members[0]
    ports_csv = ','.join(str(m.get('display_port') or m.get('listen_port') or 0) for m in members)
    methods = {(_method_badge(m.get('request_command') or '')[0]) for m in members}
    method_filter = (
        next(iter(methods))
        if len(methods) == 1 and next(iter(methods)) in ('GET', 'POST')
        else 'OTHER'
    )
    service = detected_id_name(m0.get('detected_id'))
    search = _esc(' '.join(_search_blob(m) for m in members))
    ts = int(group['ts'])
    min_port = min((m.get('display_port') or m.get('listen_port') or 0) for m in members)
    header = (
        f'<div class="log-row-main log-group-main" style="border-left-color:{sev_color}">'
        f'<div class="log-time">{_esc(m0.get("_time"))}</div>'
        f'<div><span class="badge-group {badge_cls}">{badge}</span></div>'
        '<div class="log-req">'
        f'<span class="log-target">{_group_summary(members, badge)}</span>'
        f'<span class="log-group-count {badge_cls}">&times;{len(members)}</span></div>'
        f'<div class="log-source"><span class="log-cc">{_esc(m0.get("bot_country"))}</span> '
        f'<span class="log-ip">{_esc(m0.get("bot_ip"))}</span></div>'
        f'<div class="log-sensor">{_esc(m0.get("sensor"))}</div>'
        '<div class="log-caret">&#9656;</div></div>'
    )
    children = ''.join(_single_row(m, child=True) for m in members)
    entry_attrs = (
        f'data-kind="group" data-ts="{ts}" data-ports="{ports_csv}" data-method="{method_filter}" '
        f'data-cc="{_esc(m0.get("bot_country"))}" data-ip="{_esc(m0.get("bot_ip"))}" '
        f'data-service="{_esc(service)}" data-search="{search}" data-count="{len(members)}" data-sort-port="{min_port}"'
    )
    return (
        f'<div class="log-entry" {entry_attrs}>{header}'
        f'<div class="log-children" hidden>{children}</div></div>'
    )


def render_log_pager(payload: dict) -> str:
    """Render the capture-log paginator (issue #316).

    Offset/numbered paging over the time-range window. The summary line stays
    accurate to the current page; when the window fits on one page the pager is
    hidden.
    """
    page = int(payload.get('page', 1))
    size = int(payload.get('log_page_size', 50))
    total = int(payload.get('log_window_total', 0))
    total_pages = max(1, (total + size - 1) // size)
    if total_pages <= 1:
        return ''
    pages = []
    # Compact numbered control: always first/last, current ±1, ellipses.
    shown: list[int] = []
    for p in (1, page - 1, page, page + 1, total_pages):
        if 1 <= p <= total_pages and p not in shown:
            shown.append(p)
    shown.sort()
    prev_class = 'seg-btn sm' + ('' if page > 1 else ' disabled')
    pages.append(
        f'<button class="{prev_class}" data-page="{max(1, page - 1)}" data-nav="prev"{" disabled" if page <= 1 else ""}>&lsaquo; PREV</button>'
    )
    last = 0
    for p in shown:
        if last and p - last > 1:
            pages.append('<span class="pager-ellipsis">…</span>')
        active = ' active' if p == page else ''
        pages.append(f'<button class="seg-btn sm{active}" data-page="{p}">{p}</button>')
        last = p
    next_class = 'seg-btn sm' + ('' if page < total_pages else ' disabled')
    pages.append(
        f'<button class="{next_class}" data-page="{min(total_pages, page + 1)}" data-nav="next"{" disabled" if page >= total_pages else ""}>NEXT &rsaquo;</button>'
    )
    return (
        f'<div class="log-pager" data-page="{page}" data-total-pages="{total_pages}" '
        f'data-total="{total}" data-size="{size}">'
        + ''.join(pages)
        + f'<span class="pager-info">page {page} / {total_pages}</span></div>'
    )


def render_log_rows(payload: dict) -> str:
    out = []
    for row in payload['log_rows']:
        if row['kind'] == 'single':
            out.append(_single_row(row['row']))
        else:
            out.append(_group_row(row))
    return ''.join(out)


def _render_log_section(payload: dict) -> str:
    rows_html = render_log_rows(payload)
    pager_html = render_log_pager(payload)
    empty_hidden = '' if payload['log_rows'] else ' hidden'
    return f"""
<section id="log" class="section">
  <div class="section-head">
    <div class="section-title">CAPTURE LOG</div>
    <div class="rule"></div>
    <div class="section-hint" id="log-summary" data-full="{_esc(payload['log_summary'])}">{_esc(payload['log_summary'])}</div>
  </div>
  <div class="log-toolbar">
    <div class="search-wrap">
      <span class="search-prompt">&gt;</span>
      <input id="log-search" class="search-input" placeholder="grep ip / path / face / user-agent / raw&hellip;" />
    </div>
    <div class="seg-row" id="method-row">
      <button class="seg-btn active" data-method="ALL">ALL</button>
      <button class="seg-btn" data-method="GET">GET</button>
      <button class="seg-btn" data-method="POST">POST</button>
      <button class="seg-btn" data-method="OTHER">OTHER</button>
    </div>
    <div class="seg-row" id="sort-row">
      <button class="seg-btn active" data-sort="newest">NEWEST</button>
      <button class="seg-btn" data-sort="port">PORT</button>
      <button class="seg-btn" data-sort="volume">VOLUME</button>
    </div>
  </div>
  <div class="chip-row" id="filter-chip-row" hidden></div>
  <div class="log-box">
    <div class="log-head-row"><div>TIME</div><div>PORT / SVC</div><div>REQUEST</div>
      <div>SOURCE</div><div>SENSOR</div><div></div></div>
    <div id="log-rows">{rows_html}</div>
    <div id="log-empty" class="log-empty"{empty_hidden}>// no captures match the current filters</div>
  </div>
  <div id="log-pager-wrap">{pager_html}</div>
</section>
"""


# ---------------------------------------------------------------------------
# Full page + fragment entry points
# ---------------------------------------------------------------------------


def render_page(payload: dict) -> str:
    # Embedded as JS source (inside <script>), NOT HTML text — must not be
    # html.escape()'d (that would mangle the JSON's quotes). Only the
    # </script>-breakout sequence needs neutralising.
    bootstrap = json.dumps({'token': payload['token'], 'range': payload['range']}).replace(
        '</', '<\\/'
    )
    generated = _esc(payload['generated_at'])
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>manyfaced &mdash; hive telemetry</title>
<style>{CSS}</style>
</head>
<body>
<div class="crt-scan" aria-hidden="true"></div>
<div class="crt-vignette" aria-hidden="true"></div>

<nav class="top">
  <a href="#top" class="brand">MANYFACED<span class="brand-dim">_HONEYPOT</span></a>
  <div class="nav-links">
    <a href="#top">OVERVIEW</a><a href="#volume">VOLUME</a><a href="#intel">INTEL</a><a href="#log">LOG</a>
  </div>
  <div class="nav-right">
    <span class="live-pill"><span class="dot"></span>LIVE</span>
    <span id="clock" class="clock">--:--:--</span>
    <button id="pause-btn" class="btn">&#10074;&#10074; PAUSE</button>
  </div>
</nav>

<main>
{_render_hero(payload)}
{_render_volume_section(payload)}
{_render_intel_section(payload)}
{_render_log_section(payload)}
<div class="footer">MANYFACED HONEYPOT &middot; read-only, token-gated &middot; generated {generated}</div>
</main>
<script>window.__MFD__ = {bootstrap};</script>
<script>{JS}</script>
</body></html>"""


def render_fragment(payload: dict) -> bytes:
    """Compact multi-section response used by the client's fetch-based refresh.

    Wire format: first line is a fresh random boundary; the rest is a series
    of ``<boundary>:<name>\\n<content>\\n`` chunks. The random boundary can't
    be pre-guessed by anything that ends up embedded in a chunk's content
    (e.g. attacker-controlled capture text reflected into the log fragment),
    so it can't be abused to forge a fake section split client-side.
    """
    boundary = 'MFB' + secrets.token_hex(8)
    s = payload['stats']
    meta = {
        'total': fmt_k(s['total']),
        'day': fmt(s['day']),
        'uniq': fmt(s['unique_ips']),
        'activePorts': payload['listening_count'],
        'rate': str(s.get('hour_total', 0)),
        'summary': payload['log_summary'],
        'logPage': payload['page'],
        'logPageSize': payload['log_page_size'],
        'logWindowTotal': payload['log_window_total'],
    }
    sections = {
        'vol-box': render_vol_box(payload),
        'intel-grid': render_intel_grid(payload),
        'log-rows': render_log_rows(payload),
        'log-pager': render_log_pager(payload),
        'meta': json.dumps(meta),
    }
    parts = [boundary]
    for name, content in sections.items():
        parts.append(f'{boundary}:{name}\n{content}')
    body = '\n'.join(parts) + '\n'
    return body.encode('utf-8')
