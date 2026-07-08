"""Read-only token-gated stats dashboard for the honeypot (issue #234).

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
* **Separate access log.** Dashboard hits go to ``manyfaced.web.dashboard.access``
  so viewing the dashboard never pollutes the honeypot's own ``honeypot_bears``
  capture dataset.
* **No third-party framework.** Stdlib ``http.server`` only.

The recent-activity view shows *uncensored* raw captures (full ``request_raw``,
``bot_ip``, ``bot_user_agent``, ``timestamp``, ``request_path``,
``bot_country``) — it is an internal capture view; redacting it would defeat
the point. All dynamic values are HTML-escaped on render.
"""

from __future__ import annotations

import html
import hmac
import logging
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from manyfaced.common import config as _config
from manyfaced.db import storage as _storage

logger = logging.getLogger(__name__)
# Separate logger so dashboard access doesn't pollute bear captures.
access_logger = logging.getLogger('manyfaced.web.dashboard.access')

# The honeypot writer holds the WAL lock heavily on a multi-million-row DB, so a
# fresh read can block for several seconds waiting for the lock. To keep the
# dashboard responsive we refresh the rendered page on a background thread and
# serve the cached copy on every request — the request path never touches SQLite.
# The stale-while-revalidate window is generous on purpose (the data is only
# marginally fresher than the refresh interval anyway).
_REFRESH_INTERVAL = 30.0
_STALE_SERVE_SECONDS = 300.0

# Populated by the background refresher; guarded by _CACHE_LOCK.
_CACHE: dict[str, tuple[float, bytes]] = {}  # range_str -> (rendered_at, html_bytes)
_CACHE_LOCK = threading.Lock()
_REFRESHER: threading.Thread | None = None
_REFRESHER_STOP = threading.Event()


def _token_valid(token: str | None) -> bool:
    """Constant-time compare of the request token against the configured secret."""
    secret = _config.settings.DASHBOARD_SECRET
    if not secret or not token:
        return False
    return hmac.compare_digest(token, secret)


def _parse_range(range_str: str) -> tuple[str | None, str]:
    """Resolve a range string to (since_timestamp, bucket).

    ``since_timestamp`` is ``None`` for 'all' (no lower bound); otherwise a
    textual ``%Y-%m-%d %H:%M:%S.%f`` cutoff. ``bucket`` is 'day' for wide ranges
    and 'hour' otherwise (controls the volume series granularity).
    """
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
            # Unknown range -> default 24h
            since = now - timedelta(hours=24)
            bucket = 'hour'
    except ValueError:
        since = now - timedelta(hours=24)
        bucket = 'hour'
    return since.strftime('%Y-%m-%d %H:%M:%S.%f'), bucket


def _get_stats(range_str: str, store: _storage.StorageBackend) -> dict:
    """Return aggregates for the given range (fresh per request)."""
    since, bucket = _parse_range(range_str)
    result = store.aggregate_stats(since=since, bucket=bucket)
    result['range'] = range_str
    return result


def _get_recent(limit: int, range_str: str, store: _storage.StorageBackend) -> list[dict]:
    """Return recent records for the given range (fresh per request)."""
    since, _ = _parse_range(range_str)
    rows = store.recent_records(limit=limit, since=since)
    # Coerce detected_id to int-friendly for mapping; keep raw fields intact.
    result = []
    for r in rows:
        rec = dict(r)
        rec['_service'] = _storage.detected_id_name(rec.get('detected_id'))
        result.append(rec)
    return result


# ---------------------------------------------------------------------------
# HTML rendering (all dynamic values escaped)
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    if value is None:
        return ''
    return html.escape(str(value))


def _table(rows: list[dict], value_label: str = 'count') -> str:
    if not rows:
        return '<p class="muted">no data</p>'
    body = ''.join(
        f'<tr><td>{_esc(r["key"])}</td><td class="num">{_esc(r["count"])}</td></tr>' for r in rows
    )
    return (
        f'<table><thead><tr><th>key</th><th class="num">{value_label}</th></tr></thead>'
        f'<tbody>{body}</tbody></table>'
    )


def _volume_chart(volume: list[dict]) -> str:
    if not volume:
        return '<p class="muted">no data</p>'
    max_c = max((r['count'] for r in volume), default=1) or 1
    rows = []
    for r in volume:
        pct = (r['count'] / max_c * 100) if max_c else 0
        rows.append(
            f'<tr><td class="bk">{_esc(r["bucket"])}</td>'
            f'<td class="num">{_esc(r["count"])}</td>'
            f'<td><div class="bar" style="width:{pct:.1f}%"></div></td></tr>'
        )
    return (
        '<table class="vol"><thead><tr><th>bucket</th><th class="num">count</th>'
        '<th></th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>'
    )


_STYLE = """
:root{color-scheme:dark}
body{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;background:#0b0e14;color:#c9d1d9;margin:0;padding:1.5rem}
h1{font-size:1.4rem;margin:0 0 .25rem}
h2{font-size:1rem;border-bottom:1px solid #21262d;padding-bottom:.3rem;margin:1.5rem 0 .6rem;color:#58a6ff}
.meta{color:#8b949e;font-size:.8rem}
.muted{color:#6e7681;font-style:italic}
a,button{color:#58a6ff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:.8rem}
table{border-collapse:collapse;width:100%;font-size:.82rem}
th,td{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #21262d}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.bk{white-space:nowrap}
.bar{background:#1f6feb;height:.8rem;border-radius:3px}
.raw{white-space:pre-wrap;word-break:break-word;background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:.5rem;max-height:14rem;overflow:auto;font-size:.75rem}
.summary{display:flex;gap:1.5rem;flex-wrap:wrap;margin:.5rem 0 1rem}
.summary b{color:#fff;font-size:1.1rem}
.nav{margin:.5rem 0}
.nav a{margin-right:1rem;text-decoration:none}
form{display:inline}
select,button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:.25rem .5rem;font:inherit}
"""


def _render_html(stats: dict, recent: list[dict], range_str: str, token: str) -> str:
    """Render the full dashboard page as an HTML string."""
    total = stats.get('total', 0)
    detected = stats.get('detected', 0)
    undetected = stats.get('undetected', 0)
    ratio = (detected / total * 100) if total else 0.0
    gen = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    ranges = ['24h', '7d', '30d', 'all']
    nav = ''.join(
        f'<a href="/?token={token}&range={r}">{r}</a>' if r != range_str else f'<b>{r}</b>'
        for r in ranges
    )

    recent_rows = []
    for r in recent:
        recent_rows.append(
            '<tr>'
            f'<td class="bk">{_esc(r.get("timestamp"))}</td>'
            f'<td>{_esc(r.get("_service"))}</td>'
            f'<td>{_esc(r.get("bot_ip"))}</td>'
            f'<td>{_esc(r.get("bot_country"))}</td>'
            f'<td>{_esc(r.get("request_path"))}</td>'
            f'<td>{_esc(r.get("bot_user_agent"))}</td>'
            '</tr>'
        )
    recent_table = (
        '<table><thead><tr><th>timestamp</th><th>service</th><th>bot_ip</th>'
        '<th>country</th><th>path</th><th>user-agent</th></tr></thead><tbody>'
        + ''.join(recent_rows)
        + '</tbody></table>'
        if recent_rows
        else '<p class="muted">no recent activity</p>'
    )

    # Uncensored raw capture for the latest entry (internal view).
    raw_html = ''
    if recent:
        raw_html = (
            '<h2>latest raw capture</h2>'
            '<div class="raw">' + _esc(recent[0].get('request_raw')) + '</div>'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>manyfaced — capture dashboard</title><style>{_STYLE}</style></head>
<body>
<h1>manyfaced capture dashboard</h1>
<div class="meta">range: <b>{_esc(range_str)}</b> · generated {_esc(gen)} · read-only</div>
<div class="nav">{nav}</div>

<div class="summary">
  <span>total <b>{total}</b></span>
  <span>detected <b>{detected}</b></span>
  <span>undetected <b>{undetected}</b></span>
  <span>detected % <b>{ratio:.1f}</b></span>
</div>

<div class="grid">
  <div class="card"><h2>top targeted services</h2>{_table(stats.get('by_service', []))}</div>
  <div class="card"><h2>top source countries</h2>{_table(stats.get('by_country', []))}</div>
  <div class="card"><h2>top source continents</h2>{_table(stats.get('by_continent', []))}</div>
  <div class="card"><h2>top source IPs</h2>{_table(stats.get('by_ip', []))}</div>
  <div class="card"><h2>most-probed paths</h2>{_table(stats.get('by_path', []))}</div>
</div>

<h2>request volume over time</h2>
{_volume_chart(stats.get('volume', []))}

<h2>recent activity</h2>
{recent_table}
{raw_html}

</body></html>"""


# ---------------------------------------------------------------------------
# Background cache refresh (keeps request path off SQLite)
# ---------------------------------------------------------------------------


def _build_page(range_str: str, token: str) -> bytes:
    """Run the (slow) aggregate queries once and render the page to bytes."""
    # One long-lived reader connection for the refresher thread; it waits out
    # the WAL lock with a high busy_timeout off the request path.
    store = _storage.get_storage(integrity_check=False, busy_timeout=60000, init_schema=False)
    try:
        stats = _get_stats(range_str, store)
        recent = _get_recent(50, range_str, store)
    finally:
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass
    return _render_html(stats, recent, range_str, token or '').encode('utf-8')


def _refresh_cache(token: str) -> None:
    """Refresh the cached page for every supported range; called on a timer."""
    for r in ('24h', '7d', '30d', 'all'):
        try:
            html_bytes = _build_page(r, token)
        except Exception:  # noqa: BLE001 — keep serving stale copy on failure
            logger.exception('Dashboard cache refresh failed for range %s', r)
            continue
        with _CACHE_LOCK:
            _CACHE[r] = (time.time(), html_bytes)


def _start_refresher(token: str) -> None:
    """Spin up the background refresh loop (idempotent)."""
    global _REFRESHER
    if _REFRESHER is not None and _REFRESHER.is_alive():
        return

    def _loop() -> None:
        # Prime the cache immediately, then refresh on an interval.
        _refresh_cache(token)
        while not _REFRESHER_STOP.is_set():
            _REFRESHER_STOP.wait(_REFRESH_INTERVAL)
            if _REFRESHER_STOP.is_set():
                break
            _refresh_cache(token)

    _REFRESHER = threading.Thread(target=_loop, name='dashboard-refresh', daemon=True)
    _REFRESHER.start()


def _get_cached(range_str: str, token: str) -> bytes | None:
    """Return a cached page if present and not too stale, else None."""
    with _CACHE_LOCK:
        entry = _CACHE.get(range_str)
        if entry is None:
            return None
        rendered_at, html_bytes = entry
    if time.time() - rendered_at > _STALE_SERVE_SECONDS:
        return None
    return html_bytes


class _DashboardHandler(BaseHTTPRequestHandler):
    # Quieter than the default (which logs to stderr via the bear logger).
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        access_logger.info('%s - %s', self.client_address[0], format % args)

    def _deny(self) -> None:
        # Generic 404 — do NOT reveal that this is an auth-gated endpoint.
        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'not found')

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

        range_str = (qs.get('range') or [_config.settings.DASHBOARD_TIME_RANGE])[0]
        # Basic allow-list to avoid query-injection surprises.
        if range_str not in ('24h', '7d', '30d', 'all'):
            range_str = '24h'

        # Serve the cached, pre-rendered page. The background refresher runs the
        # (slow, lock-contended) aggregate queries off the request path, so this
        # returns instantly. If the cache is missing/stale (e.g. right after
        # startup before the first refresh finishes), build on demand but cap
        # the wait so a request can never hang behind the WAL writer.
        body = _get_cached(range_str, token or '')
        if body is None:
            try:
                body = _build_page(range_str, token or '')
                with _CACHE_LOCK:
                    _CACHE[range_str] = (time.time(), body)
            except Exception as exc:  # noqa: BLE001 — surface as 500, never crash
                logger.exception('Dashboard query failed')
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(f'dashboard error: {exc!r}'.encode())
                return

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)


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
    # Prime + maintain a cached, pre-rendered page on a background thread so the
    # request path never blocks on the live writer's WAL lock.
    _start_refresher(token)

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
            pass
        _REFRESHER_STOP.set()
        t.join(timeout=2)
