"""Data shaping for the dashboard (issue #234 redesign).

Pure functions that turn raw ``honeypot_bears`` rows / config into the shapes
the renderer needs: which ports to draw on the hero, a friendly protocol name
per port, a rough severity for a capture, and the SCAN/REPEAT/BURST grouping
that keeps port-scans from flooding the capture log.

Kept separate from ``dashboard.py`` (HTTP/caching plumbing) and
``dashboard_render.py`` (HTML assembly) so each stays small and testable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from manyfaced.common import ports as _ports
from manyfaced.common import status as _status

# ---------------------------------------------------------------------------
# Port -> friendly protocol name (display only; independent of detected_id,
# which identifies the *matched face*, not the raw port).
# ---------------------------------------------------------------------------

PORT_SERVICE_NAMES: dict[int, str] = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    2049: 'NFS',
    2181: 'Zookeeper',
    3306: 'MySQL',
    3389: 'RDP',
    4369: 'EPMD',
    5000: 'HTTP-alt',
    5432: 'PgSQL',
    5672: 'AMQP',
    5900: 'VNC',
    5901: 'VNC-1',
    6379: 'Redis',
    7001: 'WebLogic',
    7002: 'WebLogic-S',
    8080: 'HTTP-alt',
    8443: 'HTTPS-alt',
    8888: 'HTTP-alt',
    9090: 'HTTP-alt',
    9200: 'Elastic',
    11211: 'Memcached',
    11300: 'Beanstalkd',
    15672: 'RabbitMQ',
    27017: 'Mongo',
}

# Ports with no entry above but a digit range worth labelling generically.
_BEANSTALKD_RANGE = range(11301, 11312)


# iptables REDIRECT mapping (see manyfaced/common/ports.py — the SINGLE SOURCE
# OF TRUTH). Privileged ports (<1024) can't be bound by the non-root honeypot,
# so they are redirected to high ports the honeypot actually binds. Capture
# records store the BOUND (high) port as ``listen_port``; the dashboard must
# resolve it back to the EXTERNAL (privileged) port attackers actually hit,
# which is the useful info. The high->service label is derived from the same
# canonical map so there is only one copy to maintain (issue #320).
_PORT_REDIRECT_PRIV_TO_HIGH = _ports.PRIVILEGED_PORT_REDIRECTS
# high redirect port -> privileged service name (the label attackers actually see)
_REDIRECTED_PORT_SERVICE_NAMES: dict[int, str] = {
    high: PORT_SERVICE_NAMES[priv]
    for priv, high in _PORT_REDIRECT_PRIV_TO_HIGH.items()
    if priv in PORT_SERVICE_NAMES
}


def port_service_name(port: int | None) -> str:
    """Best-effort friendly protocol label for a raw port number."""
    if not port:
        return '?'
    if port in PORT_SERVICE_NAMES:
        return PORT_SERVICE_NAMES[port]
    if port in _REDIRECTED_PORT_SERVICE_NAMES:
        return _REDIRECTED_PORT_SERVICE_NAMES[port]
    if port in _BEANSTALKD_RANGE:
        return 'Beanstalkd'
    return 'TCP'


def display_port(port: int | None) -> int:
    """Port to show on the dashboard for a captured ``listen_port``.

    Resolves a bound high port (e.g. 10022) back to the external privileged
    port an attacker actually targeted (22), so the panel shows useful,
    attacker-visible info rather than the container-internal bind port
    (issue #320). Ports that are not redirect targets pass through unchanged.
    """
    return _ports.external_port(port)


# ---------------------------------------------------------------------------
# Which ports to draw on the hero
# ---------------------------------------------------------------------------

# 'all' port_mode listens on every port 1-65535; drawing 65k LEDs is
# meaningless, so cap the hero to a representative set: the ports that have
# actually been hit, falling back to the curated top-ports list.
_MAX_HERO_PORTS = 42


def resolve_display_ports(configured_ports: list[int], by_port: list[dict]) -> list[int]:
    """Return the ports to surface on the dashboard, sorted by port number.

    Every port with at least one historical capture (from ``by_port``) is
    shown — resolved to its EXTERNAL (attacker-visible) port and de-duplicated
    — so the display reflects real activity, not a curated guess. Only when
    nothing has been captured yet do we fall back to the configured listening
    ports (capped) so the panel isn't empty on a fresh honeypot.
    """
    hit_ports = {int(row['key']) for row in by_port if row.get('key')}
    if hit_ports:
        # Resolve bound high ports back to the external privileged port, then
        # show every active port sorted by number.
        active = {_ports.external_port(p) for p in hit_ports}
        return sorted(active)
    # No activity yet: show the configured listening ports (external view),
    # capped so an "all" (1-65535) config doesn't explode the panel.
    fallback = sorted({_ports.external_port(p) for p in configured_ports})
    return fallback[:_MAX_HERO_PORTS]


# ---------------------------------------------------------------------------
# Severity heuristic (crit / warn / info) — schema has no severity column.
# ---------------------------------------------------------------------------

_HTTP_SERVICE_IDS = {
    _status.WORDPRESS_HTTP,
    _status.PHPMYADMIN_HTTP,
    _status.JENKINS_HTTP,
    _status.TOMCAT_HTTP,
    _status.DRUPAL_HTTP,
    _status.CPANEL_HTTP,
    _status.BITRIX_HTTP,
    _status.WEBDAV_HTTP,
}

# Protocols where merely speaking them at all is a strong worm/RCE signal.
_CRIT_PROTOCOLS = {_status.UNKNOWN_TELNET, _status.UNKNOWN_SMB}
_WARN_PROTOCOLS = {
    _status.UNKNOWN_RDP,
    _status.UNKNOWN_VNC,
    _status.UNKNOWN_REDIS,
    _status.UNKNOWN_MONGODB,
}

_SENSITIVE_PATH_MARKERS = (
    '.env',
    '.git',
    '.aws',
    'eval-stdin',
    'boaform',
    'diag_form',
    'passwd',
    'shell',
    'cgi-bin',
)


def severity_for(record: dict[str, Any]) -> str:
    """Rough crit/warn/info bucket for a capture row, driven off real fields."""
    detected_id = record.get('detected_id')
    login = record.get('login') or ''
    path = (record.get('request_path') or '').lower()
    method = (record.get('request_command') or '').upper()

    if login:
        # A login/credential was actually captured.
        return 'crit'
    if detected_id == _status.CONFIG_DISCLOSURE_HTTP:
        return 'crit'
    if any(marker in path for marker in _SENSITIVE_PATH_MARKERS):
        return 'crit'
    if detected_id in _HTTP_SERVICE_IDS:
        return 'crit' if method == 'POST' else 'warn'
    if detected_id in _CRIT_PROTOCOLS:
        return 'crit'
    if detected_id in _WARN_PROTOCOLS:
        return 'warn'
    return 'info'


# ---------------------------------------------------------------------------
# Log grouping — collapse port-scans / repeated hits from the same bot_ip so
# a single noisy attacker can't flood the log with near-duplicate rows.
# Consecutive rows sharing a source IP are always collapsed, with no time
# window: a scanner that reconnects every few minutes floods the log exactly
# as much as one that hammers it every second, so gap length isn't a useful
# signal here — only "did any other source's traffic interleave" is.
# ---------------------------------------------------------------------------

_SCAN_MIN_PORTS = 4


def _parse_ts(ts: str) -> float:
    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(ts, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def _target_of(record: dict[str, Any]) -> str:
    if record.get('request_command'):
        return record.get('request_path') or '/'
    raw = record.get('request_raw') or ''
    return raw.splitlines()[0] if raw else '(empty connection)'


def annotate(record: dict[str, Any]) -> dict[str, Any]:
    """Attach display-only derived fields to a raw honeypot_bears row dict."""
    rec = dict(record)
    port = record.get('listen_port') or 0
    rec['svc'] = port_service_name(port)
    rec['display_port'] = display_port(port)
    rec['sev'] = severity_for(record)
    rec['target'] = _target_of(record)
    rec['bytes'] = len(record.get('request_raw') or '')
    # hive_id (INTEGER) is not populated by the current write path — the
    # reporting node's identity actually lands in `hostname` (from
    # HIVELOGIN). Prefer hostname, fall back to hive_id for older/custom data.
    rec['sensor'] = record.get('hostname') or record.get('hive_id') or 'unknown'
    epoch = _parse_ts(record.get('timestamp') or '')
    rec['_ts_epoch'] = epoch
    rec['_time'] = datetime.fromtimestamp(epoch).strftime('%H:%M:%S') if epoch else '--:--:--'
    return rec


def group_log_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group newest-first ``recent_records()`` rows into single/scan/repeat/burst rows.

    Runs of consecutive rows from the same ``bot_ip`` always collapse into one
    group row (badge SCAN when >=4 distinct ports were hit, REPEAT when it's
    the same path/target repeated, else BURST), expandable to the individual
    child rows — regardless of how far apart in time they land, as long as no
    other source's row interrupts the run (so chronological order is
    preserved and unrelated attackers never get merged together). A run of
    exactly 1 record renders as a plain row.
    """
    annotated = [annotate(r) for r in records]
    runs: list[list[dict[str, Any]]] = []
    for rec in annotated:
        ip = rec.get('bot_ip') or ''
        if runs and (runs[-1][0].get('bot_ip') or '') == ip:
            runs[-1].append(rec)
        else:
            runs.append([rec])

    rows: list[dict[str, Any]] = []
    for members in runs:
        if len(members) == 1:
            rows.append({'kind': 'single', 'row': members[0], 'ts': members[0]['_ts_epoch']})
            continue
        ports = {m.get('listen_port') for m in members}
        targets = {m['target'] for m in members}
        if len(ports) >= _SCAN_MIN_PORTS:
            badge = 'SCAN'
        elif len(targets) == 1:
            badge = 'REPEAT'
        else:
            badge = 'BURST'
        worst = 'info'
        for m in members:
            if m['sev'] == 'crit':
                worst = 'crit'
                break
            if m['sev'] == 'warn':
                worst = 'warn'
        rows.append(
            {
                'kind': 'group',
                'badge': badge,
                'members': members,
                'sev': worst,
                'ts': members[0]['_ts_epoch'],
            }
        )
    return rows
