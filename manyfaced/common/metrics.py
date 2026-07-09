"""Lightweight, dependency-free observability for the honeypot.

This module exposes a small set of thread-safe counters and gauges so the
runtime has live operational signals beyond log scraping (issue #166):
request throughput, credential captures, report-send successes/failures,
geo-lookup failures, DB insert failures, handler exceptions, and queue depth /
active connection backpressure.

Design goals
------------
- **No third-party dependencies.** The data is surfaced two ways:
  1. A periodic structured ``stats`` log line (consumable by existing
     analysis tooling / canary checks in #165).
  2. ``snapshot()`` — a plain ``dict`` any other component (e.g. the #125
     credential-capture alerting) can read to fire on a signal.
- **Thread-safe.** All mutations go through ``_LOCK`` so concurrent
  report/request threads can't corrupt the counters.
- **Cheap on the hot path.** Increments are a single ``with`` block around an
  integer add; gauges are set under the same lock.

The metric names mirror the proposal in #166:

Counters
  - bot_connections
  - responses_by_domain (labels: domain)
  - credential_captures
  - report_send_success
  - report_send_failure
  - geo_lookup_failure
  - db_insert_failure
  - handler_exception

Gauges
  - report_queue_depth
  - active_connections
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# Module-level counters and gauges. All access is guarded by _LOCK.
_LOCK = threading.Lock()
_COUNTERS: dict[str, int] = {
    'bot_connections': 0,
    'credential_captures': 0,
    'report_send_success': 0,
    'report_send_failure': 0,
    'geo_lookup_failure': 0,
    'db_insert_failure': 0,
    'handler_exception': 0,
    'classification.benign': 0,
    'classification.unknown': 0,
    'classification.malicious': 0,
}
# Domain-labeled response counters (e.g. "wordpress", "phpmyadmin").
_RESPONSES_BY_DOMAIN: dict[str, int] = {}
_GAUGES: dict[str, int] = {
    'report_queue_depth': 0,
    'active_connections': 0,
}

# Background stats-logger thread handle.
_stats_thread: threading.Thread | None = None
_stats_thread_lock = threading.Lock()
_stats_running = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def incr(name: str, amount: int = 1) -> None:
    """Increment a counter by ``amount`` (default 1). Unknown names are ignored."""
    with _LOCK:
        if name in _COUNTERS:
            _COUNTERS[name] += amount


def incr_response(domain: str) -> None:
    """Increment the per-domain response counter (label ``domain``)."""
    with _LOCK:
        _RESPONSES_BY_DOMAIN[domain] = _RESPONSES_BY_DOMAIN.get(domain, 0) + 1


def set_gauge(name: str, value: int) -> None:
    """Set a gauge to ``value``. Unknown names are ignored."""
    with _LOCK:
        if name in _GAUGES:
            _GAUGES[name] = value


def snapshot() -> dict[str, Any]:
    """Return a point-in-time copy of all metrics.

    The result is safe to read by other components (e.g. alerting in #125)
    without holding the metrics lock.
    """
    with _LOCK:
        return {
            'counters': dict(_COUNTERS),
            'responses_by_domain': dict(_RESPONSES_BY_DOMAIN),
            'gauges': dict(_GAUGES),
        }


def format_snapshot() -> str:
    """Return a single-line structured representation of the metrics.

    Format is stable enough for log scraping:
    ``metrics bot_connections=12 credential_captures=3 ... responses.wordpress=5 ...``
    """
    snap = snapshot()
    parts: list[str] = []
    for key in sorted(snap['counters']):
        parts.append(f'{key}={snap["counters"][key]}')
    for key in sorted(snap['gauges']):
        parts.append(f'{key}={snap["gauges"][key]}')
    for domain in sorted(snap['responses_by_domain']):
        parts.append(f'responses.{domain}={snap["responses_by_domain"][domain]}')
    return 'metrics ' + ' '.join(parts)


# ---------------------------------------------------------------------------
# Periodic structured stats logger
# ---------------------------------------------------------------------------


def _stats_loop(interval: float = 60.0) -> None:
    """Emit a structured ``stats`` line every ``interval`` seconds."""
    global _stats_running
    while _stats_running:
        time.sleep(interval)
        if not _stats_running:
            break
        try:
            logger.info('stats %s', format_snapshot())
        except Exception:  # noqa: BLE001 — stats must never crash the service
            logger.exception('metrics stats loop error')


def start_stats_logger(interval: float = 60.0) -> None:
    """Start the background stats-logger thread (idempotent)."""
    global _stats_thread, _stats_running
    with _stats_thread_lock:
        if _stats_running:
            return
        _stats_running = True
        _stats_thread = threading.Thread(
            target=_stats_loop,
            args=(interval,),
            daemon=True,
            name='metrics-stats',
        )
        _stats_thread.start()


def stop_stats_logger() -> None:
    """Stop the background stats-logger thread (best-effort)."""
    global _stats_running
    with _stats_thread_lock:
        _stats_running = False


__all__ = [
    'incr',
    'incr_response',
    'set_gauge',
    'snapshot',
    'format_snapshot',
    'start_stats_logger',
    'stop_stats_logger',
]
