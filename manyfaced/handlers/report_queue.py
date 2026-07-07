"""Report queue management for honeypot bot interaction reports.

Provides a bounded work queue with worker threads to send reports to the
server, replacing per-request subprocess spawning that caused file descriptor
exhaustion and crashes.

Module-level state is managed here; HTTPHandler delegates report sending
to this module via _get_report_queue().
"""

from __future__ import annotations

import queue as _queue
import threading

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.metrics import set_gauge

logger = get_logger(__name__)

# Singleton bounded work queue for sending reports.
# Uses a queue.Queue with maxsize for backpressure: when the queue is full,
# put() blocks until space is available.
_report_queue: _queue.Queue | None = None
_report_queue_lock = threading.Lock()
_report_queue_alive: bool = False  # Public flag for aliveness tracking
_report_workers: list[threading.Thread] = []
_report_workers_lock = threading.Lock()

MAX_REPORT_THREADS = 10


def _report_worker():
    """Worker thread that processes items from the report queue."""
    q = _get_report_queue()
    while _report_queue_alive:
        try:
            fn, args = q.get(timeout=1)
            set_gauge('report_queue_depth', q.qsize())
            try:
                fn(*args)
            except Exception:
                logger.exception('Report worker error')
            finally:
                q.task_done()
                set_gauge('report_queue_depth', q.qsize())
        except _queue.Empty:
            continue


def _get_report_queue() -> _queue.Queue:
    """Get or create the module-level report work queue (singleton).

    Uses a bounded queue (maxsize=MAX_REPORT_THREADS*10) to provide
    backpressure: when the queue is full, put() blocks until space is available.
    """
    global _report_queue, _report_queue_alive
    if _report_queue is None:
        with _report_queue_lock:
            if _report_queue is None:
                _report_queue = _queue.Queue(maxsize=MAX_REPORT_THREADS * 10)
                _report_queue_alive = True
                with _report_workers_lock:
                    for _ in range(MAX_REPORT_THREADS):
                        t = threading.Thread(
                            target=_report_worker,
                            daemon=True,
                            name='report_worker',
                        )
                        t.start()
                        _report_workers.append(t)
    return _report_queue


def shutdown_report_executor():
    """Gracefully shut down the report work queue and workers."""
    global _report_queue, _report_queue_alive, _report_workers
    if _report_queue is not None and _report_queue_alive:
        _report_queue_alive = False
        # Wait for queue to drain
        _report_queue.join()
        _report_queue = None
        with _report_workers_lock:
            _report_workers.clear()
