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
    """Worker thread that processes items from the report queue.

    Keeps draining the queue until it is empty, not just until
    ``_report_queue_alive`` flips to False. This is critical for graceful
    shutdown: if we stopped pulling items the instant ``alive`` went False,
    any items still queued would never be processed, their ``task_done()``
    would never fire, and ``join()`` in ``shutdown_report_executor()`` would
    block forever (issue #645).
    """
    q = _get_report_queue()
    while _report_queue_alive or not q.empty():
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


# How long shutdown waits for in-flight report sends to finish before giving
# up. A single report send can take a while (connect timeout + retries in
# send_report), but shutdown must never block the process indefinitely -- an
# unbounded queue.join() is what previously deadlocked graceful shutdown.
# Workers are daemon threads (reaped with the process), so a stuck worker is
# simply abandoned after this window rather than stalling shutdown.
SHUTDOWN_JOIN_TIMEOUT = 3.0


def shutdown_report_executor():
    """Gracefully shut down the report work queue and workers.

    Flips the liveness flag; with the worker loop now draining until the queue
    is empty (``while _report_queue_alive or not q.empty()``), queued items are
    processed instead of being abandoned with ``task_done()`` never called. We
    then join the worker threads with a hard timeout so a misbehaving task
    (e.g. a ``send_report`` to a dead port) cannot stall shutdown forever.

    The previously-unbounded ``_report_queue.join()`` was removed: it could
    block indefinitely when an item's ``task_done()`` was never called
    (issue #645). Workers are daemon threads, so any that are still mid-task
    after the join window are reaped when the process exits.
    """
    global _report_queue, _report_queue_alive, _report_workers
    if _report_queue is None or not _report_queue_alive:
        return
    _report_queue_alive = False
    workers = list(_report_workers)
    # Best-effort drain: give workers a bounded window to finish in-flight
    # sends, then abandon any still-stuck ones (daemon threads die with us).
    for w in workers:
        w.join(timeout=SHUTDOWN_JOIN_TIMEOUT)
    _report_queue = None
    with _report_workers_lock:
        _report_workers.clear()
