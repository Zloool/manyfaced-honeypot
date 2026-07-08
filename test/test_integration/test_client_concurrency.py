"""Regression test for issue #212 (per-connection threading in the client).

#212 / #140: `create_server()` used to call `_handle_bot_connection` *synchronously*
in its accept loop, so a slow/interactive bot (up to ~15s of credential capture)
blocked `accept()` for that port, starving every other connection to the same port.

This test proves each accepted connection is now dispatched to its own daemon
thread: two connections to the *same* port are served concurrently (the second
starts before the first finishes) rather than serialized.
"""

import socket
import threading
import time
from unittest.mock import MagicMock

import pytest


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_create_server_serves_connections_concurrently(monkeypatch):
    """Two bots on the same port are handled in parallel, not serially."""
    from manyfaced.client import client as client_mod

    # A fake handler that records the thread it ran on and blocks briefly,
    # simulating a slow/interactive bot.
    handled_threads = []
    started = threading.Event()
    release = threading.Event()

    def _slow_handler(conn_sock, args, bot_addr, update_event, listen_port=0):
        handled_threads.append(threading.current_thread().ident)
        started.set()
        release.wait(timeout=10)  # hold the (per-connection) thread
        try:
            conn_sock.close()
        except OSError:
            pass

    monkeypatch.setattr(client_mod, '_handle_bot_connection', _slow_handler)

    args = MagicMock(verbose=False)
    update_event = threading.Event()
    port = _free_port()

    t = threading.Thread(
        target=client_mod.create_server,
        args=(args, update_event, port),
        name='test-create-server',
        daemon=True,
    )
    t.start()

    # Open connection #1 — its handler thread will block on `release`.
    # Retry the connect briefly in case the server is still binding.
    c1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _connected = False
    for _ in range(60):
        try:
            c1.connect(('127.0.0.1', port))
            _connected = True
            break
        except OSError:
            time.sleep(0.05)
    assert _connected, 'could not connect to test server'
    assert started.wait(timeout=3), 'first connection was never handled'

    # Open connection #2 immediately while #1's handler is still blocked.
    c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c2.connect(('127.0.0.1', port))
    c2.sendall(b'x\n')
    # Give the accept loop a moment to dispatch #2 to its own thread.
    time.sleep(0.5)

    # The key assertion: #2 was dispatched to a *different* thread than #1,
    # while #1 is still blocked. If accept() were serialized, #2 would not be
    # handled until we release #1.
    assert len(handled_threads) == 2, (
        f'expected 2 per-connection handler threads, got {len(handled_threads)}; '
        'accept() is serializing connections (issue #212)'
    )
    assert handled_threads[0] != handled_threads[1], (
        'both connections were handled by the same thread — not concurrent'
    )

    release.set()
    c1.close()
    c2.close()
    update_event.set()
    t.join(timeout=3)
