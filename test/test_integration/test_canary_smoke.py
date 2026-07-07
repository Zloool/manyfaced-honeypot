"""Canary smoke test — synthetic end-to-end pipeline (issue #165).

This is the IN-WORKFLOW canary gate: it runs a real (no mocks) synthetic bot
report through the full client -> server -> DB path and asserts a row lands,
plus that the server returned a response. The `canary` job in deploy.yml runs
this file and the `deploy` job depends on it, so a change that "starts but is
wrong" (bad responses / silent report-send failures / data-quality regressions)
fails the gate BEFORE prod traffic sees it. Rollback handles "won't start";
this handles "starts but is wrong".

Reuses the shared integration conftest (TEST_KEY / BEE_IDENTIFIER /
make_encrypted_message and the autouse DB-cleaning fixture) so the synthetic
row is asserted against a clean, isolated DB.

Note: once the droplet runs the container image (#149 cutover), this same check
can be promoted to a `docker run --rm` smoke against the built image. Until
then it exercises the exact code that gets baked into that image.
"""

import threading
import time
from unittest.mock import MagicMock

from .conftest import BEE_IDENTIFIER, TEST_KEY, make_encrypted_message


def test_canary_synthetic_report_reaches_db():
    """A synthetic encrypted report must traverse client->server->DB and land a row."""
    import socket

    from manyfaced.server.server import ServerHandler

    bear_data = {
        'ip': '203.0.113.99',
        'raw_request': 'GET /wp-admin/ HTTP/1.1\r\nHost: honeypot\r\n\r\n',
        'timestamp': '2026-07-07 12:00:00.000000',
        'parsed_request': {
            'command': 'GET',
            'path': '/wp-admin/',
            'version': 'HTTP/1.1',
            'headers': {'Host': 'honeypot'},
        },
        'is_detected': 1,
        'HIVELOGIN': '',
    }

    message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

    update_event = threading.Event()
    args_obj = MagicMock(server=(0, 0), verbose=False)
    received = []
    responded = []

    class _Handler(ServerHandler):
        def handle_request(self, msg):
            received.append(msg)
            out = super().handle_request(msg)
            responded.append(out)
            return out

    def _server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        args_obj.server = ('127.0.0.1', port)
        handler = _Handler(args_obj, update_event)
        sock.listen(1)
        conn, _ = sock.accept()
        try:
            data = b''
            while not update_event.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\n' in data or b'\r\n' in data:
                    break
            if data:
                handler.handle_request(data.decode('utf-8', errors='replace').strip())
        finally:
            conn.close()
            sock.close()

    t = threading.Thread(target=_server, daemon=True)
    t.start()
    time.sleep(0.3)
    if args_obj.server[1] == 0:
        raise AssertionError('canary server failed to bind')

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(('127.0.0.1', args_obj.server[1]))
        client.sendall((message + '\n').encode('utf-8'))
        time.sleep(0.5)
    finally:
        client.close()
    update_event.set()
    t.join(timeout=3)

    # The server must have received and processed exactly one synthetic report.
    assert len(received) == 1, f'canary: expected 1 report, got {len(received)}'
    # And it must have produced a response (the "starts but is wrong" guard).
    assert responded and responded[0], 'canary: server returned no response'

    # The report must have landed in the DB.
    import sqlite3

    from manyfaced.db.storage import _resolve_db_path

    conn = sqlite3.connect(_resolve_db_path())
    try:
        row = conn.execute(
            'SELECT bot_ip, request_path FROM honeypot_bears WHERE bot_ip = ?',
            ('203.0.113.99',),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None, 'canary: synthetic report was not saved to the database'
    assert row[0] == '203.0.113.99'
    assert row[1] == '/wp-admin/'
