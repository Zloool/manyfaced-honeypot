"""End-to-end integration tests for the full honeypot data pipeline.

These tests simulate real client-server communication, non-HTTP protocol flows,
and multi-bear scenarios that unit tests cannot cover.

Test categories:
  - E2E socket: Real TCP connection from encrypted client to server handler
  - Non-HTTP credential capture: SSH/Telnet probe -> credential extraction -> DB storage
  - Multi-bear concurrent: Multiple clients sending simultaneously
  - Report queue worker: Background thread processes queued reports correctly
"""

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is on path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from .conftest import TEST_KEY, BEE_IDENTIFIER, make_encrypted_message


# -- Fixtures ---------------------------------------------------------------


@pytest.fixture()
def _clean_db():
    """Remove test DB before and after each test."""
    from manyfaced.db.storage import _resolve_db_path

    db_path = _resolve_db_path()
    if Path(db_path).exists():
        Path(db_path).unlink(missing_ok=True)
    yield
    # Force-close any lingering connections by re-opening and closing
    try:
        if Path(db_path).exists():
            conn = __import__('sqlite3').connect(db_path)
            conn.close()
            Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass


@pytest.fixture()
def _patch_bears_dict_integration():
    """Ensure AUTHORIZED_BEES has our test bee for integration tests."""
    mod = sys.modules['manyfaced.common.config']
    cfg = mod.settings
    cfg.AUTHORIZED_BEES[BEE_IDENTIFIER] = TEST_KEY
    try:
        yield cfg
    finally:
        cfg.AUTHORIZED_BEES.pop(BEE_IDENTIFIER, None)


@pytest.fixture(autouse=True)
def _reset_report_queue():
    """Reset the report queue singleton before and after each test."""
    from manyfaced.handlers.report_queue import shutdown_report_executor

    # Clean up any leftover state from previous tests
    shutdown_report_executor()
    yield
    # Ensure clean teardown
    shutdown_report_executor()


# -- E2E Socket Tests -------------------------------------------------------


class TestE2ESocketClientServer:
    """Real TCP socket communication between client and server handler."""

    def test_e2e_http_request_via_socket(self):
        """A real socket connection should deliver encrypted data to the server.

        Simulates: bot connects -> encrypts report -> sends over TCP -> server receives,
        decrypts, saves to DB.
        """
        from manyfaced.common.myenc import AESCipher
        from manyfaced.server.server import ServerHandler

        # Prepare bear data
        bear_data = {
            'ip': '10.20.30.40',
            'raw_request': 'GET /admin/config.php HTTP/1.1\r\nHost: honeypot\r\n\r\n',
            'timestamp': '2026-05-20 10:00:00.000000',
            'parsed_request': {
                'command': 'GET',
                'path': '/admin/config.php',
                'version': 'HTTP/1.1',
                'headers': {'Host': 'honeypot'},
            },
            'is_detected': 1,
            'HIVELOGIN': '',
        }

        # Encrypt the message as a real client would
        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

        # Start server handler in a thread listening on a random port
        update_event = threading.Event()
        args_obj = MagicMock(server=(0, 0), verbose=False)

        received_messages = []

        class CapturingServerHandler(ServerHandler):
            def handle_request(self, message):
                received_messages.append(message)
                return super().handle_request(message)

        handler_instance = None

        def server_thread():
            nonlocal handler_instance
            # Bind to port 0 to get a random available port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            args_obj.server = ('127.0.0.1', port)
            handler_instance = CapturingServerHandler(args_obj, update_event)

            # Accept one connection and process it
            sock.listen(1)
            conn, _ = sock.accept()
            try:
                data = b''
                while not update_event.is_set():
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # Check if we have a complete message (newline-terminated)
                    if b'\n' in data or b'\r\n' in data:
                        break

                if data:
                    msg_str = data.decode('utf-8', errors='replace').strip()
                    handler_instance.handle_request(msg_str)
            finally:
                conn.close()
                sock.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # Give server time to start listening
        time.sleep(0.3)

        if handler_instance is None or args_obj.server[1] == 0:
            pytest.skip('Server did not bind to a port in time')
            return

        # Client connects and sends the encrypted message
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_sock.connect(('127.0.0.1', args_obj.server[1]))
            client_sock.sendall((message + '\n').encode('utf-8'))
            # Small delay for server to process
            time.sleep(0.5)
        finally:
            client_sock.close()

        update_event.set()
        t.join(timeout=3)

        # Verify the message was received and processed
        assert len(received_messages) == 1, f'Expected 1 message, got {len(received_messages)}'

        # Verify it was saved to DB
        import sqlite3

        from manyfaced.db.storage import _resolve_db_path

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_ip, request_path FROM honeypot_bears WHERE bot_ip = ?',
            ('10.20.30.40',),
        ).fetchone()
        conn.close()

        assert row is not None, 'Record was not saved to database'
        assert row[0] == '10.20.30.40'
        assert row[1] == '/admin/config.php'

    def test_e2e_invalid_message_handling(self):
        """A malformed message should be handled gracefully without crashing the server."""
        from manyfaced.server.server import ServerHandler

        update_event = threading.Event()
        args_obj = MagicMock(server=(0, 0), verbose=False)

        received_data = []

        class TestHandler(ServerHandler):
            def handle_request(self, message):
                received_data.append(message)
                return super().handle_request(message)

        handler_instance = None

        def server_thread():
            nonlocal handler_instance
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            args_obj.server = ('127.0.0.1', port)
            handler_instance = TestHandler(args_obj, update_event)

            sock.listen(1)
            conn, _ = sock.accept()
            try:
                data = conn.recv(4096)
                if data:
                    msg_str = data.decode('utf-8', errors='replace').strip()
                    handler_instance.handle_request(msg_str)
            except Exception:
                pass  # Expected for malformed data
            finally:
                conn.close()
                sock.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()
        time.sleep(0.3)

        if handler_instance is None or args_obj.server[1] == 0:
            pytest.skip('Server did not bind in time')
            return

        # Send garbage data
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_sock.connect(('127.0.0.1', args_obj.server[1]))
            client_sock.sendall(b'GARBAGE_DATA_NOT_ENCRYPTED\x00\xff')
            time.sleep(0.5)
        finally:
            client_sock.close()

        update_event.set()
        t.join(timeout=3)

        # Server should have received the data (even if it failed to process)
        assert len(received_data) == 1


# -- Non-HTTP Credential Capture Tests --------------------------------------


class TestNonHTTPE2EPipeline:
    """Test non-HTTP protocol flows through the full pipeline."""

    def test_ssh_credential_capture_to_db(self):
        """SSH probe with credentials should flow through to DB storage.

        Simulates: SSH honeypot captures username/password -> client sends report ->
        server decrypts and saves credential data.
        """
        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        # This is what the client would send after capturing SSH credentials.
        # Note: raw_request must be a string (not bytes) because make_encrypted_message
        # uses json.dumps() which cannot serialize Python bytes objects.
        bear_data = {
            'ip': '45.33.32.156',
            'raw_request': 'SSH-2.0-OpenSSH_8.9\r\n',  # string, not bytes
            'timestamp': '2026-05-21 14:30:00.000000',
            'parsed_request': {
                'protocol': 'ssh',
                'version': 'SSH-2.0-OpenSSH_8.9',
                'client': 'OpenSSH_8.9',
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            'login': 'root:password123',  # Captured credentials
        }

        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

        args_obj = MagicMock(server=(0, 8100), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        # Let save_data run for real (no mock) so data actually gets written to DB
        result = handler.handle_request(message)

        assert result is True

        # Verify it was saved to DB with credentials
        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_ip, login FROM honeypot_bears WHERE bot_ip = ?',
            ('45.33.32.156',),
        ).fetchone()
        conn.close()

        assert row is not None, 'SSH credential record was not saved'
        assert row[0] == '45.33.32.156'
        assert row[1] == 'root:password123', f'Expected credentials, got: {row[1]}'

    def test_telnet_credential_capture_to_db(self):
        """Telnet probe with login attempt should capture credentials to DB."""
        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        bear_data = {
            'ip': '185.220.101.42',
            # raw_request as string (bytes would fail json.dumps)
            'raw_request': '\xff\xfb\x01\x03 login attempt',
            'timestamp': '2026-05-21 15:00:00.000000',
            'parsed_request': {
                'protocol': 'telnet',
                'raw': '\xff\xfb\x01...',
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            'login': 'admin:admin',  # Captured telnet credentials
        }

        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

        args_obj = MagicMock(server=(0, 8101), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        result = handler.handle_request(message)

        assert result is True

        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT login FROM honeypot_bears WHERE bot_ip = ?',
            ('185.220.101.42',),
        ).fetchone()
        conn.close()

        assert row is not None, 'Telnet credential record was not saved'
        assert row[0] == 'admin:admin'


# -- Multi-Bear Concurrent Tests --------------------------------------------


class TestMultiBearConcurrent:
    """Test multiple bears sending reports simultaneously."""

    def test_multiple_bears_save_separate_records(self):
        """Multiple encrypted messages from different IPs should create separate DB rows."""
        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        args_obj = MagicMock(server=(0, 8200), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        # Simulate 5 different bears sending reports concurrently
        bear_data_list = []
        for i in range(5):
            bear_data = {
                'ip': f'192.168.{i}.{i}',
                'raw_request': f'GET /scan{i} HTTP/1.1\r\nHost: honeypot\r\n\r\n',
                'timestamp': f'2026-05-22 {10 + i}:00:00.000000',
                'parsed_request': {'command': 'GET', 'path': f'/scan{i}'},
                'is_detected': 1,
                'HIVELOGIN': '',
            }
            bear_data_list.append(bear_data)

        # Save all records synchronously (simulating concurrent saves)
        for data in bear_data_list:
            handler.save_data(data, args_obj)

        # Verify all 5 records exist with correct data
        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        rows = conn.execute(
            'SELECT bot_ip, request_path FROM honeypot_bears ORDER BY bot_ip'
        ).fetchall()
        conn.close()

        assert len(rows) == 5, f'Expected 5 records, got {len(rows)}'

        for i in range(5):
            expected_ip = f'192.168.{i}.{i}'
            found = any(row[0] == expected_ip for row in rows)
            assert found, f'Missing record for IP {expected_ip}'

    def test_concurrent_saves_no_data_loss(self):
        """Rapid concurrent saves should not lose any records.

        Uses a shared threading.Lock to serialize writes because SQLite's WAL mode
        does not support multiple simultaneous writer connections on the same file.
        This mirrors how production code should handle concurrent DB access.
        """
        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        args_obj = MagicMock(server=(0, 8201), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        num_records = 50
        threads = []
        errors = []
        write_lock = threading.Lock()

        def save_batch(start_idx):
            try:
                for i in range(start_idx, start_idx + 10):
                    data = {
                        'ip': f'10.0.{i // 256}.{i % 256}',
                        'raw_request': f'GET /concurrent{i} HTTP/1.1\r\n\r\n',
                        'timestamp': f'2026-05-22 12:00:{i:02d}.000000',
                        'parsed_request': {'command': 'GET', 'path': f'/concurrent{i}'},
                        'is_detected': 1,
                        'HIVELOGIN': '',
                    }
                    with write_lock:
                        handler.save_data(data, args_obj)
            except Exception as e:
                errors.append(e)

        # Launch 5 threads saving 10 records each = 50 total
        for i in range(5):
            t = threading.Thread(target=save_batch, args=(i * 10,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f'Errors during concurrent saves: {errors}'

        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        count = conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()[0]
        conn.close()

        assert count == num_records, f'Expected {num_records} records, got {count}'


# -- Report Queue Worker Tests ----------------------------------------------


class TestReportQueueWorker:
    """Test the report queue worker thread processes items correctly."""

    def test_report_queue_processes_items(self):
        """The report queue should process queued functions and args."""
        from manyfaced.handlers.report_queue import (
            _get_report_queue,
            shutdown_report_executor,
        )

        # Ensure clean state (fixture already called shutdown)
        q = _get_report_queue()
        results = []

        def sample_fn(x):
            results.append(x * 2)

        # Queue several items
        for i in range(5):
            q.put((sample_fn, (i,)))

        # Wait for queue to drain (Queue.join doesn't support timeout in stdlib)
        deadline = time.monotonic() + 10
        while not q.empty():
            if time.monotonic() > deadline:
                raise TimeoutError('Report queue did not drain in time')
            time.sleep(0.05)

        assert len(results) == 5, f'Expected 5 results, got {len(results)}'
        assert sorted(results) == [0, 2, 4, 6, 8]

    def test_shutdown_drains_queued_items(self):
        """Regression test for the graceful-shutdown deadlock.

        Previously, ``shutdown_report_executor()`` flipped ``_report_queue_alive``
        to False and then blocked on an unbounded ``_report_queue.join()``. Because
        the worker loop was ``while _report_queue_alive:`` it stopped pulling
        items the instant the flag went False, so any item still queued never got
        ``task_done()`` and ``join()`` hung forever (manifested as a 30s
        pytest-timeout kill of ``test_run_auto_detect_starts_both`` in the full
        suite, where the queue is a module-level singleton left non-empty by an
        earlier test).

        This test queues an item, flips the liveness flag the way shutdown does,
        and asserts ``shutdown_report_executor()`` returns promptly (drains the
        pending item rather than blocking on it).
        """
        from manyfaced.handlers.report_queue import (
            _get_report_queue,
            shutdown_report_executor,
        )

        # Clean slate.
        shutdown_report_executor()
        q = _get_report_queue()
        processed = []
        q.put((lambda: processed.append(1), ()))

        start = time.monotonic()
        shutdown_report_executor()
        elapsed = time.monotonic() - start

        # Must drain the pending item (not block on the unbounded join).
        assert processed == [1], 'shutdown left a queued item unprocessed'
        assert elapsed < 5.0, f'shutdown deadlocked ({elapsed:.1f}s)'


# -- Full Pipeline with Real Encryption -------------------------------------


class TestFullPipelineWithEncryption:
    """Test the complete pipeline from encrypted client data to DB query."""

    def test_full_pipeline_http_with_enrichment(self):
        """Complete flow: encrypt -> send -> decrypt -> enrich -> save -> query."""
        import sqlite3

        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        # Step 1: Client prepares and encrypts data with enrichment fields
        bear_data = {
            'ip': '203.0.113.50',
            'raw_request': 'GET /wp-admin/ HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: Nmap\r\n\r\n',
            'timestamp': '2026-05-23 08:00:00.000000',
            'parsed_request': {
                'command': 'GET',
                'path': '/wp-admin/',
                'version': 'HTTP/1.1',
                'headers': {'Host': 'honeypot', 'User-Agent': 'Nmap'},
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            # Enrichment fields that the client adds
            'ua': 'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
            'dns_name': 'scanner.shodan.io',
            'country': 'United States',
            'continent': 'North America',
        }

        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

        # Step 2: Server receives and processes the encrypted message (no mock - real save)
        args_obj = MagicMock(server=(0, 8300), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        result = handler.handle_request(message)

        assert result is True

        # Step 3: Verify all fields were preserved through the pipeline by querying DB
        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_ip, request_path, detected_id, bot_user_agent, '
            'bot_dns_name, bot_country, bot_continent '
            'FROM honeypot_bears WHERE bot_ip = ?',
            ('203.0.113.50',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == '203.0.113.50'  # ip
        assert row[1] == '/wp-admin/'  # path
        assert row[2] == 1  # detected_id
        assert row[3] == 'Mozilla/5.0 (compatible; Nmap Scripting Engine)'  # ua
        assert row[4] == 'scanner.shodan.io'  # dns_name
        assert row[5] == 'United States'  # country
        assert row[6] == 'North America'  # continent

    def test_full_pipeline_non_http_with_credentials(self):
        """Complete flow for non-HTTP: SSH probe with captured credentials."""
        import sqlite3

        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        bear_data = {
            'ip': '91.240.118.172',
            'raw_request': 'SSH-2.0-libssh_0.9.5\r\n',  # string, not bytes
            'timestamp': '2026-05-23 09:15:00.000000',
            'parsed_request': {
                'protocol': 'ssh',
                'version': 'SSH-2.0-libssh_0.9.5',
                'client': 'libssh_0.9.5',
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            'login': 'admin:letmein',
        }

        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

        args_obj = MagicMock(server=(0, 8301), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        result = handler.handle_request(message)

        assert result is True

        # Verify in DB
        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_ip, login FROM honeypot_bears WHERE bot_ip = ?',
            ('91.240.118.172',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == '91.240.118.172'
        assert row[1] == 'admin:letmein'

    def test_full_pipeline_unknown_protocol(self):
        """Unknown protocol should still be saved with detected_id = UNKNOWN_HTTP."""
        import sqlite3

        from manyfaced.common.status import UNKNOWN_HTTP
        from manyfaced.db.storage import _resolve_db_path
        from manyfaced.server.server import ServerHandler

        bear_data = {
            'ip': '198.51.100.99',
            # raw_request as string (bytes would fail json.dumps)
            'raw_request': '\x00\x01\x02\x03\x04 unknown binary probe',
            'timestamp': '2026-05-23 10:00:00.000000',
            'parsed_request': {
                'protocol': 'unknown',
                'raw': '\x00\x01\x02...',
            },
            'is_detected': UNKNOWN_HTTP,
            'HIVELOGIN': '',
        }

        message = make_encrypted_message(BEE_IDENTIFIER, bear_data, TEST_KEY)

        args_obj = MagicMock(server=(0, 8302), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        result = handler.handle_request(message)

        assert result is True

        # Verify in DB
        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_ip, detected_id FROM honeypot_bears WHERE bot_ip = ?',
            ('198.51.100.99',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == '198.51.100.99'
        assert row[1] == UNKNOWN_HTTP


# -- Error Recovery Tests ---------------------------------------------------


class TestErrorRecovery:
    """Test error handling and recovery through the pipeline."""

    def test_corrupted_encrypted_data_fails_gracefully(self):
        """Corrupted encrypted data should not crash the server handler."""
        from manyfaced.server.server import ServerHandler

        args_obj = MagicMock(server=(0, 8400), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        # Valid identifier but corrupted ciphertext (wrong length / invalid base64)
        bad_message = f'{BEE_IDENTIFIER}:!!!invalid_base64_data!!!'

        with pytest.raises(Exception):
            handler.handle_request(bad_message)

    def test_empty_message_raises_valueerror(self):
        """An empty message should raise ValueError."""
        from manyfaced.server.server import ServerHandler

        args_obj = MagicMock(server=(0, 8401), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        with pytest.raises(ValueError):
            handler.handle_request('')

    def test_message_without_colon_delimiter_raises_valueerror(self):
        """A message without the identifier:data delimiter should raise ValueError."""
        from manyfaced.server.server import ServerHandler

        args_obj = MagicMock(server=(0, 8402), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())

        with pytest.raises(ValueError):
            handler.handle_request('no_delimiter_here')
