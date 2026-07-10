"""
Tests for manyfaced.common.utils, manyfaced.common.config, and manyfaced.common.arguments.

Usage:
    /usr/bin/python3 -m pytest test/test_utils_config_args.py -v -c /home/zlol/manyfaced-honeypot/pytest.ini
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ---------------------------------------------------------------------------
# Mock geoip modules before any module that uses it is imported
# ---------------------------------------------------------------------------
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules['geoip'] = geoip_mock
sys.modules['geoip.geolite2'] = geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()

# ---------------------------------------------------------------------------
# Import units under test
# ---------------------------------------------------------------------------
from manyfaced.common.utils import dump_file, receive_timeout


# ===================================================================
# Helper utilities
# ===================================================================


class _TempDumpFile:
    """Context manager that patches dump_file to use a temp file."""

    def __init__(self, path):
        self.path = str(path)
        self._mock = None

    def __enter__(self):
        self._real_open = open
        self._mock = patch('manyfaced.common.utils.open', self._patched_open)
        self._mock.start()
        return self.path

    def __exit__(self, *exc):
        if self._mock:
            self._mock.stop()

    def _patched_open(self, path, mode, *args, **kwargs):
        return self._real_open(self.path, mode, *args, **kwargs)


def _write_toml(tmp_path, content):
    """Write a TOML file and return its Path."""
    toml_path = tmp_path / 'config.toml'
    toml_path.write_text(content)
    return toml_path


def _make_time_counter(start=1000.0, increment=0.1):
    """Create a time.time() side_effect that increments by `increment` each call."""
    counter = [0]

    def side_effect():
        counter[0] += 1
        return start + counter[0] * increment

    return side_effect


# ===================================================================
# utils.py  –  dump_file / receive_timeout
# ===================================================================


class TestDumpFile:
    """Tests for dump_file(data): appends JSON lines to a JSONL file."""

    def test_creates_file_and_writes_data(self, tmp_path):
        """dump_file creates the dump file, writes JSON line with data."""
        dump_path = tmp_path / 'dump.jsonl'
        with _TempDumpFile(dump_path):
            dump_file({'key': 'value'})
        lines = dump_path.read_text().strip().split('\n')
        assert len(lines) == 1
        assert json.loads(lines[0]) == {'key': 'value'}

    def test_appends_to_existing_file(self, tmp_path):
        """dump_file appends data as a new JSON line."""
        dump_path = tmp_path / 'dump.jsonl'
        # Pre-seed one line
        dump_path.write_text('{"first": 1}\n')

        with _TempDumpFile(dump_path):
            dump_file({'second': 2})

        lines = dump_path.read_text().strip().split('\n')
        assert len(lines) == 2
        assert json.loads(lines[0]) == {'first': 1}
        assert json.loads(lines[1]) == {'second': 2}

    def test_handles_missing_file(self, tmp_path):
        """dump_file handles missing dump file gracefully (creates new file)."""
        dump_path = tmp_path / 'dump.jsonl'
        assert not dump_path.exists()

        with _TempDumpFile(dump_path):
            dump_file('new_data')

        lines = dump_path.read_text().strip().split('\n')
        assert len(lines) == 1
        assert json.loads(lines[0]) == 'new_data'

    def test_multiple_appends(self, tmp_path):
        """Multiple dump_file calls accumulate data."""
        dump_path = tmp_path / 'dump.jsonl'

        with _TempDumpFile(dump_path):
            dump_file('item1')
            dump_file('item2')
            dump_file('item3')

        lines = dump_path.read_text().strip().split('\n')
        assert len(lines) == 3
        assert json.loads(lines[0]) == 'item1'
        assert json.loads(lines[1]) == 'item2'
        assert json.loads(lines[2]) == 'item3'

    def test_dump_file_with_dict_data(self, tmp_path):
        """dump_file handles dict data correctly."""
        dump_path = tmp_path / 'dump.jsonl'
        with _TempDumpFile(dump_path):
            dump_file({'url': 'http://example.com', 'method': 'GET'})
        lines = dump_path.read_text().strip().split('\n')
        assert json.loads(lines[0]) == {'url': 'http://example.com', 'method': 'GET'}

    def test_dump_file_with_bytes_data(self, tmp_path):
        """dump_file handles bytes data (converted to string via default=str)."""
        dump_path = tmp_path / 'dump.jsonl'
        with _TempDumpFile(dump_path):
            dump_file(b'raw bytes data')
        lines = dump_path.read_text().strip().split('\n')
        # bytes → str via default=str → "b'raw bytes data'"
        assert json.loads(lines[0]) == "b'raw bytes data'"

    def test_dump_file_is_append_only(self, tmp_path):
        """dump_file never truncates the file – it always appends."""
        dump_path = tmp_path / 'dump.jsonl'
        dump_path.write_text('{"existing": true}\n{"more": 1}\n')

        with _TempDumpFile(dump_path):
            dump_file({'new': 'entry'})

        lines = dump_path.read_text().strip().split('\n')
        assert len(lines) == 3
        assert json.loads(lines[0]) == {'existing': True}
        assert json.loads(lines[1]) == {'more': 1}
        assert json.loads(lines[2]) == {'new': 'entry'}


class TestReceiveTimeout:
    """Tests for receive_timeout(the_socket, timeout): uses settimeout() for reliable data reception.

    The current implementation uses socket.settimeout() and catches socket.timeout.
    Socket recv() returns bytes, so we mock it to return bytes.
    """

    def test_assembles_multiple_receives(self, monkeypatch):
        """receive_timeout assembles data from multiple recv calls until timeout."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()
        data_chunks = [
            b'HTTP/1.1 200 OK\r\n',
            b'Content-Type: text/html\r\n',
            b'\r\n',
            b'<!DOCTYPE html>',
        ]

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            if idx < len(data_chunks):
                return data_chunks[idx]
            raise socket_timeout('timed out')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>'
        mock_socket.settimeout.assert_any_call(1.0)  # set timeout
        mock_socket.settimeout.assert_any_call(None)  # reset in finally
        assert mock_socket.recv.call_count == len(data_chunks) + 1  # +1 for timeout

    def test_returns_empty_on_immediate_empty(self, monkeypatch):
        """receive_timeout returns empty string when peer closes connection immediately."""
        mock_socket = MagicMock()
        mock_socket.recv = MagicMock(return_value=b'')

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == ''
        mock_socket.settimeout.assert_any_call(1.0)

    def test_timeout_breaks_after_data_received(self, monkeypatch):
        """receive_timeout breaks out of loop after timeout once data has been received."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()
        data_chunks = [b'data1', b'data2', b'data3', b'data4', b'data5']

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            if idx < len(data_chunks):
                return data_chunks[idx]
            raise socket_timeout('timed out')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == 'data1data2data3data4data5'

    def test_timeout_without_data(self, monkeypatch):
        """receive_timeout returns empty after timeout even with no data."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()

        recv_count = [0]

        def side_effect(*args):
            recv_count[0] += 1
            raise socket_timeout('timed out')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == ''

    def test_refreshes_begin_on_data(self, monkeypatch):
        """receive_timeout collects all data until timeout."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()
        data_chunks = [b'a', b'b', b'c']

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            if idx < len(data_chunks):
                return data_chunks[idx]
            raise socket_timeout('timed out')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == 'abc'

    def test_socket_error_handled(self, monkeypatch):
        """receive_timeout catches socket.error and returns collected data."""
        from socket import error as socket_error, timeout as socket_timeout

        mock_socket = MagicMock()

        recv_count = [0]

        def side_effect(*args):
            recv_count[0] += 1
            if recv_count[0] == 1:
                return b'partial'
            raise socket_error('would block')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        # socket_error is caught; returns data collected before the error
        assert result == 'partial'

    def test_single_chunk(self, monkeypatch):
        """receive_timeout handles a single recv call with data then timeout."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()

        recv_count = [0]

        def side_effect(*args):
            recv_count[0] += 1
            if recv_count[0] == 1:
                return b'hello'
            raise socket_timeout('timed out')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == 'hello'

    def test_timeout_exactly_at_timeout2(self, monkeypatch):
        """receive_timeout breaks on socket.timeout with no data."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()
        mock_socket.recv = MagicMock(side_effect=socket_timeout('timed out'))

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == ''

    def test_data_then_timeout(self, monkeypatch):
        """receive_timeout collects data, then times out after receiving data."""
        from socket import timeout as socket_timeout

        mock_socket = MagicMock()

        recv_count = [0]

        def side_effect(*args):
            recv_count[0] += 1
            if recv_count[0] == 1:
                return b'hello'
            if recv_count[0] == 2:
                return b' world'
            raise socket_timeout('timed out')

        mock_socket.recv = MagicMock(side_effect=side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == 'hello world'


class TestReceiveFirstFrame:
    """Tests for receive_first_frame (issue #377 client-first fix).

    Unlike receive_timeout, this must return as soon as the peer's frame is
    read (short idle gap), not block until the connection idles/closes.
    """

    def test_returns_frame_and_does_not_block_for_idle(self):
        """A single recv that returns data should return promptly, NOT wait
        the full timeout for the connection to go idle (that was the bug that
        made client-first faces time out before replying)."""
        from socket import timeout as socket_timeout

        from manyfaced.common.utils import RECVLINE_IDLE, receive_first_frame

        # recv returns one chunk, then idles (timeout) -> frame complete.
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b'PING', socket_timeout('idle')]

        result = receive_first_frame(mock_socket, timeout=5.0)

        assert result == 'PING'
        # Only the first recv waits the full timeout; trailing recvs use RECVLINE_IDLE.
        assert mock_socket.recv.call_count == 2
        # Second recv uses the short idle timeout, not the full 5s.
        idle_calls = [
            c
            for c in mock_socket.settimeout.call_args_list
            if c.args and c.args[0] == RECVLINE_IDLE
        ]
        assert idle_calls, 'idle recv did not switch to RECVLINE_IDLE'

    def test_coalesces_multi_segment_frame(self):
        """Trailing bytes that arrive within the idle window are kept."""
        from socket import timeout as socket_timeout

        from manyfaced.common.utils import receive_first_frame

        mock_socket = MagicMock()
        # chunk1, chunk2 (within idle), then idle.
        CRLF = bytes([13, 10])
        mock_socket.recv.side_effect = [b'*1' + CRLF, b'$4' + CRLF, socket_timeout('idle')]

        result = receive_first_frame(mock_socket, timeout=5.0)

        crlf = chr(13) + chr(10)
        assert result == '*1' + crlf + '$4' + crlf

    def test_empty_when_peer_closes_immediately(self):
        from manyfaced.common.utils import receive_first_frame

        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b'']  # peer closed

        result = receive_first_frame(mock_socket, timeout=1.0)

        assert result == ''
