"""Tests for manyfaced.server.server._handle_client error containment."""

from socket import error as socket_error
from unittest.mock import MagicMock

from manyfaced.server import server


def _make_args():
    args = MagicMock()
    args.verbose = False
    args.server = 8888
    return args


def test_handle_client_contains_socket_error():
    """A socket error while reading is contained (no crash, socket closed)."""
    sock = MagicMock()
    sock.recv.side_effect = socket_error('connection reset')

    server._handle_client(sock, ('1.2.3.4', 5000), _make_args(), MagicMock())
    sock.close.assert_called_once()


def test_handle_client_contains_value_error():
    """An unauthorised identifier raises ValueError, contained and answered."""
    sock = MagicMock()
    sock.recv.side_effect = [b'some-encrypted-bytes', b'']

    server._handle_client(sock, ('1.2.3.4', 5000), _make_args(), MagicMock())
    sock.send.assert_called_once()
    assert b'ERROR' in sock.send.call_args[0][0]


def test_handle_client_contains_unexpected_exception():
    """A generic exception is contained by the last-resort handler."""
    sock = MagicMock()
    sock.recv.side_effect = [b'payload', b'']

    server._handle_client(sock, ('1.2.3.4', 5000), _make_args(), MagicMock())
    sock.close.assert_called_once()
