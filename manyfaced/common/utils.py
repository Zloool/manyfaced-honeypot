import json
import os
from socket import error as socket_error, timeout as socket_timeout

from manyfaced.common.config import settings
from manyfaced.common.logging_setup import get_logger
from manyfaced.common.status import CLIENT_TIMEOUT

logger = get_logger(__name__)

# --- non-HTTP exchange timing -------------------------------------------------
# How long to wait for the first byte of a client-first request frame.
EXCHANGE_TIMEOUT = 5.0
# After the first chunk, how long to keep draining trailing bytes of the same
# frame before deciding the frame is complete (request/response protocols,
# where the server must reply promptly rather than wait for idle/close).
RECVLINE_IDLE = 0.3

# Default JSONL dump path – overridable via settings.DUMP_FILE or env var
_DUMP_FILE = os.environ.get('MANYFACED_DUMP_FILE', 'dump.jsonl')


def dump_file(data):
    """Append *data* as a single JSON line to the dump file.

    Each call appends one JSON-serialisable object (dict, list, str, …).
    The file is created with 0600 permissions if it does not exist.
    """
    path = getattr(settings, 'DUMP_FILE', _DUMP_FILE)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        # Directory already exists or parent is not creatable — best-effort.
        logger.debug('swallowed exception', exc_info=True)
    with open(path, 'a') as f:
        f.write(json.dumps(data, default=str) + '\n')


def receive_first_frame(the_socket, timeout=EXCHANGE_TIMEOUT):
    """Read a single client frame for a request/response (non-HTTP) exchange.

    Unlike :func:`receive_timeout` (which loops until the connection goes idle
    or closes — appropriate for HTTP requests and SSH credential capture), this
    returns as soon as the peer's frame has been read, so the server can reply
    promptly. It reads the first chunk, then keeps draining any immediately
    following chunks with a short idle timeout (to coalesce a frame that
    arrived in multiple TCP segments) and stops on the first idle gap.

    Args:
        the_socket: The client socket.
        timeout: Max time to wait for the first byte.

    Returns:
        The raw frame as ``bytes`` (so binary protocols such as MongoDB OP_MSG
        are preserved verbatim — issue #597) or ``b''`` if nothing arrived.
        Callers that need text decode with ``latin-1`` (lossless) deliberately.
    """
    the_socket.settimeout(timeout)
    chunks: list[bytes] = []
    try:
        while True:
            try:
                data = the_socket.recv(8192)
            except socket_timeout:
                break  # idle gap → frame complete (or no data at all)
            if not data:
                break  # peer closed
            chunks.append(data)
            # After the first chunk, only wait a brief moment for trailing bytes
            # of the same frame; a longer idle means the frame is finished.
            the_socket.settimeout(RECVLINE_IDLE)
    except socket_error:
        logger.debug('swallowed exception', exc_info=True)
    finally:
        the_socket.settimeout(None)  # reset to blocking for the reply
    return b''.join(chunks)


def receive_timeout(the_socket, timeout=CLIENT_TIMEOUT):
    """Receive data from a socket with a timeout.

    Uses blocking mode with settimeout() for reliable data reception.
    """
    the_socket.settimeout(timeout)
    total_data = []
    try:
        while True:
            try:
                data = the_socket.recv(8192)
                if data:
                    total_data.append(data)
                else:
                    # Connection closed by peer
                    break
            except socket_timeout:
                # Timeout reached, return what we have
                break
    except socket_error:
        # Receive was interrupted by a non-timeout socket error; return what we
        # have so far rather than raising into the caller.
        logger.debug('swallowed exception', exc_info=True)
    finally:
        the_socket.settimeout(None)  # Reset to blocking

    raw = b''.join(total_data)
    result = raw.decode('utf-8', errors='replace')
    logger.debug('receive_timeout: received %d bytes, repr=%r', len(raw), repr(result[:200]))
    return result
