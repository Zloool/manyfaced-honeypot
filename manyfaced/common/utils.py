import json
import os
from socket import error as socket_error, timeout as socket_timeout

from manyfaced.common.config import settings
from manyfaced.common.logging_setup import get_logger
from manyfaced.common.status import CLIENT_TIMEOUT

logger = get_logger(__name__)

# Default JSONL dump path – overridable via settings.DUMP_FILE or env var
_DUMP_FILE = os.environ.get("MANYFACED_DUMP_FILE", "/var/lib/manyfaced/dump.jsonl")


def dump_file(data):
    """Append *data* as a single JSON line to the dump file.

    Each call appends one JSON-serialisable object (dict, list, str, …).
    The file is created with 0600 permissions if it does not exist.
    """
    path = getattr(settings, "DUMP_FILE", _DUMP_FILE)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        pass
    with open(path, "a") as f:
        f.write(json.dumps(data, default=str) + "\n")


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
        pass
    finally:
        the_socket.settimeout(None)  # Reset to blocking

    raw = b"".join(total_data)
    result = raw.decode("utf-8", errors="replace")
    logger.debug(
        "receive_timeout: received %d bytes, repr=%r", len(raw), repr(result[:200])
    )
    return result
