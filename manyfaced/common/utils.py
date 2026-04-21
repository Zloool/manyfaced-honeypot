import pickle
from socket import error as socket_error, timeout as socket_timeout

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.status import CLIENT_TIMEOUT

logger = get_logger(__name__)


def dump_file(data):
    try:
        with open("temp.db", "rb") as f:
            string_file = f.read()
        db = pickle.loads(string_file)
    except (pickle.PicklingError, FileNotFoundError):
        db = list()
    db.append(data)
    with open("temp.db", "wb") as f:
        f.write(pickle.dumps(db))


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
    logger.debug("receive_timeout: received %d bytes, repr=%r", len(raw), repr(result[:200]))
    return result
