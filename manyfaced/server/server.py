import json
import signal
import threading
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    error as socket_error,
)

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.config import settings
from manyfaced.common.utils import dump_file, receive_timeout
from manyfaced.db.dbconnect import Insert, BearRequests
from manyfaced.handlers.base_handler import BaseHandler

logger = get_logger(__name__)


class ServerHandler(BaseHandler):
    def __init__(self, args, update_event):
        super().__init__(args, update_event)

    def get_key(self, identifier):
        """Get the AES key for a given identifier.

        Rejects unknown identifiers – only explicitly configured
        AUTHORIZED_BEES entries are accepted.
        """
        key = settings.AUTHORIZED_BEES.get(identifier)
        if key is None:
            logger.warning(
                "Rejected connection from unknown identifier '%s' – "
                'not in AUTHORIZED_BEES. Connection dropped.',
                identifier,
            )
            raise ValueError(f"Unknown identifier '{identifier}' – not authorized")
        return key

    def process_request(self, data):
        """Process an incoming encrypted message from the client.

        Saves data synchronously instead of spawning a subprocess.
        SQLite writes are fast enough that async is unnecessary overhead.
        """
        self.save_data(data, self.args)
        return True

    def save_data(self, data, args):
        try:
            bear = BearRequests(
                ip=data['ip'],
                raw_request=data['raw_request'],
                timestamp=data['timestamp'],
                parsed_request=data['parsed_request'],
                is_detected=data['is_detected'],
                HIVELOGIN=data.get('HIVELOGIN', ''),
                ua=data.get('ua', ''),
                dns_name=data.get('dns_name', ''),
                country=data.get('country', ''),
                continent=data.get('continent', ''),
                login=data.get('login', ''),
                bot_profile_data=data.get('bot_profile_data'),
            )
            Insert(bear)
            logger.info('Data saved for %s', data['ip'])
            if args.verbose:
                print(f'Data saved for {data["ip"]}')
        except (ConnectionError, TypeError) as e:
            dump_file(json.dumps(data))
            logger.error('Error writing data to database: %s – dumped to file', e)
            if self.args.verbose:
                print(f'Error writing data to database: {e}, writing to file')


def _handle_client(connection_socket, addr, args, update_event):
    """Handle a single client connection in its own thread.

    Any unexpected error is contained here: a malformed or failing report must
    never terminate the handler thread (or, if unhandled, the server process).
    """
    try:
        message = receive_timeout(connection_socket)
        handler = ServerHandler(args, update_event)
        response = handler.handle_request(message)
        if isinstance(response, bool):
            response = '200 OK'
        elif not isinstance(response, str):
            response = str(response)
        connection_socket.send(response.encode())
    except socket_error as e:
        logger.warning('Socket error from %s: %s', addr, e)
    except (ValueError, TypeError, KeyError, ImportError) as e:
        logger.error('Unexpected error handling request from %s: %s', addr, e)
        try:
            connection_socket.send(b'CODE 300 ERROR')
        except socket_error:
            # Client already gone (or socket torn down) — nothing more to send.
            pass
    except Exception as e:  # noqa: BLE001 - last-resort containment
        logger.exception('Unhandled error handling request from %s: %s', addr, e)
        try:
            connection_socket.send(b'CODE 300 ERROR')
        except socket_error:
            # Client already gone (or socket torn down) — nothing more to send.
            pass
    finally:
        connection_socket.close()


def main(args, update_event):
    logger.info('Server honeypot listening on port %d', args.server)
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    # Observability: start periodic structured stats logging (issue #166).
    from manyfaced.common.metrics import start_stats_logger

    start_stats_logger()
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('', args.server))
    server_socket.listen(128)  # queue up to 128 pending report connections
    if args.verbose:
        print('Awaiting for bears on port %s' % args.server)
    while True:
        if update_event.is_set():
            break
        connection_socket: socket | None = None
        try:
            connection_socket, addr = server_socket.accept()
        except KeyboardInterrupt:
            break
        except OSError as e:
            # Transient accept error (e.g. socket temporarily unavailable).
            # Do not crash the server; keep serving.
            logger.warning('Accept error, continuing: %s', e)
            continue
        # Handle each client in a separate thread to avoid blocking new connections
        t = threading.Thread(
            target=_handle_client,
            args=(connection_socket, addr, args, update_event),
            daemon=True,
        )
        t.start()

    server_socket.close()
