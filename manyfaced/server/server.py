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
from manyfaced.common.classification import classify
from manyfaced.db.dbconnect import Insert, BearRequests
from manyfaced.handlers.base_handler import BaseHandler

logger = get_logger(__name__)


def _port_from_host(host: object) -> int:
    """Extract a trailing :port from a `host[:port]` string, else 0.

    The ``metadata.host`` value inside ``bot_profile_data`` carries the
    real honeypot host + port the bot actually hit (e.g. ``68.183.114.1:10110``).
    When the top-level ``listen_port`` is 0/empty we recover the port from this
    suffix so orphan rows become attributable (issue #450 / #516).
    """
    if not isinstance(host, str) or not host:
        return 0
    if ':' in host:
        suffix = host.rsplit(':', 1)[-1]
        if suffix.isdigit():
            return int(suffix)
    return 0


def _promote_attribution(data: dict) -> dict:
    """Recover attribution fields from the ``bot_profile_data`` JSON blob.

    A capture row frequently arrives with empty top-level ``ip`` / ``asn`` /
    ``org`` / ``ua`` / ``dns_name`` / ``country`` / ``continent`` / ``login`` /
    ``listen_port`` while the *same* row's ``bot_profile_data`` JSON carries the
    real values (``bot_ip``, ``metadata.host`` → port, per-handler network
    signals). This happens for the uncategorized slice (issue #516) and for
    orphan port=0 rows (issue #450).

    Top-level flat fields always win when populated. The JSON is only a
    fallback so a genuinely attributable row is never stored as anonymous.

    Args:
        data: The decrypted report dict received from the client.

    Returns:
        A dict with the (possibly promoted) attribution fields: ip, asn, org,
        ua, dns_name, country, continent, login, listen_port.
    """
    flat = {
        'ip': data.get('ip') or '',
        'asn': data.get('asn') or '',
        'org': data.get('org') or '',
        'ua': data.get('ua') or '',
        'dns_name': data.get('dns_name') or '',
        'country': data.get('country') or '',
        'continent': data.get('continent') or '',
        'login': data.get('login') or '',
        'listen_port': data.get('listen_port') or 0,
    }

    bp = data.get('bot_profile_data')
    if isinstance(bp, str):
        try:
            bp = json.loads(bp)
        except (ValueError, TypeError):
            bp = None
    if not isinstance(bp, dict):
        return flat

    # Recover bot_ip when the flat column is empty.
    if not flat['ip']:
        json_ip = bp.get('bot_ip')
        if isinstance(json_ip, str) and json_ip:
            flat['ip'] = json_ip

    # Recover listen_port from metadata.host[:port] when the flat port is 0/empty.
    if not flat['listen_port']:
        meta = bp.get('metadata')
        if isinstance(meta, dict):
            flat['listen_port'] = _port_from_host(meta.get('host'))
        # Some profiles nest network signals directly; try a top-level host too.
        if not flat['listen_port']:
            flat['listen_port'] = _port_from_host(bp.get('host'))

    # Recover network/attribution signals emitted by handlers inside the JSON.
    for key in ('asn', 'org', 'ua', 'dns_name', 'country', 'continent', 'login'):
        if not flat[key]:
            val = bp.get(key)
            if isinstance(val, str) and val:
                flat[key] = val
            elif isinstance(val, dict) and val.get(key):
                # Occasionally a sub-dict holds the value (defensive).
                sub = val.get(key)
                if isinstance(sub, str) and sub:
                    flat[key] = sub

    return flat


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
            # Promote attribution fields that may only exist inside the
            # bot_profile_data JSON blob (issue #516 / #517). Genuine captures
            # frequently arrive with an empty top-level `ip`/`asn`/`org`/`
            # classification` while the SAME row's bot_profile_data JSON carries
            # the real `bot_ip` + `metadata.host` (which embeds the real port).
            # We fall back to those values so the row is attributable instead of
            # anonymous. The top-level flat fields always win when populated.
            promoted = _promote_attribution(data)

            # Classify the source as benign/unknown from the signals the client
            # already shipped (reverse DNS + UA); ASN/org are resolved at the
            # client (resolve_geo) and forwarded alongside country/continent
            # (issue #271). classify() is pure and cheap.
            asn = promoted['asn'] or ''
            org = promoted['org'] or ''
            classification, benign_source = classify(
                reverse_dns=promoted['dns_name'] or '',
                org=org,
                asn=asn,
                user_agent=promoted['ua'] or '',
            )
            bear = BearRequests(
                ip=promoted['ip'],
                raw_request=data['raw_request'],
                timestamp=data['timestamp'],
                parsed_request=data['parsed_request'],
                is_detected=data['is_detected'],
                HIVELOGIN=data.get('HIVELOGIN', ''),
                ua=promoted['ua'],
                dns_name=promoted['dns_name'],
                country=promoted['country'],
                continent=promoted['continent'],
                login=promoted['login'],
                bot_profile_data=data.get('bot_profile_data'),
                listen_port=promoted['listen_port'] or 0,
                asn=asn,
                org=org,
                classification=classification,
                benign_source=benign_source,
            )
            Insert(bear)
            logger.info('Data saved for %s', promoted['ip'])
            if args.verbose:
                print(f'Data saved for {promoted["ip"]}')
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
            logger.debug('swallowed exception', exc_info=True)
    except Exception as e:  # noqa: BLE001 - last-resort containment
        logger.exception('Unhandled error handling request from %s: %s', addr, e)
        try:
            connection_socket.send(b'CODE 300 ERROR')
        except socket_error:
            # Client already gone (or socket torn down) — nothing more to send.
            logger.debug('swallowed exception', exc_info=True)
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
