"""Honeypot client – serves fake web services to scanning bots.

The client listens on one or more ports, receives raw HTTP requests from
bots, and uses the handler registry (in ``manyfaced.handlers``) to generate
realistic honeypot responses. Reports are sent to the server via encrypted
TCP connections.

Architecture::

    Bot connects → create_server() → HTTPHandler.handle_request()
                                          → Router.dispatch() (first match wins)
                                          → ServiceHandler.generate_response()
                                          → send_report() (encrypted to server)
"""

import signal
from multiprocessing import Event
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    error as socket_error,
)

from manyfaced.client.report_sender import send_report
from manyfaced.client.ssh_creds import _capture_ssh_credentials
from manyfaced.common.config import settings
from manyfaced.common.logging_setup import get_logger
from manyfaced.common.myenc import AESCipher
from manyfaced.common.ports import DEFAULT_TOP_PORTS as _DEFAULT_TOP_PORTS
from manyfaced.common.status import BOT_TIMEOUT
from manyfaced.handlers.http_handler import HTTPHandler
from manyfaced.common.utils import dump_file, receive_timeout

logger = get_logger(__name__)


def create_server(args, update_event: Event, port: int):
    """Create a single-port honeypot server.

    Args:
        args: CLI arguments namespace.
        update_event: Event to signal shutdown.
        port: Port number to listen on.

    Returns:
        True if server started successfully, False otherwise.
    """
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', port))
    except PermissionError:
        logger.warning(
            'Permission denied binding to port %d (try running as root or use a higher port)',
            port,
        )
        return False
    except OSError as e:
        logger.warning('Failed to bind to port %d: %s', port, e)
        return False
    server_socket.listen(1)
    logger.info('Client honeypot listening on port %d', port)
    if args.verbose:
        print(f'Serving honey on port {port}')
    try:
        while True:
            if update_event.is_set():
                break
            connection_socket = None
            try:
                connection_socket, bot_addr = server_socket.accept()
            except KeyboardInterrupt:
                break
            try:
                message = receive_timeout(connection_socket, BOT_TIMEOUT)
            except socket_error:
                if args.verbose:
                    print('Failed to receive data from bot')
                continue
            bot_ip = bot_addr[0] if bot_addr else '127.0.0.1'
            handler = HTTPHandler(args, update_event)
            result = handler.handle_request(message, bot_ip=bot_ip)

            # Handle different return types from handle_request
            if isinstance(result, tuple):
                output_data, bear_storage = result
            else:
                output_data = result
                bear_storage = None

            try:
                logger.debug('Sending response of length %d', len(output_data))
                connection_socket.sendall(
                    output_data
                    if isinstance(output_data, bytes)
                    else output_data.encode('iso-8859-1')
                )
                # For SSH connections, keep the connection open to capture credentials
                if isinstance(output_data, bytes) and output_data.startswith(b'SSH-'):
                    ssh_creds = _capture_ssh_credentials(connection_socket, bot_ip)
                    if ssh_creds and bear_storage is not None:
                        # Update BearStorage with captured credentials before report is sent
                        bear_storage.login = ssh_creds
                        logger.info(
                            'Captured SSH credentials from %s: %s',
                            bot_ip,
                            ssh_creds,
                        )
                    # Send report AFTER credential capture so login field has real creds
                    if bear_storage is not None:
                        handler._enrich_and_send(bear_storage, bot_ip)
                connection_socket.close()
            except socket_error:
                if args.verbose:
                    print('Failed to send response to bot')
                continue
    finally:
        server_socket.close()


def create_multiport_server(args, update_event: Event, ports: list[int]):
    """Create a multi-port honeypot server that listens on multiple ports simultaneously.

    Each port runs in its own thread. All threads share the same update_event for shutdown.
    Failed port bindings are logged but don't prevent other ports from starting.

    Args:
        args: CLI arguments namespace.
        update_event: Event to signal shutdown.
        ports: List of port numbers to listen on.
    """
    # Filter out the server port to avoid "Address already in use" conflicts
    server_port = getattr(args, 'server', None)
    if server_port is not None and server_port in ports:
        ports = [p for p in ports if p != server_port]

    import threading

    threads: list[threading.Thread] = []
    successful_ports: list[int] = []
    failed_ports: list[tuple[int, str]] = []

    def _port_worker(port: int) -> None:
        """Wrapper that tracks success/failure for each port."""
        result = create_server(args, update_event, port)
        if result:
            successful_ports.append(port)
        else:
            failed_ports.append((port, 'bind failed'))

    for port in ports:
        t = threading.Thread(
            target=_port_worker,
            args=(port,),
            name=f'honeyport-{port}',
            daemon=True,
        )
        threads.append(t)

    # Start all threads
    for t in threads:
        t.start()

    # Wait for all port threads to finish starting
    for t in threads:
        t.join(timeout=5)

    # Log summary
    if successful_ports:
        port_list_str = ', '.join(str(p) for p in successful_ports)
        logger.info(
            'Client honeypot listening on %d ports: %s',
            len(successful_ports),
            port_list_str,
        )
        if args.verbose:
            print(f'Serving honey on {len(successful_ports)} ports: {port_list_str}')

    if failed_ports:
        failed_str = ', '.join(str(p) for p, _ in failed_ports)
        logger.warning('Failed to bind on %d ports (skipped): %s', len(failed_ports), failed_str)

    # Wait for shutdown signal
    try:
        while not update_event.is_set():
            update_event.wait(timeout=1)
    except KeyboardInterrupt:
        pass

    # Wait for all threads to finish
    for t in threads:
        t.join(timeout=5)

    logger.info('All honeypot threads stopped')


def main(args, update_event):
    """Main entry point for the honeypot client.

    Supports single-port, top-ports, and all-ports modes.

    Args:
        args: CLI arguments namespace.
        update_event: Event to signal shutdown.
    """
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    port_mode = getattr(args, 'port_mode', 'single')
    top_ports = getattr(args, 'top_ports', '')

    if port_mode == 'all':
        ports = list(range(1, 65536))
        logger.warning('Listening on ALL 65535 ports – this may take time to start')
        print('WARNING: Listening on all 65535 TCP ports...')
        create_multiport_server(args, update_event, ports)
    elif port_mode == 'top':
        if top_ports:
            try:
                ports = sorted({int(p.strip()) for p in top_ports.split(',') if p.strip()})
            except ValueError:
                logger.error(
                    'Invalid --top-ports value: %s. Must be comma-separated integers.',
                    top_ports,
                )
                raise ValueError(
                    f'Invalid --top-ports value: {top_ports!r}. Must be comma-separated integers.'
                ) from None
        else:
            ports = _DEFAULT_TOP_PORTS
        create_multiport_server(args, update_event, ports)
    else:
        port = args.client
        create_server(args, update_event, port)
