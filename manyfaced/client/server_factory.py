"""Server factory for honeypot client.

Provides functions to create single-port and multi-port honeypot servers.
Extracted from client.py to reduce cyclomatic complexity of the main module.
"""

import socket
import threading
from multiprocessing import Event
from typing import TYPE_CHECKING

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.status import BOT_TIMEOUT
from manyfaced.common.utils import receive_timeout
from manyfaced.handlers.http_handler import HTTPHandler

if TYPE_CHECKING:
    from socket import socket as SocketType

logger = get_logger(__name__)


def _setup_server_socket(port: int) -> 'SocketType | None':
    """Create and bind a TCP server socket on the given port.

    Args:
        port: Port number to listen on.

    Returns:
        Bound and listening socket, or None if binding failed.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', port))
    except PermissionError:
        logger.warning(
            'Permission denied binding to port %d (try running as root or use a higher port)',
            port,
        )
        return None
    except OSError as e:
        logger.warning('Failed to bind to port %d: %s', port, e)
        return None
    server_socket.listen(1)
    return server_socket


def _handle_bot_connection(
    connection_socket: 'socket.socket',
    args,
    bot_addr: tuple,
    update_event: Event,
) -> None:
    """Handle a single bot connection: receive request, generate response, send reply.

    Args:
        connection_socket: The client socket to communicate with the bot.
        args: CLI arguments namespace.
        bot_addr: Tuple of (ip, port) from the accepting socket.
        update_event: Event to signal shutdown.
    """
    message = receive_timeout(connection_socket, BOT_TIMEOUT)
    if not message:
        return

    bot_ip = bot_addr[0] if bot_addr else '127.0.0.1'
    handler = HTTPHandler(args, update_event)
    output_data = handler.handle_request(message, bot_ip=bot_ip)

    try:
        logger.debug('Sending response of length %d', len(output_data))
        connection_socket.sendall(
            output_data if isinstance(output_data, bytes) else output_data.encode('iso-8859-1')
        )
        # For SSH connections, keep the connection open to capture credentials
        if isinstance(output_data, bytes) and output_data.startswith(b'SSH-'):
            from manyfaced.client.ssh_creds import _capture_ssh_credentials

            ssh_creds = _capture_ssh_credentials(connection_socket, bot_ip)
            if ssh_creds:
                logger.info('Captured SSH credentials from %s: %s', bot_ip, ssh_creds)
    except socket.error:
        pass
    finally:
        connection_socket.close()


def create_server(args, update_event: Event, port: int) -> bool:
    """Create a single-port honeypot server.

    Args:
        args: CLI arguments namespace
        update_event: Event to signal shutdown
        port: Port number to listen on

    Returns:
        True if server started successfully, False otherwise.
    """
    server_socket = _setup_server_socket(port)
    if server_socket is None:
        return False

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
            _handle_bot_connection(connection_socket, args, bot_addr, update_event)
    finally:
        server_socket.close()
    return True


def create_multiport_server(args, update_event: Event, ports: list[int]) -> None:
    """Create a multi-port honeypot server that listens on multiple ports simultaneously.

    Each port runs in its own thread. All threads share the same update_event for shutdown.
    Failed port bindings are logged but don't prevent other ports from starting.

    Args:
        args: CLI arguments namespace
        update_event: Event to signal shutdown
        ports: List of port numbers to listen on
    """
    # Filter out the server port to avoid "Address already in use" conflicts
    server_port = getattr(args, 'server', None)
    if server_port is not None and server_port in ports:
        ports = [p for p in ports if p != server_port]

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
        failed_str = ', '.join(f'{p}' for p, _ in failed_ports)
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
