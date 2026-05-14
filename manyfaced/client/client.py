"""Honeypot client – serves fake web services to scanning bots.

The client listens on one or more ports, receives raw HTTP requests from
bots, and uses the handler registry (in ``manyfaced.handlers``) to generate
realistic honeypot responses. Reports are sent to the server via encrypted
TCP connections.

Architecture::

    Bot connects → create_server() → HTTPHandler.handle_request()
                                          → HandlerRegistry.generate_response()
                                          → ServiceHandler (WordPress, phpMyAdmin, etc.)
                                          → send_report() (encrypted to server)
"""

import json
import signal
import threading
from multiprocessing import Event
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    error as socket_error,
)

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.myenc import AESCipher
from manyfaced.common.status import BOT_TIMEOUT
from manyfaced.handlers.http_handler import HTTPHandler
from manyfaced.common.utils import dump_file, receive_timeout

logger = get_logger(__name__)

# Default top 50 ports for --top-ports mode (extracted to avoid duplication)
_DEFAULT_TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    5901,
    6379,
    8080,
    8443,
    9200,
    11211,
    27017,
    5672,
    15672,
    4369,
    2181,
    9090,
    8888,
    7001,
    7002,
    11300,
    11301,
    11302,
    11303,
    11304,
    11305,
    11306,
    11307,
    11308,
    11309,
    11310,
    11311,
    5000,
]


def _capture_ssh_credentials(connection_socket: socket, bot_ip: str) -> str | None:
    """Capture SSH credentials by keeping the connection open and parsing auth messages.

    Args:
        connection_socket: The open socket connection to the bot.
        bot_ip: IP address of the bot.

    Returns:
        String with captured credentials, or None if no credentials captured.
    """
    try:
        # Set a longer timeout for SSH credential capture
        connection_socket.settimeout(30)
        all_data = b''
        while True:
            try:
                data = connection_socket.recv(4096)
                if not data:
                    break
                all_data += data
                # Check if we have enough data to parse
                if len(all_data) > 500:
                    break
            except socket.timeout:
                break
            except socket_error:
                break

        if all_data:
            # Decode the data
            raw_str = all_data.decode('utf-8', errors='replace')
            # Look for username/password in the raw data
            # SSH auth messages contain username and password in plaintext
            # for password authentication
            creds = _parse_ssh_auth_data(raw_str)
            if creds:
                return creds
            # If no structured credentials found, log the raw data
            logger.debug(
                'SSH raw data from %s: %s',
                bot_ip,
                repr(all_data[:200]),
            )
            return f'SSH data: {repr(all_data[:100])}'
    except Exception as e:
        logger.debug('Error capturing SSH credentials from %s: %s', bot_ip, e)
    return None


def _parse_ssh_auth_data(raw_data: str) -> str | None:
    """Parse SSH authentication data to extract credentials.

    Args:
        raw_data: Raw SSH protocol data as string.

    Returns:
        String with extracted credentials, or None.
    """
    # SSH password authentication sends username and password in plaintext
    # Look for common patterns in SSH auth messages
    # The SSH protocol sends username in SSH_MSG_USERAUTH_REQUEST
    # and password in SSH_MSG_USERAUTH_REQUEST (for password auth)

    # Try to extract username from SSH auth messages
    # SSH_MSG_USERAUTH_REQUEST format:
    #   byte SSH_MSG_USERAUTH_REQUEST (50)
    #   string username
    #   string service
    #   string method

    # Look for username patterns
    username = None
    password = None

    # Try to find username in the data
    # SSH auth messages often contain "username" field
    import re

    # Look for common SSH auth patterns
    # SSH_MSG_USERAUTH_REQUEST: 50, username, service, method
    # The username is typically the first string after the message type

    # Try to extract from raw SSH protocol data
    # SSH password auth sends: msg_type(50), username, service, method, password
    # We can look for the username in the data

    # Simple heuristic: look for strings that look like usernames
    # Common patterns: "user", "username", "admin", "root", etc.
    # Also look for password patterns

    # Try to parse SSH binary protocol
    try:
        data_bytes = raw_data.encode('latin-1')
        # Look for SSH_MSG_USERAUTH_REQUEST (byte 50)
        idx = data_bytes.find(b'\x32')  # 0x32 = 50
        if idx >= 0:
            # Skip message type and length
            # SSH binary protocol: length(4), type(1), data...
            # Look for the username string
            # The username is typically a string (length + content)
            # Try to find common username patterns
            for pattern in [b'\x00', b'\x01', b'\x02']:
                # Look for username patterns
                pass
    except Exception:
        logger.debug('Failed to parse SSH binary protocol data')

    # Fallback: look for plaintext username/password in the data
    # Some SSH clients send credentials in plaintext
    username_match = re.search(r'username[=:\s]+(\w+)', raw_data, re.IGNORECASE)
    if username_match:
        username = username_match.group(1)

    password_match = re.search(r'password[=:\s]+(\S+)', raw_data, re.IGNORECASE)
    if password_match:
        password = password_match.group(1)

    if username and password:
        return f'user={username}, pass={password}'
    elif username:
        return f'user={username}'
    elif password:
        return f'pass={password}'

    return None


REPORT_SEND_MAX_RETRIES = 5
REPORT_SEND_RETRY_DELAY = 2  # seconds
REPORT_SEND_BACKOFF_FACTOR = 2  # exponential backoff


def send_report(data, client, password, server_host, server_port, sensor_id=None):
    """Send a bot report to the server as an encrypted TCP message.

    Args:
        data: BearStorage instance with bot data
        client: Bot IP address (used for logging and data dict)
        password: AES encryption password (HIVEPASS)
        server_host: Server hostname
        server_port: Server port number
        sensor_id: Sensor identifier sent as message prefix to the server.
                   If None, falls back to client IP (legacy behavior).
    """
    cypher = AESCipher(password)
    parsed = data.parsed_request if hasattr(data, 'parsed_request') else None

    # Extract user-agent from headers (case-insensitive lookup on HTTPMessage)
    ua = ''
    if hasattr(data, 'ua'):
        ua = data.ua or ''
    elif hasattr(parsed, 'headers') and parsed.headers:
        # Try direct attribute first, then case-insensitive lookup
        ua = (
            getattr(parsed, 'user_agent', '')
            or parsed.headers.get('User-Agent', '')
            or parsed.headers.get('user-agent', '')
        )

    data_dict = {
        'ip': data.ip,
        'raw_request': data.raw_request,
        'timestamp': data.timestamp,
        'parsed_request': {
            'command': getattr(data, 'command', ''),
            'path': getattr(data, 'path', ''),
            'request_version': getattr(data, 'version', ''),
            'headers': dict(data.headers)
            if hasattr(data, 'headers') and isinstance(data.headers, dict)
            else {},
        },
        'is_detected': data.isDetected if hasattr(data, 'isDetected') else data.is_detected,
        'HIVELOGIN': data.hostname,
        # Additional fields for better data quality
        'ua': ua,
        'dns_name': getattr(data, 'dns_name', '') or '',
        'country': getattr(data, 'country', '') or '',
        'continent': getattr(data, 'continent', '') or '',
    }
    identifier = sensor_id if sensor_id else client
    message = (identifier + ':').encode()
    message += cypher.encrypt(json.dumps(data_dict).encode()).encode()

    # Retry with exponential backoff to handle server restarts
    delay = REPORT_SEND_RETRY_DELAY
    for attempt in range(1, REPORT_SEND_MAX_RETRIES + 1):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(10)  # don't hang forever on connect
        try:
            s.connect((server_host, server_port))
            s.sendall(message)
            response = s.recv(1024)
            if not response.decode().startswith('200'):
                logger.warning(
                    'Failed to send report: Non-200 response from server (attempt %d/%d)',
                    attempt,
                    REPORT_SEND_MAX_RETRIES,
                )
                print(response)
            s.close()
            logger.info('Report sent for %s', client)
            return  # success – stop retrying
        except socket_error:
            s.close()
            if attempt < REPORT_SEND_MAX_RETRIES:
                logger.debug(
                    'Report send failed for %s (attempt %d/%d), retrying in %ds',
                    client,
                    attempt,
                    REPORT_SEND_MAX_RETRIES,
                    delay,
                )
                import time

                time.sleep(delay)
                delay *= REPORT_SEND_BACKOFF_FACTOR
            else:
                logger.error(
                    'Socket error sending report for %s after %d attempts – dumping to file',
                    client,
                    REPORT_SEND_MAX_RETRIES,
                )
                dump_file(data)
        except KeyboardInterrupt:
            s.close()
            raise
    return


def create_server(args, update_event: Event, port: int):
    """Create a single-port honeypot server.

    Args:
        args: CLI arguments namespace
        update_event: Event to signal shutdown
        port: Port number to listen on

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
            connection_socket: socket | None = None
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
            output_data = handler.handle_request(message, bot_ip=bot_ip)
            try:
                logger.debug('Sending response of length %d', len(output_data))
                # output_data is already bytes from HTTPHandler
                connection_socket.sendall(
                    output_data
                    if isinstance(output_data, bytes)
                    else output_data.encode('iso-8859-1')
                )
                # For SSH connections, keep the connection open to capture credentials
                if isinstance(output_data, bytes) and output_data.startswith(b'SSH-'):
                    # SSH connection - keep listening for auth attempts
                    ssh_creds = _capture_ssh_credentials(connection_socket, bot_ip)
                    if ssh_creds:
                        logger.info(
                            'Captured SSH credentials from %s: %s',
                            bot_ip,
                            ssh_creds,
                        )
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


def main(args, update_event):
    """Main entry point for the honeypot client.

    Supports single-port, top-ports, and all-ports modes.

    Args:
        args: CLI arguments namespace
        update_event: Event to signal shutdown
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
                # Invalid --top-ports value: error out instead of silently falling back
                # This helps users catch typos (e.g., "80,443,xyz")
                import argparse

                # Note: This will raise SystemExit if called from argparse, otherwise log error
                logger.error(
                    'Invalid --top-ports value: %s. Must be comma-separated integers.',
                    top_ports,
                )
                raise ValueError(
                    f'Invalid --top-ports value: {top_ports!r}. Must be comma-separated integers.'
                )
        else:
            # No --top-ports specified, use the default list
            ports = _DEFAULT_TOP_PORTS
        create_multiport_server(args, update_event, ports)
    else:
        port = args.client
        create_server(args, update_event, port)
