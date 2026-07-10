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

# pyright: reportInvalidTypeForm=false

from __future__ import annotations

import signal
import socket
import threading
from multiprocessing.synchronize import Event as _MpEvent  # type: ignore[attr-defined]
from typing import TYPE_CHECKING

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.ports import DEFAULT_TOP_PORTS as _DEFAULT_TOP_PORTS
from manyfaced.common.status import BOT_TIMEOUT
from manyfaced.common.utils import receive_first_frame, receive_timeout
from manyfaced.handlers.http_handler import (
    HTTPHandler,
    _build_bear_storage,
    _enrich_and_send_bear,
)

# Internal IPs to filter out (loopback, DO internal network, honeypot's own IP)
_INTERNAL_IPS = frozenset(
    {
        '127.0.0.1',  # loopback
        '::1',  # IPv6 loopback
    }
)

if TYPE_CHECKING:
    from socket import socket as SocketType

logger = get_logger(__name__)


# Protocols that can have interactive credential exchange (banner → auth)
_INTERACTIVE_PROTOCOL_SIGNATURES: list[bytes] = [
    b'SSH-',  # SSH banner
    b'220 ',  # FTP/SMTP greeting
    b'+OK',  # POP3 greeting
    b'* OK',  # IMAP greeting
    b'RFB ',  # VNC
    b'\xff',  # TELNET IAC (Interpret As Command) - starts with 0xFF
]


def _is_interactive_protocol(response_bytes: bytes) -> bool:
    """Check if response indicates an interactive protocol that may have credentials.

    Args:
        response_bytes: The honeypot response sent to the bot.

    Returns:
        True if this is an interactive protocol where credentials might follow.
    """
    for sig in _INTERACTIVE_PROTOCOL_SIGNATURES:
        if response_bytes.startswith(sig):
            return True
    return False


def _capture_credentials(connection_socket, bot_ip: str, response_bytes: bytes) -> str | None:
    """Capture credentials from interactive protocol connections.

    For SSH, uses binary protocol parsing. For other protocols (TELNET, FTP, etc.),
    tries to extract plaintext username/password patterns.

    Args:
        connection_socket: The open socket connection to the bot.
        bot_ip: IP address of the bot.
        response_bytes: The honeypot response sent (used to determine protocol type).

    Returns:
        String with captured credentials, or None if no credentials captured.
    """
    from manyfaced.client.ssh_creds import _capture_ssh_credentials  # noqa: PLC0415

    # SSH gets special binary protocol parsing
    if response_bytes.startswith(b'SSH-'):
        return _capture_ssh_credentials(connection_socket, bot_ip)

    # For other interactive protocols (TELNET, FTP, etc.), try plaintext extraction
    try:
        connection_socket.settimeout(10)  # Wait for auth data
        all_data = b''
        while True:
            try:
                data = connection_socket.recv(4096)
                if not data:
                    break
                all_data += data
                if len(all_data) > 2048:  # Reasonable max for auth exchange
                    break
            except socket.timeout:
                break
            except socket.error:
                break

        if all_data:
            # Strip TELNET IAC (Interpret As Command) bytes and options
            # TELNET protocol uses \xff as escape character followed by command codes
            clean_data = b''
            i = 0
            while i < len(all_data):
                if all_data[i : i + 1] == b'\xff':
                    # Skip IAC byte and any following option bytes (IAC WILL, IAC WONT, etc.)
                    i += 1
                    while i < len(all_data) and all_data[i : i + 1] in (
                        b'\xfb',
                        b'\xfc',
                        b'\xfd',
                        b'\xfe',
                        b'\xff',
                    ):
                        i += 1
                else:
                    clean_data += all_data[i : i + 1]
                    i += 1

            raw_str = clean_data.decode('utf-8', errors='replace')
            creds = _parse_plaintext_credentials(raw_str)
            if creds:
                return creds
            logger.debug(
                'No credentials found in %s data from %s (length=%d): %s',
                'TELNET'
                if response_bytes.startswith(b'\xff')
                else ('FTP/SMTP' if response_bytes.startswith(b'220 ') else 'interactive'),
                bot_ip,
                len(all_data),
                repr(clean_data[:200]),
            )
    except Exception as e:
        logger.debug('Error capturing credentials from %s: %s', bot_ip, e)

    return None


def _parse_plaintext_credentials(raw_data: str) -> str | None:
    """Extract username/password from plaintext protocol data (TELNET, FTP, etc.).

    Args:
        raw_data: Raw protocol data as string.

    Returns:
        String with extracted credentials, or None if not found.
    """
    import re  # noqa: PLC0415

    username = None
    password = None

    # Common patterns for credential disclosure in plaintext protocols
    user_patterns = [
        r'username[=:\s]+(\S+)',
        r'user[=:\s]+(\S+)',
        r'login[=:\s]+(\S+)',
        r'USER\s+(\S+)',  # FTP command
    ]

    pass_patterns = [
        r'password[=:\s]+(\S+)',
        r'pass[=:\s]+(\S+)',
        r'PASS\s+(\S+)',  # FTP command
    ]

    for pattern in user_patterns:
        match = re.search(pattern, raw_data, re.IGNORECASE)
        if match:
            username = match.group(1).strip('\'"')
            break

    for pattern in pass_patterns:
        match = re.search(pattern, raw_data, re.IGNORECASE)
        if match:
            password = match.group(1).strip('\'"')
            break

    if username and password:
        return f'user={username}, pass={password}'
    elif username:
        return f'user={username}'
    elif password:
        return f'pass={password}'

    return None


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
    update_event: _MpEvent,
    listen_port: int = 0,
) -> None:
    """Handle a single bot connection: receive request, generate response, send reply.

    Args:
        connection_socket: The client socket to communicate with the bot.
        args: CLI arguments namespace.
        bot_addr: Tuple of (ip, port) from the accepting socket.
        update_event: Event to signal shutdown.
    """
    from manyfaced.common.metrics import incr, set_gauge  # noqa: PLC0415

    bot_ip = bot_addr[0] if bot_addr else '127.0.0.1'

    # Filter out internal/loopback connections (iptables redirects, local probes)
    if bot_ip in _INTERNAL_IPS:
        logger.debug('Dropping connection from internal IP %s', bot_ip)
        return

    # Observability: count each real bot connection and track concurrency (issue #166).
    incr('bot_connections')
    set_gauge('active_connections', threading.active_count())

    # ── Non-HTTP face dispatch (issue #377) ──────────────────────────────────
    # Server-first faces (SSH/FTP/Telnet/SMTP/POP3/IMAP/VNC/RDP/MySQL/MSSQL/
    # AMQP) must GREET on accept, before any client bytes arrive — they cannot
    # be detected from the wire because the client has not spoken yet. The face
    # is resolved by the port the client connected to. Client-first faces
    # (Redis/Memcached/MongoDB/Zookeeper/Postgres/ES) read the client frame
    # then reply. HTTP falls through to the existing handler unchanged.
    from manyfaced.common.faces import get_face, is_http_port  # noqa: PLC0415

    spec = get_face(listen_port)
    if spec is not None and not is_http_port(listen_port):
        _handle_non_http_connection(
            connection_socket, args, bot_ip, update_event, listen_port, spec
        )
        return

    message = receive_timeout(connection_socket, BOT_TIMEOUT)
    if not message:
        return

    handler = HTTPHandler(args, update_event, listen_port=listen_port)
    output_data = handler.handle_request(message, bot_ip=bot_ip)

    try:
        logger.debug('Sending response of length %d', len(output_data))
        # Handle both SSH/non-HTTP (returns tuple) and HTTP (returns bytes) paths
        if isinstance(output_data, tuple):
            # SSH or non-HTTP probe: (response_bytes, BearStorage)
            response_bytes, bear_storage = output_data
            connection_socket.sendall(response_bytes)

            # For interactive protocols (SSH, TELNET, FTP, SMTP, POP3, IMAP, VNC), keep
            # the connection open to capture credentials from subsequent data
            if _is_interactive_protocol(response_bytes):
                creds = _capture_credentials(connection_socket, bot_ip, response_bytes)
                if creds and bear_storage is not None:
                    bear_storage.login = creds
                    logger.info(
                        'Captured %s credentials from %s: %s',
                        'SSH' if response_bytes.startswith(b'SSH-') else 'interactive',
                        bot_ip,
                        creds,
                    )
                # Send report AFTER credential capture so login field has real creds
                if bear_storage is not None:
                    handler._enrich_and_send(bear_storage, bot_ip)
        else:
            # HTTP request: response bytes only (report already queued in process_request)
            connection_socket.sendall(
                output_data if isinstance(output_data, bytes) else output_data.encode('iso-8859-1')
            )
    except socket.error:
        # Client disconnected mid-response (or socket torn down) — nothing to
        # send back; the connection is already gone.
        pass
    finally:
        # Clear router handler instances so BotProfile state doesn't leak across connections
        from manyfaced.handlers.http_handler import _get_router  # noqa: PLC0415

        _get_router().clear_handler_instances()
        connection_socket.close()


def _handle_non_http_connection(
    connection_socket: 'socket.socket',
    args,
    bot_ip: str,
    update_event: _MpEvent,
    listen_port: int,
    spec,
) -> None:
    """Handle a non-HTTP face connection via the port-keyed registry (issue #377).

    Model: PRELUDE (server-first greet on accept) → EXCHANGE (read client
    frame, reply, optionally capture credentials). For client-first faces the
    greeting is empty and we go straight to the exchange.

    Args:
        connection_socket: The client socket.
        args: CLI arguments namespace.
        bot_ip: Source IP.
        update_event: Shutdown event (unused here, kept for signature parity).
        listen_port: The bound port the client connected to.
        spec: The resolved ``FaceSpec`` from ``manyfaced.common.faces``.
    """
    from manyfaced.common.faces import FaceSpec  # noqa: PLC0415

    assert isinstance(spec, FaceSpec)

    # ── PRELUDE: send the server-first greeting (before any recv) ──────────
    if spec.direction == 'server-first' and spec.greeting:
        try:
            connection_socket.sendall(spec.greeting)
        except socket.error:
            return

    # ── EXCHANGE: read the client's request/response frame ──────────────────
    # Use receive_first_frame (not receive_timeout) so we reply as soon as the
    # peer's frame is read, instead of blocking until the connection idles
    # (which made client-first faces time out before ever sending a reply).
    message = receive_first_frame(connection_socket, BOT_TIMEOUT)
    raw_bytes = message.encode('utf-8') if isinstance(message, str) else message

    # ── SSH: banner already sent in PRELUDE; drive binary credential capture,
    #    then record. SSH has no follow-up reply to send. ───────────────────
    if spec.name == 'ssh':
        creds = _capture_credentials(connection_socket, bot_ip, spec.greeting)
        bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port)
        if creds:
            bs.login = creds
        _enrich_and_send_bear(bs, bot_ip)
        return

    # ── Client-first faces (Redis/Memcached/Mongo/Postgres/ES/Zookeeper): a
    #    real client issues a *sequence* of commands (e.g. redis-py does
    #    HELLO → PING → SET), so run a request/reply loop until the client
    #    stops sending or the connection idles. Each frame is replied to
    #    promptly; credentials offered on any frame are captured. ──────────
    if spec.direction == 'client-first':
        creds: object = None
        # Process the first (prelude) frame.
        if raw_bytes and spec.respond is not None:
            try:
                reply = spec.respond(raw_bytes, bot_ip) or b''
            except Exception as e:  # never let a handler blow up the loop
                logger.debug('face %s respond error: %s', spec.name, e)
                reply = b''
            if reply:
                try:
                    connection_socket.sendall(reply)
                except socket.error:
                    return
        if spec.capture_creds and spec.extract_creds is not None:
            c = spec.extract_creds(raw_bytes)
            creds = creds or c
        # Loop for subsequent frames (bounded by idle timeout + sane iteration cap).
        for _ in range(64):
            frame = receive_first_frame(connection_socket, BOT_TIMEOUT)
            if not frame:
                break
            raw2 = frame.encode('utf-8') if isinstance(frame, str) else frame
            if not raw2:
                break
            if spec.capture_creds and spec.extract_creds is not None:
                c = spec.extract_creds(raw2)
                creds = creds or c
            if spec.respond is not None:
                try:
                    reply2 = spec.respond(raw2, bot_ip) or b''
                except Exception as e:
                    logger.debug('face %s respond error: %s', spec.name, e)
                    reply2 = b''
                if reply2:
                    try:
                        connection_socket.sendall(reply2)
                    except socket.error:
                        break
        bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port)
        if creds:
            bs.login = creds if isinstance(creds, str) else str(creds)
        _enrich_and_send_bear(bs, bot_ip)
        return

    # ── Server-first interactive (TELNET/FTP/SMTP/POP3/IMAP/RDP/MSSQL/…):
    #    single reply, then blocking credential capture, then record. ───────
    reply = b''
    if raw_bytes and spec.respond is not None:
        try:
            reply = spec.respond(raw_bytes, bot_ip) or b''
        except Exception as e:  # never let a handler blow up the dispatch loop
            logger.debug('face %s respond error: %s', spec.name, e)
            reply = b''

    # ── REPLY: send the protocol response (if any) BEFORE any blocking
    #    credential-capture read, so the client actually receives it.
    #    Critical for client-first faces (Redis +PONG, Memcached VERSION,
    #    ES 200, Postgres AuthRequest, …) which would otherwise time out
    #    waiting on the capture read. ─────────────────────────────────────
    if reply:
        try:
            connection_socket.sendall(reply)
        except socket.error:
            pass

    # ── Interactive credential capture (TELNET/FTP/SMTP/POP3/IMAP/RDP/MSSQL/
    #    Redis/…) — runs AFTER the reply so the connection stays responsive.
    #    Reads the client's subsequent auth frame(s); a no-data timeout just
    #    means no creds were offered. ───────────────────────────────────────
    creds = None
    if spec.capture_creds:
        creds = _capture_credentials(connection_socket, bot_ip, reply)
    if creds:
        bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port)
        bs.login = creds
        _enrich_and_send_bear(bs, bot_ip)
        return

    # ── Record the probe (greeting-only / no-credential exchanges too) ─────
    bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port)
    _enrich_and_send_bear(bs, bot_ip)


def create_server(args, update_event: _MpEvent, port: int) -> bool:
    """Create a single-port honeypot server.

    Args:
        args: CLI arguments namespace.
        update_event: Event to signal shutdown.
        port: Port number to listen on.

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
            # Issue #212 / #140: handle each connection in its own daemon thread
            # so a slow/interactive bot (up to ~15s of credential capture) can't
            # block accept() and starve other connections on this port. The
            # per-port daemon threads above are for multi-port, not per-connection.
            t = threading.Thread(
                target=_handle_bot_connection,
                args=(connection_socket, args, bot_addr, update_event, port),
                name=f'bot-{bot_addr[0]}:{bot_addr[1]}' if bot_addr else 'bot-?',
                daemon=True,
            )
            t.start()
    finally:
        server_socket.close()
    return True


def create_multiport_server(args, update_event: _MpEvent, ports: list[int]) -> None:
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

    # Observability: start periodic structured stats logging (issue #166).
    from manyfaced.common.metrics import start_stats_logger

    start_stats_logger()

    port_mode = getattr(args, 'port_mode', 'single')
    top_ports = getattr(args, 'top_ports', '')

    # Register args so the non-HTTP face dispatch (issue #377) can reach the
    # report server host/port when enriching + queuing captures.
    from manyfaced.handlers.http_handler import set_enrich_args  # noqa: PLC0415

    set_enrich_args(args)

    if port_mode == 'all':
        ports = list(range(1, 65536))
        logger.warning('Listening on ALL 65535 ports – this may take time to start')
        print('WARNING: Listening on all 65535 TCP ports...')
        create_multiport_server(args, update_event, ports)
        # UDP faces (SIP/SNMP/…) ride along in 'all' mode (issue #388).
        create_multiport_udp_server(args, update_event, None)
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
        # UDP faces (SIP/SNMP/…) ride along in 'top' mode (issue #388).
        create_multiport_udp_server(args, update_event, None)
    else:
        port = args.client
        create_server(args, update_event, port)


# ---------------------------------------------------------------------------
# UDP transport (issue #388)
#
# SIP (5060) and SNMP (161) are UDP yet were completely invisible because the
# honeypot only opened SOCK_STREAM listeners. This adds a parallel UDP datagram
# path that mirrors the TCP non-HTTP face model: resolve the face by port, call
# its respond() per datagram, send the reply, and record a capture via the same
# enrichment pipeline used by the TCP faces.
# ---------------------------------------------------------------------------


def _setup_udp_socket(port: int) -> 'SocketType | None':
    """Create and bind a UDP server socket on the given port.

    Args:
        port: Port number to listen on (UDP).

    Returns:
        Bound UDP socket, or None if binding failed.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', port))
    except PermissionError:
        logger.warning(
            'Permission denied binding to UDP port %d (try running as root or use a higher port)',
            port,
        )
        return None
    except OSError as e:
        logger.warning('Failed to bind to UDP port %d: %s', port, e)
        return None
    return server_socket


def _handle_udp_datagram(
    server_socket: 'socket.socket',
    data: bytes,
    bot_addr: tuple,
    args,
    listen_port: int,
) -> None:
    """Process one UDP datagram against a UDP face and reply + record.

    Args:
        server_socket: The UDP server socket (used to sendto the reply).
        data: The raw datagram payload bytes.
        bot_addr: Tuple of (ip, port) of the sender.
        args: CLI arguments namespace.
        listen_port: The UDP port the datagram arrived on.
    """
    from manyfaced.common.faces import get_udp_face  # noqa: PLC0415
    from manyfaced.common.metrics import incr  # noqa: PLC0415

    bot_ip = bot_addr[0] if bot_addr else '127.0.0.1'
    if bot_ip in _INTERNAL_IPS:
        return

    incr('bot_connections')
    spec = get_udp_face(listen_port)
    if spec is None:
        # Not a known UDP face — drop silently (no spoofed service).
        return

    # For SIP, capture any credentials/INVITE destination offered in the payload
    # before replying (the 401 challenge is what makes bots reveal digests).
    creds = None
    if spec.capture_creds:
        try:
            text = data.decode('latin-1', errors='replace')
            creds = _parse_plaintext_credentials(text)
            # SIP REGISTER often carries Authorization: Digest username="...";
            # also surface INVITE toll-fraud destinations for the capture record.
            import re as _re  # noqa: PLC0415

            _inv = _re.search(r'INVITE\s+sip:([^\s@]+)', text)
            if _inv and not creds:
                creds = f'invite_dst={_inv.group(1)}'
        except Exception as e:  # never let a parse blow up the UDP loop
            logger.debug('udp %s parse error: %s', spec.name, e)

    reply = b''
    try:
        if spec.respond is not None:
            reply = spec.respond(data, bot_ip) or b''
    except Exception as e:  # never let a handler blow up the UDP loop
        logger.debug('udp face %s respond error: %s', spec.name, e)

    if reply:
        try:
            server_socket.sendto(reply, bot_addr)
        except socket.error:
            pass

    # Record the capture (greeting-only / no-credential exchanges too).
    from manyfaced.handlers.http_handler import (  # noqa: PLC0415
        _build_bear_storage,
        _enrich_and_send_bear,
    )

    bs = _build_bear_storage(bot_ip, spec, data, listen_port)
    if creds:
        bs.login = creds if isinstance(creds, str) else str(creds)
    _enrich_and_send_bear(bs, bot_ip)


def create_udp_server(args, update_event: _MpEvent, port: int) -> bool:
    """Create a single-port UDP honeypot server.

    Args:
        args: CLI arguments namespace.
        update_event: Event to signal shutdown.
        port: UDP port number to listen on.

    Returns:
        True if the server started, False otherwise.
    """
    server_socket = _setup_udp_socket(port)
    if server_socket is None:
        return False

    logger.info('Client honeypot (UDP) listening on port %d', port)
    if args.verbose:
        print(f'Serving UDP honey on port {port}')

    try:
        while True:
            if update_event.is_set():
                break
            try:
                server_socket.settimeout(1.0)
                data, bot_addr = server_socket.recvfrom(65535)
            except socket.timeout:
                continue
            except (OSError, ConnectionError):
                break
            if not data:
                continue
            t = threading.Thread(
                target=_handle_udp_datagram,
                args=(server_socket, data, bot_addr, args, port),
                name=f'udp-{bot_addr[0]}:{bot_addr[1]}' if bot_addr else 'udp-?',
                daemon=True,
            )
            t.start()
    finally:
        server_socket.close()
    return True


def create_multiport_udp_server(args, update_event: _MpEvent, ports: 'list[int] | None') -> None:
    """Start UDP honeypot servers on many ports, one thread per port.

    Args:
        ports: Ports to bind. When None, the canonical DEFAULT_UDP_PORTS are used.
    """
    from manyfaced.common.ports import DEFAULT_UDP_PORTS  # noqa: PLC0415

    ports = list(ports or DEFAULT_UDP_PORTS)
    threads: list[threading.Thread] = []
    successful_ports: list[int] = []
    failed_ports: list[int] = []

    def _udp_port_worker(port: int) -> None:
        if create_udp_server(args, update_event, port):
            successful_ports.append(port)
        else:
            failed_ports.append(port)

    for port in ports:
        t = threading.Thread(
            target=_udp_port_worker,
            args=(port,),
            name=f'udp-honeyport-{port}',
            daemon=True,
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    if successful_ports:
        logger.info(
            'Client honeypot (UDP) listening on %d ports: %s',
            len(successful_ports),
            ', '.join(str(p) for p in successful_ports),
        )
