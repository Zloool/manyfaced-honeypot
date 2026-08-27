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
from manyfaced.common.status import BOT_TIMEOUT, EMPTY_CONNECTION, HTTP_ON_NONHTTP_PORT
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
    from manyfaced.common.faces import FaceSpec

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


def _capture_credentials(
    connection_socket,
    bot_ip: str,
    response_bytes: bytes,
    spec: 'FaceSpec | None' = None,
) -> str | None:
    """Capture credentials from interactive protocol connections.

    For SSH, uses binary protocol parsing. For other protocols (TELNET, FTP, etc.),
    tries to extract plaintext username/password patterns.

    When ``spec`` carries a dedicated ``extract_creds`` extractor (FTP, POP3, IMAP,
    MySQL, MSSQL), the client's auth frame is read and handed to that extractor
    instead of the generic plaintext parser. This is required because the
    server-first interactive path never invoked ``spec.extract_creds`` before, so
    those faces captured zero credentials despite ``capture_creds=True`` (issue #627).

    Args:
        connection_socket: The open socket connection to the bot.
        bot_ip: IP address of the bot.
        response_bytes: The honeypot response sent (used to determine protocol type).
        spec: The matching ``FaceSpec`` (if known), used to dispatch to its
            dedicated credential extractor.

    Returns:
        String with captured credentials, or None if no credentials captured.
    """
    from manyfaced.client.ssh_creds import _capture_ssh_credentials  # noqa: PLC0415

    # Faces with a dedicated extractor get the real wire frame parsed by it.
    # SSH keeps its bespoke socket-driven parser (extract_creds is None there).
    if spec is not None and spec.extract_creds is not None:
        try:
            connection_socket.settimeout(BOT_TIMEOUT)
            frame = receive_first_frame(connection_socket, BOT_TIMEOUT)
        except (socket.timeout, socket.error, OSError):
            frame = b''
        if frame:
            try:
                return spec.extract_creds(frame)
            except Exception as e:  # noqa: BLE001 - extractor must never kill capture
                logger.debug('extract_creds failed for %s: %s', spec.name, e)

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


def _record_empty_connection(bot_ip: str, listen_port: int) -> None:
    """Persist a minimal EMPTY_CONNECTION capture for a payloadless connect (issue #488).

    Builds a ``BearStorage`` stamped with the ``EMPTY_CONNECTION`` sentinel, the
    real ``listen_port`` and ``bot_ip``, then runs it through the shared
    enrichment pipeline (geo/DNS/classify/report) so the accept is accountable
    in analysis instead of being silently dropped.
    """
    from datetime import datetime, timezone  # noqa: PLC0415

    from manyfaced.common.status import EMPTY_CONNECTION  # noqa: PLC0415
    from manyfaced.handlers.http_handler import (  # noqa: PLC0415
        _enrich_and_send_bear,
    )
    from manyfaced.common.bearstorage import BearStorage  # noqa: PLC0415
    from manyfaced.common.config import settings  # noqa: PLC0415

    class _ParsedEmpty:
        command = ''
        path = ''
        version = ''
        headers: dict[str, str] = {}
        user_agent = ''
        request_version = ''

    bs = BearStorage(
        bot_ip,
        '',
        str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')),
        _ParsedEmpty(),
        EMPTY_CONNECTION,
        settings.HIVELOGIN,
    )
    if listen_port:
        bs.listen_port = listen_port
    _enrich_and_send_bear(bs, bot_ip)


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
        # Issue #488: a payloadless connect (port scan, no data within timeout)
        # must still be recorded so it is accountable in analysis. Previously the
        # thread returned here with NO capture, silently dropping 9.6% of accepted
        # OTHER-PORTS connections. Emit a minimal EMPTY_CONNECTION capture with the
        # connection metadata (bot_ip, listen_port, timestamp) so the row is not
        # lost. The HTTP handler's _handle_empty_connection already does this for
        # the HTTP path; mirror it here for raw (non-HTTP-decided) preludes.
        logger.debug(
            'Payloadless connect from %s on port %s — recording EMPTY_CONNECTION',
            bot_ip,
            listen_port,
        )
        _record_empty_connection(bot_ip, listen_port)
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
        logger.debug('swallowed exception', exc_info=True)
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
    # receive_first_frame returns raw bytes (binary-safe, issue #597) — do NOT
    # decode/encode back through UTF-8, which would mangle non-UTF-8 payloads
    # (e.g. MongoDB OP_MSG frames with arbitrary BSON bytes).
    raw_bytes = (
        message if isinstance(message, bytes) else message.encode('latin-1', errors='replace')
    )

    # ── Issue #596: HTTP-on-non-HTTP re-sniff for ALL non-HTTP faces ───────
    # An HTTP frame (GET/POST/…) arriving on a non-HTTP port (SSH 22, MySQL
    # 3306, MSSQL 1433, Redis 6379, …) is a protocol mismatch, not a genuine
    # probe of that service. Previously only the ssh branch re-classified such
    # frames as HTTP_ON_NONHTTP_PORT; every other face silently labeled them
    # with the service's UNKNOWN_* sentinel, hiding scanners/censys/masscan
    # HTTP sweeps on DB ports. Re-sniff every face identically (the ssh branch
    # below keeps its exact prior behavior).
    from manyfaced.common.protocol import is_http_request  # noqa: PLC0415

    http_on_nonhttp = is_http_request(raw_bytes)

    # ── SSH: banner already sent in PRELUDE; drive binary credential capture,
    #    then record. SSH has no follow-up reply to send. ───────────────────
    if spec.name == 'ssh':
        # Issue #445: an HTTP request arriving on the SSH port is a protocol
        # mismatch, not a real SSH scanner. Flag it with a distinct detected_id
        # so analysis can separate HTTP-on-SSH-port probes from genuine SSH
        # banner scans instead of silently labeling them unknown SSH. Uses the
        # same http_on_nonhttp re-sniff computed above (issue #596) so every
        # face shares identical HTTP-on-non-HTTP logic.
        from manyfaced.common.status import (  # noqa: PLC0415
            SSH_CLIENT,
        )

        detected_id = SSH_CLIENT
        if http_on_nonhttp:
            detected_id = HTTP_ON_NONHTTP_PORT
            logger.info('HTTP-on-SSH-port mismatch from %s (flagged, not mislabeled)', bot_ip)
        creds = _capture_credentials(connection_socket, bot_ip, spec.greeting, spec)
        bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port)
        bs.isDetected = detected_id
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
        replies: list[bytes] = []
        # Process the first (prelude) frame.
        if raw_bytes and spec.respond is not None:
            try:
                reply = spec.respond(raw_bytes, bot_ip) or b''
            except Exception as e:  # never let a handler blow up the loop
                logger.debug('face %s respond error: %s', spec.name, e)
                reply = b''
            if reply:
                replies.append(reply)
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
            # frame is raw bytes (binary-safe, issue #597); keep as-is.
            raw2 = frame if isinstance(frame, bytes) else frame.encode('latin-1', errors='replace')
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
                    replies.append(reply2)
                    try:
                        connection_socket.sendall(reply2)
                    except socket.error:
                        break
        bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port, reply=b''.join(replies))
        if creds:
            bs.login = creds if isinstance(creds, str) else str(creds)
        # ── Issue #596: HTTP-on-non-HTTP re-sniff (client-first faces) ────
        # Client-first faces (redis/memcached/mongo/…) must ALSO reclassify an
        # HTTP frame to HTTP_ON_NONHTTP_PORT, exactly like the server-first and
        # ssh branches. An HTTP request arriving on e.g. the Redis port is a
        # protocol mismatch, not a genuine Redis probe (issue #596).
        if http_on_nonhttp:
            bs.isDetected = HTTP_ON_NONHTTP_PORT
            logger.info(
                'HTTP-on-%s-port mismatch from %s (flagged, not mislabeled)',
                spec.name,
                bot_ip,
            )
        # ── Issue #601: client-first silent-capture guard ──────────────────
        # A client-first connect (redis/memcached/mongo/zookeeper/postgres/
        # epmd/nfs) that sends NO frame before idling is currently recorded as
        # a normal UNKNOWN_NON_HTTP session with EMPTY request_raw AND empty
        # bot_profile_data — indistinguishable from EMPTY_CONNECTION, hiding
        # data loss. If the whole exchange captured nothing (no frame at all),
        # stamp it EMPTY_CONNECTION and attach a minimal, auditable
        # bot_profile_data note so analysts can separate a real no-frame
        # connect from a genuine capture failure.
        elif not raw_bytes:
            bs.isDetected = EMPTY_CONNECTION
            bs.bot_profile_data = {
                spec.name: {
                    'dialogue': [],
                    'note': 'client-first frame not captured',
                    'captured': False,
                }
            }
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
            logger.debug('swallowed exception', exc_info=True)

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

    # ── Issue #596: HTTP-on-non-HTTP re-sniff (server-first faces) ────────
    # MySQL/MSSQL/AMQP/Oracle/RDP/… are server-first, so the HTTP-on-port
    # mismatch can only be detected from the client's frame. If an HTTP request
    # arrived on one of these ports (e.g. GET / on 3306), reclassify it to
    # HTTP_ON_NONHTTP_PORT instead of the service's UNKNOWN_* sentinel — the
    # same distinct flag the SSH branch uses. This is the missing re-sniff that
    # previously let HTTP-on-3306 fall through to UNKNOWN_NON_HTTP.
    if http_on_nonhttp:
        bs = _build_bear_storage(bot_ip, spec, raw_bytes, listen_port)
        bs.isDetected = HTTP_ON_NONHTTP_PORT
        logger.info(
            'HTTP-on-%s-port mismatch from %s (flagged, not mislabeled)',
            spec.name,
            bot_ip,
        )
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
            logger.debug('swallowed exception', exc_info=True)

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
