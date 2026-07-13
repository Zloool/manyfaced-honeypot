"""HTTPHandler – handles raw HTTP requests from bots.

Routes to service-specific handlers via Router, generates honeypot responses,
and queues reports for sending to the server. Response content is delegated
to protocol_responses module; report queue management to report_queue module.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from manyfaced.handlers.router import Router  # noqa: F401

from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.classification import classify
from manyfaced.common.config import settings
from manyfaced.common.credential_extractor import extract_http_credentials, format_creds_string
from manyfaced.common.httphandler import HTTPRequest
from manyfaced.common.logging_setup import get_logger
from manyfaced.common.protocol import detect_protocol, get_protocol_info
from manyfaced.common.alerting import notify_credential_capture
from manyfaced.common.status import (
    EMPTY_CONNECTION,
    SSH_CLIENT,
    UNKNOWN_DNS,
    UNKNOWN_MONGODB,
    UNKNOWN_NON_HTTP,
    UNKNOWN_REDIS,
    UNKNOWN_SMB,
    UNKNOWN_TLS,
    UNKNOWN_TELNET,
    UNKNOWN_RDP,
    UNKNOWN_VNC,
)
from manyfaced.handlers.protocol_responses import (
    fallback_response,
    fake_ssh_banner,
    non_http_response,
)
from manyfaced.handlers.redis_handler import generate_redis_response
from manyfaced.handlers.mongodb_handler import (
    generate_mongodb_response,
)
from manyfaced.handlers.telnet_handler import (
    generate_telnet_response,
)
from manyfaced.handlers.rdp_handler import generate_rdp_response
from manyfaced.handlers.vnc_handler import generate_vnc_response
from manyfaced.handlers.report_queue import _get_report_queue

logger = get_logger(__name__)


# Singleton router – initialized on first use. Double-checked locking mirrors
# _get_report_queue() so concurrent first requests on different multiport
# accept-loop threads can't each build a separate Router instance.
_router: Router | None = None
_router_lock = threading.Lock()


def _get_router() -> Router:
    """Get or create the module-level router (singleton)."""
    global _router
    if _router is None:
        with _router_lock:
            if _router is None:
                from manyfaced.handlers.routes import ROUTES  # noqa: F811

                from manyfaced.handlers.router import Router

                _router = Router(ROUTES)
                logger.info('Router initialized with %d routes', len(_router.routes))
    return _router


class HTTPHandler:
    """HTTP honeypot handler that routes requests to service-specific handlers.

    Unlike the server-side BaseHandler, this does NOT decrypt or parse JSON.
    It receives raw HTTP data, routes to the appropriate handler, generates
    a honeypot response, and queues reports for sending to the server.
    """

    def __init__(self, args, update_event, listen_port: int = 0):
        self.args = args
        self.update_event = update_event
        # Local honeypot port the bot connected to (issue #299). 0 = unknown
        # (only accurate when the handler was constructed per-connection with the
        # real listening port, as the client does).
        self.listen_port = listen_port

    def handle_request(self, message: str, bot_ip: str = '127.0.0.1'):
        """Handle a raw HTTP request from a bot.

        Returns:
            For SSH/non-HTTP paths: (response_bytes, BearStorage) so caller can update credentials
            For HTTP paths: response bytes only
        """
        raw_bytes = message.encode('utf-8') if isinstance(message, str) else message
        if not raw_bytes:
            return self._handle_empty_connection(bot_ip)

        protocol = detect_protocol(raw_bytes)
        protocol_info = get_protocol_info(raw_bytes) if protocol else {}

        if protocol == 'ssh':
            logger.info(
                'SSH probe detected from %s: %s',
                bot_ip,
                protocol_info.get('client', 'unknown'),
            )
            return self._handle_ssh_probe(bot_ip, protocol_info)

        if protocol is not None and protocol != 'http':
            logger.info('Non-HTTP protocol detected from %s: %s', bot_ip, protocol)
            return self._handle_non_http_probe(bot_ip, protocol, protocol_info)

        # Parse the raw HTTP request
        try:
            parsed = HTTPRequest(message)
            if getattr(parsed, 'path', None) is None:
                logger.debug('HTTPRequest failed to parse path, using fallback for %s', bot_ip)
                parsed = HTTPRequest(
                    'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n'
                )
        except Exception as e:
            logger.debug('Failed to parse HTTP request: %s, using fallback for %s', e, bot_ip)
            parsed = HTTPRequest('GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n')

        raw_for_report = (
            message
            if message
            else 'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n'
        )
        data = {
            'ip': bot_ip,
            'raw_request': raw_for_report,
            'parsed_request': parsed,
        }
        return self.process_request(data)

    def _handle_ssh_probe(self, bot_ip: str, protocol_info: dict) -> tuple[bytes, BearStorage]:
        """Handle an SSH probe by responding with a fake SSH banner.

        Returns:
            Tuple of (response_bytes, BearStorage) so caller can update credentials after capture.
            NOTE: Does NOT queue report — caller must send report AFTER credential capture.
        """
        client = protocol_info.get('client', '')
        version = protocol_info.get('version', '')
        banner = fake_ssh_banner() + '\r\n'

        logger.debug('Sent SSH banner to %s (client=%s)', bot_ip, client)

        class _ParsedSSH:
            command = 'SSH'
            path = '/'
            headers: dict[str, str] = {}
            user_agent = client or 'unknown'
            request_version = version or 'SSH-2.0'

        bs = BearStorage(
            bot_ip,
            protocol_info.get('raw', 'SSH-2.0-PUTTY'),
            str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')),
            _ParsedSSH(),
            SSH_CLIENT,
            settings.HIVELOGIN,
        )
        # NOTE: Do NOT call _enrich_and_send() here — credential capture happens
        # after this returns. The caller must send the report AFTER updating bs.login.
        return banner.encode('utf-8'), bs

    def _handle_non_http_probe(
        self, bot_ip: str, protocol: str, protocol_info: dict
    ) -> tuple[bytes, BearStorage]:
        """Handle non-HTTP protocol probes.

        Returns:
            Tuple of (response_bytes, BearStorage).
        """
        detected_id = {
            'tls': UNKNOWN_TLS,
            'dns': UNKNOWN_DNS,
            'mongodb': UNKNOWN_MONGODB,
            'redis': UNKNOWN_REDIS,
            'smb': UNKNOWN_SMB,
            'telnet': UNKNOWN_TELNET,
            'rdp': UNKNOWN_RDP,
            'vnc': UNKNOWN_VNC,
        }.get(protocol, UNKNOWN_NON_HTTP)

        raw_data = protocol_info.get('raw', b'')

        # Use protocol-specific handlers for Redis, MongoDB, Telnet, RDP, VNC
        if protocol == 'redis':
            response = generate_redis_response(raw_data, bot_ip)
        elif protocol == 'mongodb':
            response = generate_mongodb_response(raw_data, bot_ip)
        elif protocol == 'telnet':
            response = generate_telnet_response(raw_data, bot_ip)
        elif protocol == 'rdp':
            response = generate_rdp_response(raw_data, bot_ip)
        elif protocol == 'vnc':
            response = generate_vnc_response(raw_data, bot_ip)
        elif protocol in ('ftp', 'pop3', 'imap'):
            # These protocol probes must get a protocol-shaped greeting, NOT the
            # generic Apache HTTP banner. A real FTP/POP3/IMAP client receiving
            # ``HTTP/1.1 200 OK`` immediately errors/hangs — poor fidelity and a
            # lost credential-capture opportunity (issue #491).
            response = self._non_http_greeting(protocol)
        else:
            # Fallback to legacy handler for other protocols
            response = non_http_response(protocol)

        if response is None:
            response = b''

        class _ParsedNonHTTP:
            command = protocol.upper()
            path = '/'
            version = protocol_info.get('version', protocol)
            headers: dict[str, str] = {}
            user_agent = protocol_info.get('client', protocol)

        bs = BearStorage(
            bot_ip,
            protocol_info.get('raw', ''),
            str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')),
            _ParsedNonHTTP(),
            detected_id,
            settings.HIVELOGIN,
        )
        # NOTE: Do NOT call _enrich_and_send() here — credential capture happens
        # after this returns. The caller must send the report AFTER updating bs.login.
        return response, bs

    def _non_http_greeting(self, protocol: str) -> bytes:
        """Return a protocol-shaped greeting for FTP/POP3/IMAP probes (#491).

        These clients must receive a protocol-appropriate banner, not the
        generic Apache HTTP response — otherwise they error/hang and the
        connection (and any credential-capture opportunity) is lost.
        """
        greetings = {
            'ftp': '220 (vsFTPd 3.0.3)'.encode() + bytes([13, 10]),
            'pop3': '+OK POP3 server ready'.encode() + bytes([13, 10]),
            'imap': '* OK IMAP4rev1 server ready'.encode() + bytes([13, 10]),
        }
        return greetings.get(protocol, b'')

    def process_request(self, data):
        """Process an incoming HTTP request."""

        bot_ip = data['ip']
        raw_request = data['raw_request']
        parsed = data['parsed_request']
        request_time = str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f'))

        logger.info('Incoming request from %s at %s', bot_ip, request_time)

        headers = {}
        if hasattr(parsed, 'headers') and parsed.headers:
            try:
                headers = dict(parsed.headers)
            except Exception:
                logger.debug('Failed to parse request headers for %s', bot_ip)

        # Extract credentials from POST requests (login attempts)
        login_creds_dict = extract_http_credentials(raw_request, headers or {})
        login_creds = format_creds_string(login_creds_dict) if login_creds_dict else None

        router = _get_router()
        path = getattr(parsed, 'path', '/')
        # The Router percent-decodes the path once during dispatch (issue #443)
        # so encoded path-escape probes (/ .env%2e -> /.env, /.htaccess,
        # /%2eenv) match the exploit/config-disclosure routes instead of
        # falling through to the monster page. Handlers receive the decoded
        # path from the router.
        result = router.dispatch(path, raw_request, bot_ip, headers or {})

        if result is not None:
            output_data, detected = result
        else:
            output_data, detected = fallback_response(path), 1

        logger.debug(
            'Generated response for %s, detected=%s, size=%d', bot_ip, detected, len(output_data)
        )

        bs = BearStorage(
            bot_ip,
            raw_request,
            request_time,
            parsed,
            detected,
            settings.HIVELOGIN,
        )

        # Store extracted credentials in BearStorage
        if login_creds:
            bs.login = login_creds
            logger.info('Captured HTTP credentials from %s at %s', bot_ip, path)
            notify_credential_capture(
                ip=bot_ip,
                credentials=login_creds,
                path=path,
                hostname=settings.HIVELOGIN,
            )

        self._enrich_and_send(bs, bot_ip)
        return output_data

    def _handle_empty_connection(self, bot_ip: str) -> tuple[bytes, BearStorage]:
        """Handle a zero-byte connection (port scan with no data sent).

        Returns:
            Tuple of (response_bytes, BearStorage).
        """

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
        self._enrich_and_send(bs, bot_ip)
        return fallback_response(''), bs

    def _enrich_and_send(self, bs: BearStorage, bot_ip: str) -> None:
        """Resolve DNS/geo and queue report for a BearStorage entry."""
        # Tag the record with the local honeypot port it was captured on (issue #299).
        if self.listen_port:
            bs.listen_port = self.listen_port
        try:
            bs.dns_name = bs.resolve_dns_name(bot_ip, timeout=1.0)
        except Exception:
            logger.debug('DNS resolution failed for %s', bot_ip)

        try:
            bs.resolve_geo(bot_ip, timeout=2.0)
        except Exception:
            logger.debug('Geo resolution failed for %s', bot_ip)

        # Classify the source as benign/unknown from its strongest available
        # signals (reverse DNS is already resolved; ASN/org arrived with geo).
        # classify() is pure and cheap. The result rides on the report to the
        # server which stores it pre-classified (issue #271).
        try:
            bs.classification, bs.benign_source = classify(
                reverse_dns=bs.dns_name,
                org=bs.org,
                asn=bs.asn,
                user_agent=bs.ua,
            )
            from manyfaced.common.metrics import incr

            incr(f'classification.{bs.classification}')
        except Exception:
            logger.debug('Classification failed for %s', bot_ip)

        # Collect BotProfile data from all handler instances for this IP
        router = _get_router()
        profile_data = router.get_all_profiles_for_ip(bot_ip)
        if profile_data:
            bs.bot_profile_data = profile_data

        server_host = getattr(self.args, 'server_host', '127.0.0.1')
        server_port = getattr(self.args, 'server', None)
        if server_port is not None:
            q = _get_report_queue()
            from manyfaced.client.report_sender import send_report  # noqa: PLC0415

            q.put(
                (
                    send_report,
                    (bs, bot_ip, settings.HIVEPASS, server_host, server_port, settings.HIVELOGIN),
                )
            )

    @staticmethod
    def _extract_method(raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'


def _build_bear_storage(bot_ip: str, spec, raw_bytes: bytes, listen_port: int, reply: bytes = b''):
    """Build a ``BearStorage`` for a non-HTTP face probe (issue #377).

    Shared by the new port-keyed non-HTTP dispatch so every face records a
    consistent capture (protocol, detected_id, raw bytes, listen port), instead
    of being silently dropped when no client data arrives.

    Args:
        bot_ip: Source IP of the bot.
        spec: The resolved ``FaceSpec`` from ``manyfaced.common.faces``.
        raw_bytes: The client's frame (may be empty for greeting-only probes).
        listen_port: The bound port the client connected to.
        reply: The protocol reply actually sent to the client, so it is
            persisted into the capture instead of being dropped (issue #502).
    """
    from manyfaced.common.faces import FaceSpec  # noqa: PLC0415

    assert isinstance(spec, FaceSpec)
    request_time = str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f'))

    # Use the *wire* verb for request_command, not the face's nominal name.
    # Non-HTTP ports (e.g. SMTP 25/10025) routinely receive HTTP probes
    # (masscan/censys `GET /`, `POST /`) and other verbs; labelling every
    # capture with spec.name (e.g. always 'SMTP') mis-classified 41 HTTP +
    # 7 JSON/masscan rows. Parse the first whitespace-delimited token of the
    # raw frame; fall back to the face name if it isn't a recognisable verb.
    wire_command = spec.name.upper()
    try:
        first_line = raw_bytes.decode('latin-1', errors='replace').splitlines()[0]
        token = first_line.split()[0].upper()
        if token and token.isalpha():
            wire_command = token
    except Exception:
        pass

    class _ParsedNonHTTP:
        command = wire_command
        path = '/'
        version = ''
        headers: dict[str, str] = {}
        user_agent = spec.name

    bs = BearStorage(
        bot_ip,
        raw_bytes.decode('latin-1', errors='replace'),
        request_time,
        _ParsedNonHTTP(),
        spec.detected_id,
        settings.HIVELOGIN,
    )
    if listen_port:
        bs.listen_port = listen_port
    # Persist the protocol reply so analysts can see what the honeypot actually
    # said to the attacker (issue #502). Recorded as a single dialogue entry on
    # the bot_profile_data so it rides the report exactly like the HTTP path.
    if reply:
        bs.bot_profile_data = {
            spec.name: {
                'dialogue': [
                    {
                        'sequence': 1,
                        'request': {
                            'path': '/',
                            'method': spec.name.upper(),
                            'raw': raw_bytes.decode('latin-1', errors='replace')[:5000],
                            'headers': {},
                        },
                        'response': {
                            'raw': reply.decode('latin-1', errors='replace')[:5000],
                            'size': len(reply),
                            'detected': spec.detected_id,
                        },
                    }
                ]
            }
        }
    return bs


def _enrich_and_send_bear(bs, bot_ip: str) -> None:
    """Resolve geo/DNS + classify + queue the report for a BearStorage (issue #377).

    Equivalent to ``HTTPHandler._enrich_and_send`` but callable without an
    ``HTTPHandler`` instance, so the non-HTTP dispatch path can reuse the exact
    same enrichment pipeline (geo, DNS, benign classification, report queue).
    """
    try:
        bs.dns_name = bs.resolve_dns_name(bot_ip, timeout=1.0)
    except Exception:
        logger.debug('DNS resolution failed for %s', bot_ip)
    try:
        bs.resolve_geo(bot_ip, timeout=2.0)
    except Exception:
        logger.debug('Geo resolution failed for %s', bot_ip)
    # Backfill: the async lookup returns empty on first contact (it schedules a
    # background worker). For captures that still lack ASN/org after the async
    # pass (common on non-HTTP faces — SSH/FTP/Telnet/SMTP — issues #430/#449),
    # do a blocking sync lookup so the attacker-infra attribution actually lands
    # on the row instead of staying NULL. Guarded so it only fires when empty.
    if not bs.asn and not bs.org:
        try:
            from manyfaced.common.geolocate import lookup_ip_geolocation_sync

            country, continent, asn, org = lookup_ip_geolocation_sync(bot_ip, timeout=2.0)
            if asn or org:
                bs.country = country or bs.country
                bs.continent = continent or bs.continent
                bs.asn = asn
                bs.org = org
        except Exception:
            logger.debug('Sync geo backfill failed for %s', bot_ip)
    try:
        bs.classification, bs.benign_source = classify(
            reverse_dns=bs.dns_name,
            org=bs.org,
            asn=bs.asn,
            user_agent=bs.ua,
        )
        from manyfaced.common.metrics import incr

        incr(f'classification.{bs.classification}')
    except Exception:
        logger.debug('Classification failed for %s', bot_ip)

    server_host = getattr(_ENRICH_ARGS, 'server_host', '127.0.0.1')
    server_port = getattr(_ENRICH_ARGS, 'server', None)
    if server_port is not None:
        q = _get_report_queue()
        from manyfaced.client.report_sender import send_report  # noqa: PLC0415

        q.put(
            (
                send_report,
                (bs, bot_ip, settings.HIVEPASS, server_host, server_port, settings.HIVELOGIN),
            )
        )


# Args namespace captured once at startup so non-HTTP enrichment can reach the
# report server host/port without threading an HTTPHandler instance through.
_ENRICH_ARGS = None


def set_enrich_args(args) -> None:
    """Register the parsed CLI args so ``_enrich_and_send_bear`` can reach the
    report server host/port (issue #377). Called once from the client main."""
    global _ENRICH_ARGS
    _ENRICH_ARGS = args
