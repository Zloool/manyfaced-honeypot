"""HTTPHandler – handles raw HTTP requests from bots.

Routes to service-specific handlers via Router, generates honeypot responses,
and queues reports for sending to the server. Response content is delegated
to protocol_responses module; report queue management to report_queue module.
"""

from __future__ import annotations

import os
import random
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from manyfaced.handlers.router import Router  # noqa: F401

from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.config import settings
from manyfaced.common.credential_extractor import extract_http_credentials, format_creds_string
from manyfaced.common.httphandler import HTTPRequest
from manyfaced.common.logging_setup import get_logger
from manyfaced.common.protocol import detect_protocol, get_protocol_info
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
    ftp_banners,
    non_http_response,
)
from manyfaced.handlers.redis_handler import generate_redis_response, extract_redis_credentials
from manyfaced.handlers.mongodb_handler import (
    generate_mongodb_response,
    extract_mongodb_credentials,
)
from manyfaced.handlers.telnet_handler import (
    generate_telnet_response,
    extract_telnet_credentials,
    generate_telnet_greeting,
)
from manyfaced.handlers.rdp_handler import generate_rdp_response, extract_rdp_credentials
from manyfaced.handlers.vnc_handler import generate_vnc_response, extract_vnc_credentials
from manyfaced.handlers.report_queue import _get_report_queue, shutdown_report_executor

logger = get_logger(__name__)


# Singleton router – initialized on first use
_router: Router | None = None


def _get_router() -> Router:
    """Get or create the module-level router (singleton)."""
    global _router
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

    def __init__(self, args, update_event):
        self.args = args
        self.update_event = update_event

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
            headers = {}
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
        else:
            # Fallback to legacy handler for other protocols
            response = non_http_response(protocol)

        if response is None:
            response = b''

        class _ParsedNonHTTP:
            command = protocol.upper()
            path = '/'
            version = protocol_info.get('version', protocol)
            headers = {}
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

    def process_request(self, data):
        """Process an incoming HTTP request."""
        from manyfaced.client.client import send_report  # noqa: PLC0415

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
            headers = {}
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
        try:
            bs.dns_name = bs.resolve_dns_name(bot_ip, timeout=1.0)
        except Exception:
            logger.debug('DNS resolution failed for %s', bot_ip)

        try:
            bs.resolve_geo(bot_ip, timeout=2.0)
        except Exception:
            logger.debug('Geo resolution failed for %s', bot_ip)

        # Collect BotProfile data from all handler instances for this IP
        router = _get_router()
        profile_data = router.get_all_profiles_for_ip(bot_ip)
        if profile_data:
            bs.bot_profile_data = profile_data

        server_host = getattr(self.args, 'server_host', '127.0.0.1')
        server_port = getattr(self.args, 'server', None)
        if server_port is not None:
            q = _get_report_queue()
            from manyfaced.client.client import send_report  # noqa: PLC0415

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
