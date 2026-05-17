"""HTTPHandler – handles raw HTTP requests from bots.

Routes to service-specific handlers via Router, generates honeypot responses,
and queues reports for sending to the server. Response content is delegated
to protocol_responses module; report queue management to report_queue module.
"""

from __future__ import annotations

import os
import random
from datetime import datetime, timezone

from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.config import settings
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
    UNKNOWN_TLS,
)
from manyfaced.handlers.protocol_responses import (
    fallback_response,
    fake_ssh_banner,
    ftp_banners,
    non_http_response,
)
from manyfaced.handlers.report_queue import _get_report_queue, shutdown_report_executor

logger = get_logger(__name__)


# Singleton router – initialized on first use
_router: object | None = None


def _get_router():
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
        """Handle a raw HTTP request from a bot."""
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
                parsed = HTTPRequest('GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n')
        except Exception as e:
            logger.debug('Failed to parse HTTP request: %s, using fallback for %s', e, bot_ip)
            parsed = HTTPRequest('GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n')

        raw_for_report = message if message else 'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n'
        data = {
            'ip': bot_ip,
            'raw_request': raw_for_report,
            'parsed_request': parsed,
        }
        return self.process_request(data)

    def _handle_ssh_probe(self, bot_ip: str, protocol_info: dict) -> bytes:
        """Handle an SSH probe by responding with a fake SSH banner."""
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
            bot_ip, protocol_info.get('raw', 'SSH-2.0-PUTTY'),
            str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')),
            _ParsedSSH(), SSH_CLIENT, settings.HIVELOGIN,
        )
        self._enrich_and_send(bs, bot_ip)
        return banner.encode('utf-8')

    def _handle_non_http_probe(self, bot_ip: str, protocol: str, protocol_info: dict) -> bytes:
        """Handle non-HTTP protocol probes."""
        detected_id = {
            'tls': UNKNOWN_TLS, 'dns': UNKNOWN_DNS,
            'mongodb': UNKNOWN_MONGODB, 'redis': UNKNOWN_REDIS,
        }.get(protocol, UNKNOWN_NON_HTTP)

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
            bot_ip, protocol_info.get('raw', ''),
            str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')),
            _ParsedNonHTTP(), detected_id, settings.HIVELOGIN,
        )
        self._enrich_and_send(bs, bot_ip)
        return response

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

        router = _get_router()
        path = getattr(parsed, 'path', '/')
        result = router.dispatch(path, raw_request, bot_ip, headers or {})

        if result is not None:
            output_data, detected = result
        else:
            output_data, detected = fallback_response(path), 1

        logger.debug('Generated response for %s, detected=%s, size=%d', bot_ip, detected, len(output_data))

        bs = BearStorage(
            bot_ip, raw_request, request_time, parsed, detected, settings.HIVELOGIN,
        )
        self._enrich_and_send(bs, bot_ip)
        return output_data

    def _handle_empty_connection(self, bot_ip: str) -> bytes:
        """Handle a zero-byte connection (port scan with no data sent)."""
        class _ParsedEmpty:
            command = ''
            path = ''
            version = ''
            headers = {}
            user_agent = ''
            request_version = ''

        bs = BearStorage(
            bot_ip, '', str(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')),
            _ParsedEmpty(), EMPTY_CONNECTION, settings.HIVELOGIN,
        )
        self._enrich_and_send(bs, bot_ip)
        return fallback_response('')

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

        server_host = getattr(self.args, 'server_host', '127.0.0.1')
        server_port = getattr(self.args, 'server', None)
        if server_port is not None:
            q = _get_report_queue()
            from manyfaced.client.client import send_report  # noqa: PLC0415
            q.put((send_report, (bs, bot_ip, settings.HIVEPASS, server_host, server_port, settings.HIVELOGIN)))

    @staticmethod
    def _extract_method(raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'
