"""MCPHandler – Model Context Protocol (MCP) over HTTP (issue #427/#434).

Implements enough of the MCP-over-HTTP transport (the Streamable HTTP / SSE
variant that the production scanners hit) to be protocol-correct:

    GET /sse          -> text/event-stream; emits an ``endpoint`` event
                         carrying the JSON-RPC POST URL (``/mcp?sessionId=…``)
                         so a conformant client can open its stream and then
                         POST JSON-RPC to /mcp. A ``\n: ping\n`` keep-alive
                         comment is included so the stream frame is well-formed.
    POST /mcp         -> application/json JSON-RPC. Answers ``initialize`` with
                         a valid ``InitializeResult`` (protocolVersion,
                         capabilities, serverInfo); echoes other methods with a
                         minimal but valid result so the client does not hang.
    GET /mcp          -> returns a JSON-RPC error hint (clients probe both verbs).

The previously-shipped scaffold answered every request with a static HTML page
(and a text/html ``Content-Type``), which a real MCP client cannot parse, so
clients errored/hung. This is the minimal protocol-shaped replacement.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import MCP_HTTP

# Supported MCP protocol version (2025-03-26 is the current Streamable HTTP rev).
MCP_PROTOCOL_VERSION = '2025-03-26'


class MCPHandler(HTTPHandlerBase):
    """MCP honeypot handler (issue #427/#434)."""

    domain = 'mcp'
    DETECTED_ID = MCP_HTTP
    VERSION = '2024.11.0'

    # Per-request session ids are generated on demand (MCP requires the client
    # to learn the session endpoint via the SSE ``endpoint`` event).
    def _new_session_id(self) -> str:
        return secrets.token_hex(16)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an MCP response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        method = self._extract_method(raw_request)
        decoded = path.split('?', 1)[0].lower()

        request_data = {
            'path': path,
            'method': method,
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        # GET /sse -> Server-Sent Events stream handshake.
        if method == 'GET' and decoded == '/sse':
            session_id = self._new_session_id()
            body = f': ping\n\nevent: endpoint\ndata: /mcp?sessionId={session_id}\n\n'
            return (
                self._build_http_response(body, 200, 'OK', 'text/event-stream'),
                self.DETECTED_ID,
            )

        # /mcp -> JSON-RPC. POST carries the method call; GET just hints the
        # endpoint so probing clients see a protocol-shaped reply.
        if decoded == '/mcp' or decoded.startswith('/mcp?'):
            if method == 'POST':
                return self._handle_jsonrpc(raw_request), self.DETECTED_ID
            # GET /mcp : return a JSON-RPC error hint.
            return (
                self._build_http_response(
                    json.dumps(
                        {
                            'jsonrpc': '2.0',
                            'error': {
                                'code': -32000,
                                'message': 'Method not allowed. Use POST for '
                                'JSON-RPC or GET /sse to open a stream.',
                            },
                        }
                    ),
                    200,
                    'OK',
                    'application/json',
                ),
                self.DETECTED_ID,
            )

        # Anything else under the MCP face: minimal protocol-shaped JSON-RPC
        # error so we never fall back to a generic HTML page.
        return (
            self._build_http_response(
                json.dumps(
                    {
                        'jsonrpc': '2.0',
                        'error': {
                            'code': -32601,
                            'message': 'Method not found',
                        },
                    }
                ),
                200,
                'OK',
                'application/json',
            ),
            self.DETECTED_ID,
        )

    # ------------------------------------------------------------------ #
    # JSON-RPC                                                           #
    # ------------------------------------------------------------------ #

    def _handle_jsonrpc(self, raw_request: str) -> bytes:
        """Parse a JSON-RPC body and return a protocol-correct response."""
        try:
            payload = json.loads(self._body_of(raw_request))
        except (json.JSONDecodeError, ValueError):
            return self._jsonrpc_error(None, -32700, 'Parse error')

        if not isinstance(payload, dict):
            return self._jsonrpc_error(None, -32600, 'Invalid Request')

        req_id = payload.get('id')
        method = payload.get('method')

        if method == 'initialize':
            result = {
                'protocolVersion': MCP_PROTOCOL_VERSION,
                'capabilities': {
                    'tools': {},
                    'resources': {},
                    'prompts': {},
                    'logging': {},
                },
                'serverInfo': {
                    'name': 'manyfaced-mcp',
                    'version': self.VERSION,
                },
            }
            return self._jsonrpc_result(req_id, result)

        if method == 'ping':
            return self._jsonrpc_result(req_id, {})

        # tools/list, tools/call, resources/list, etc.: answer with an empty
        # but valid result so the client handshake completes instead of hanging.
        if isinstance(method, str):
            return self._jsonrpc_result(req_id, {})

        return self._jsonrpc_error(req_id, -32601, 'Method not found')

    @staticmethod
    def _body_of(raw_request: str) -> str:
        """Return the body portion of a raw HTTP request (after the blank line)."""
        if '\r\n\r\n' in raw_request:
            return raw_request.split('\r\n\r\n', 1)[1]
        if '\n\n' in raw_request:
            return raw_request.split('\n\n', 1)[1]
        return ''

    @staticmethod
    def _jsonrpc_result(req_id, result) -> bytes:
        return MCPHandler._jsonrpc(
            {
                'jsonrpc': '2.0',
                'id': req_id,
                'result': result,
            }
        )

    @staticmethod
    def _jsonrpc_error(req_id, code: int, message: str) -> bytes:
        return MCPHandler._jsonrpc(
            {
                'jsonrpc': '2.0',
                'id': req_id,
                'error': {'code': code, 'message': message},
            }
        )

    @staticmethod
    def _jsonrpc(obj: dict) -> bytes:
        body = json.dumps(obj, separators=(',', ':'))
        return MCPHandler._static_build(body, 'application/json')

    # ------------------------------------------------------------------ #
    # Helpers                                                            #
    # ------------------------------------------------------------------ #

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        status_code: int = 200,
        status_text: str = 'OK',
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        return self._static_build(body, content_type, status_code, status_text)

    @staticmethod
    def _static_build(
        body: str,
        content_type: str,
        status_code: int = 200,
        status_text: str = 'OK',
    ) -> bytes:
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('utf-8')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: MCP/{MCPHandler.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body_bytes)}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        ).encode('iso-8859-1') + body_bytes
        return response

    def __repr__(self) -> str:
        return f'MCPHandler(domain={self.domain!r})'
