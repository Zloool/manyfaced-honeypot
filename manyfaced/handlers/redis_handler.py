"""Redis RESP protocol handler for the manyfaced honeypot.

Generates realistic Redis Serialization Protocol (RESP) responses and captures
credentials from AUTH commands sent by probing bots.

Supports the RESP3 HELLO handshake modern clients (redis-py 8.x, lettuce,
jedis ...) open with (issue #382), so high-level client libraries can actually
establish a session instead of raising on a raw-string reply. Raw RESP clients
(PING / SET / GET / VERSION) keep working unchanged.

Protocol reference: https://redis.io/docs/latest/develop/interact/protocol/
"""

from __future__ import annotations

import logging
import re
from typing import Tuple

logger = logging.getLogger(__name__)

# Server identity advertised in the HELLO reply (looks like a recent Redis).
_REDIS_VERSION = '7.2.3'

# RESP3 push-map HELLO reply: %<n> then key/value pairs. redis-py reads this
# as a dict and expects the keys below.
_HELLO_FIELDS = {
    'server': 'redis',
    'version': _REDIS_VERSION,
    'proto': 3,
    'id': 1,
    'mode': 'standalone',
    'role': 'master',
    'modules': [],
}

# CRLF as a bytes literal built without backslash escapes (keeps the source
# free of literal control chars that confuse editors / diff / patch tools).
_CRLF = bytes([13, 10])


def extract_redis_credentials(raw_data) -> Tuple[str, str] | None:
    """Extract credentials from a Redis AUTH command in raw data.

    Parses RESP-formatted AUTH commands to capture username and password.
    Accepts either bytes or str input.
    """
    try:
        text = (
            raw_data.decode('utf-8', errors='replace')
            if isinstance(raw_data, (bytes, bytearray))
            else raw_data
        )
    except Exception:
        return None

    # Match AUTH <user> <pass> in plain text format (single line, no RESP formatting)
    auth_match = re.search(r'AUTH\s+(\S+)\s+(\S+)', text, re.IGNORECASE | re.MULTILINE)
    if auth_match:
        user = auth_match.group(1)
        password = auth_match.group(2)
        if not user.startswith('$') and not password.startswith('$'):
            return (user, password)

    # RESP bulk string format: *3\r\n$4\r\nAUTH\r\n$5\r\nuser\r\n$6\r\npass\r\n
    parts = text.split('\r\n')
    creds = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if re.match(r'^\$(\d+)$', part):
            if i + 1 < len(parts):
                creds.append(parts[i + 1])
                i += 2
                continue
        i += 1

    if 'AUTH' in text.upper() and len(creds) >= 3:
        return (creds[1], creds[2])
    return None


def _parse_resp_command(raw_data):
    """Parse a single RESP command frame into a list of argument strings.

    Handles RESP arrays (*N\r\n$len\r\ndata\r\n...) and inline commands
    (PING\r\n). Returns None when the frame is not a recognised command.
    """
    if isinstance(raw_data, (bytes, bytearray)):
        text = raw_data.decode('utf-8', errors='replace')
    else:
        text = raw_data
    if not text:
        return None

    if not text.startswith('*'):
        line = text.strip()
        if not line:
            return None
        return line.split()

    try:
        header, _, rest = text.partition('\r\n')
        if not header.startswith('*'):
            return None
        count = int(header[1:].strip())
        if count <= 0:
            return []
        args = []
        idx = 0
        for _ in range(count):
            nl = rest.find('\r\n', idx)
            if nl == -1:
                return None
            len_line = rest[idx:nl]
            if not len_line.startswith('$'):
                return None
            blen = int(len_line[1:].strip())
            start = nl + 2
            end = start + blen
            args.append(rest[start:end])
            idx = end + 2
        return args
    except (ValueError, IndexError):
        return None


def _encode_resp_value(v) -> bytes:
    """Encode a Python value as a RESP2/RESP3 wire value."""
    if isinstance(v, bool):
        return b':1' + _CRLF if v else b':0' + _CRLF
    if isinstance(v, int):
        return f':{v}'.encode('ascii') + _CRLF
    if isinstance(v, str):
        b = v.encode('utf-8')
        return b'$' + str(len(b)).encode('ascii') + _CRLF + b + _CRLF
    if isinstance(v, (bytes, bytearray)):
        return b'$' + str(len(v)).encode('ascii') + _CRLF + bytes(v) + _CRLF
    if isinstance(v, (list, tuple)):
        body = b''.join(_encode_resp_value(x) for x in v)
        return b'*' + str(len(v)).encode('ascii') + _CRLF + body
    if isinstance(v, dict):
        body = b''.join(_encode_resp_value(k) + _encode_resp_value(val) for k, val in v.items())
        return b'%' + str(len(v)).encode('ascii') + _CRLF + body
    return _encode_resp_value(str(v))


def _hello_reply(use_proto: int) -> bytes:
    """Build a HELLO reply for the requested protocol version (issue #382).

    RESP3 (proto 3): a %7 push-map. RESP2 (proto 2): the same fields as a flat
    *14 array of interleaved keys/values. redis-py parses both.
    """
    fields = _HELLO_FIELDS
    if use_proto <= 2:
        flat = []
        for k, val in fields.items():
            flat.append(k)
            flat.append(val)
        return (
            b'*'
            + str(len(flat)).encode('ascii')
            + _CRLF
            + b''.join(_encode_resp_value(x) for x in flat)
        )
    return _encode_resp_value(dict(fields))


def generate_redis_response(raw_data, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic Redis RESP response for the given probe data.

    Handles the RESP3 HELLO handshake (issue #382) plus the legacy
    PING/SET/GET/VERSION/AUTH commands used by raw RESP clients. Accepts both
    bytes and str input (the HTTP handler sometimes passes decoded text).
    """
    if isinstance(raw_data, (bytes, bytearray)):
        raw_bytes = raw_data
    else:
        raw_bytes = raw_data.encode('utf-8', errors='replace')

    args = _parse_resp_command(raw_bytes)
    if args is None:
        text = raw_bytes.decode('utf-8', errors='replace')
        if re.search(r'PING\s*$', text.strip()):
            return b'+PONG' + _CRLF
        return b'+PONG' + _CRLF

    cmd = args[0].upper()

    # HELLO handshake (RESP3 negotiation, issue #382)
    if cmd == 'HELLO':
        use_proto = 3
        for tok in args[1:]:
            if tok.isdigit():
                use_proto = int(tok)
        if 'AUTH' in args:
            try:
                ai = args.index('AUTH')
                user = args[ai + 1] if len(args) > ai + 1 else ''
                pw = args[ai + 2] if len(args) > ai + 2 else ''
                if user and not user.startswith('$'):
                    logger.info('Captured Redis credentials from %s: user=%s', bot_ip, user)
                    if pw and not pw.startswith('$'):
                        logger.info('Redis AUTH password attempt from %s', bot_ip)
            except IndexError:
                pass
        return _hello_reply(use_proto)

    # AUTH: record the attempt, then *accept* so the session continues.
    if cmd == 'AUTH':
        creds = extract_redis_credentials(raw_bytes)
        if creds:
            logger.info('Captured Redis credentials from %s: user=%s', bot_ip, creds[0])
        return b'+OK' + _CRLF

    if cmd == 'PING':
        return b'+PONG' + _CRLF
    if cmd == 'VERSION':
        return f'VERSION {_REDIS_VERSION}'.encode('ascii') + _CRLF
    if cmd == 'SET':
        return b'+OK' + _CRLF
    if cmd == 'GET':
        return b'$-1' + _CRLF
    if cmd == 'DEL':
        return b':0' + _CRLF
    if cmd == 'EXISTS':
        return b':0' + _CRLF
    if cmd in ('KEYS', 'CONFIG', 'CLIENT', 'INFO', 'COMMAND', 'ECHO', 'SELECT'):
        if cmd == 'COMMAND':
            return b'*0' + _CRLF
        if cmd == 'ECHO' and len(args) > 1:
            return _encode_resp_value(args[1])
        if cmd == 'CLIENT':
            return b'+OK' + _CRLF
        if cmd == 'INFO':
            return b'$0' + _CRLF + _CRLF
        return b'+OK' + _CRLF

    return b'+PONG' + _CRLF


def generate_redis_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate the initial Redis greeting sent when a client connects.

    Redis sends nothing at connect time (client-first); the honeypot therefore
    greets with an empty banner and waits for the client's first command.
    """
    logger.info('Redis connection from %s (client-first, no banner)', bot_ip)
    return b''
