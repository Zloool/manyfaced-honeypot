"""MongoDB Wire Protocol handler for the manyfaced honeypot.

Generates realistic MongoDB wire protocol responses and captures credentials
from authentication commands (saslStart, authenticate).

Protocol reference: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
"""

from __future__ import annotations

import itertools
import logging
import random
import re
import struct
from datetime import datetime, timezone
from typing import Any, Tuple

logger = logging.getLogger(__name__)

# MongoDB OP_REPLY opcode (legacy wire protocol, still accepted by old clients
# for hello/ismaster in the fallback path).
OP_REPLY = 1

# MongoDB OP_MSG opcode (the modern wire protocol used by all drivers 4.2+).
# A modern driver opens the handshake with an OP_MSG `hello`/`isMaster` and
# bails out hard if it receives anything other than an OP_MSG reply.
OP_MSG = 2013

# Monotonic request-id counter so each reply carries a distinct, parseable id
# (drivers echo responseTo; 0 is legal but a counter avoids accidental reuse).
_request_id = itertools.count(1)


def _build_message(body: bytes, opcode: int = OP_REPLY) -> bytes:
    """Build a complete MongoDB wire protocol message with a valid 16-byte header.

    The standard header is::

        messageLength(4 LE) + requestID(4 LE) + responseTo(4 LE) + opcode(4 LE)

    where ``messageLength`` is the TOTAL length of the message *including* the
    header. The body is the reply payload (for OP_REPLY: responseFlags(4) +
    cursorID(8) + numberReturned(4) + documents…; we keep the legacy body as a
    JSON document so it round-trips through a JSON parser in tests/real clients).

    Args:
        body: The message body (without the 16-byte header).
        opcode: The MongoDB opcode (default OP_REPLY = 1).

    Returns:
        Complete wire protocol message as bytes.
    """
    message_length = 16 + len(body)
    request_id = next(_request_id)
    return (
        struct.pack('<I', message_length)
        + struct.pack('<I', request_id)
        + struct.pack('<I', 0)  # responseTo
        + struct.pack('<I', opcode)
        + body
    )


# --- Minimal BSON (binary JSON) support -------------------------------------
#
# OP_MSG payloads are BSON documents, NOT the JSON text the legacy OP_REPLY
# path emits. We only need a small subset of BSON to (a) read the command name
# out of an incoming OP_MSG and (b) serialize a fixed hello/isMaster-style
# reply. We deliberately do not pull in pymongo/bson (not a dependency) and
# keep the encoder strict enough for the handful of scalar types we emit.


# BSON type byte -> encoder for the python value (single value -> bytes).
def _bson_encode_doc(doc: dict[str, Any]) -> bytes:
    """Encode a python dict into a single BSON document (with trailing \\x00)."""
    body = b''.join(_bson_encode_element(k, v) for k, v in doc.items())
    # length prefix (4 LE) + body + terminating null
    return struct.pack('<i', len(body) + 5) + body + b'\x00'


def _bson_encode_element(name: str, value: Any) -> bytes:
    name_bytes = name.encode('utf-8') + b'\x00'
    if isinstance(value, bool):
        return b'\x08' + name_bytes + (b'\x01' if value else b'\x00')
    if isinstance(value, int):
        return b'\x10' + name_bytes + struct.pack('<i', value)
    if isinstance(value, float):
        return b'\x01' + name_bytes + struct.pack('<d', value)
    if isinstance(value, str):
        vb = value.encode('utf-8')
        return b'\x02' + name_bytes + struct.pack('<i', len(vb) + 1) + vb + b'\x00'
    if value is None:
        return b'\x0a' + name_bytes
    if isinstance(value, datetime):
        # UTC datetime — BSON stores milliseconds since epoch as int64.
        epoch_ms = int(value.timestamp() * 1000)
        return b'\x09' + name_bytes + struct.pack('<q', epoch_ms)
    if isinstance(value, list):
        sub = {str(i): v for i, v in enumerate(value)}
        return b'\x04' + name_bytes + _bson_encode_doc(sub)
    if isinstance(value, dict):
        return b'\x03' + name_bytes + _bson_encode_doc(value)
    raise TypeError(f'Unsupported BSON value type for key {name!r}: {type(value)!r}')


def _bson_read_cstring(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.index(b'\x00', pos)
    return buf[pos:end].decode('utf-8'), end + 1


def _bson_decode_doc(buf: bytes, pos: int = 0) -> tuple[dict[str, Any], int]:
    """Decode a single BSON document starting at ``pos``. Returns (doc, end)."""
    (doc_len,) = struct.unpack_from('<i', buf, pos)
    end = pos + doc_len
    p = pos + 4
    doc: dict[str, Any] = {}
    while p < end - 1:
        elem_type = buf[p]
        p += 1
        name, p = _bson_read_cstring(buf, p)
        value, p = _bson_decode_value(elem_type, buf, p)
        doc[name] = value
    return doc, end


def _bson_decode_value(elem_type: int, buf: bytes, pos: int) -> tuple[Any, int]:
    if elem_type == 0x01:  # double
        (v,) = struct.unpack_from('<d', buf, pos)
        return v, pos + 8
    if elem_type == 0x02:  # string
        (ln,) = struct.unpack_from('<i', buf, pos)
        p = pos + 4
        s = buf[p : p + ln - 1].decode('utf-8')
        return s, p + ln
    if elem_type == 0x03:  # embedded document
        return _bson_decode_doc(buf, pos)
    if elem_type == 0x04:  # array
        sub, p = _bson_decode_doc(buf, pos)
        return [sub[str(i)] for i in range(len(sub))], p
    if elem_type == 0x08:  # boolean
        return (buf[pos] != 0), pos + 1
    if elem_type == 0x0A:  # null
        return None, pos
    if elem_type == 0x10:  # int32
        (v,) = struct.unpack_from('<i', buf, pos)
        return v, pos + 4
    if elem_type == 0x12:  # int64
        (v,) = struct.unpack_from('<q', buf, pos)
        return v, pos + 8
    if elem_type == 0x09:  # UTC datetime (int64 ms)
        (v,) = struct.unpack_from('<q', buf, pos)
        return v, pos + 8
    raise ValueError(f'Unsupported BSON element type 0x{elem_type:02x}')


def _bson_first_key(doc: dict[str, Any]) -> str | None:
    """Return the first key of a decoded BSON document (the command name)."""
    for k in doc:
        return k
    return None


# --- OP_MSG reply construction ---------------------------------------------


def _build_op_msg(body: bytes, response_to: int = 0) -> bytes:
    """Build a complete OP_MSG wire protocol message.

    OP_MSG wire format (after the standard 16-byte header)::

        flagBits(4 LE) + sections…

    The only section kind we emit is kind 0 (single BSON document body). The
    checksum-present flag (bit 0) is intentionally NOT set, so no trailing
    CRC32C follows the body (drivers accept messages without a checksum).
    """
    flag_bits = 0
    section = b'\x00' + body  # kind 0x00 = body as a single BSON document
    payload = struct.pack('<I', flag_bits) + section
    message_length = 16 + len(payload)
    request_id = next(_request_id)
    return (
        struct.pack('<I', message_length)
        + struct.pack('<I', request_id)
        + struct.pack('<I', response_to)
        + struct.pack('<I', OP_MSG)
        + payload
    )


def _hello_reply_doc() -> dict[str, Any]:
    """A plausible hello/isMaster-style response so modern drivers continue."""
    return {
        'ismaster': True,
        'helloOk': True,
        'topologyVersion': {
            'processId': '000000000000000000000001',
            'counter': 0,
        },
        'hosts': ['mongo-honeypot:27017'],
        'setName': 'honeypot-rs',
        'setVersion': 1,
        'me': 'mongo-honeypot:27017',
        'maxBsonObjectSize': 16777216,
        'maxMessageSizeBytes': 48000000,
        'maxWriteBatchSize': 1000,
        'localTime': datetime.now(timezone.utc),
        'logicalSessionTimeoutMinutes': 30,
        'minWireVersion': 0,
        'maxWireVersion': 21,
        'readOnly': False,
        'authMechanisms': [
            'MONGODB-CR',
            'SCRAM-SHA-1',
            'SCRAM-SHA-256',
        ],
        'ok': 1.0,
    }


def generate_op_msg_reply(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Parse an OP_MSG request and return a valid OP_MSG reply.

    The first section of the incoming OP_MSG carries the command document
    (e.g. ``{hello: 1, ...}`` or ``{isMaster: 1, ...}``). We echo the
    request id as ``responseTo`` and reply with a hello-style document.

    Args:
        raw_data: Raw bytes received from the bot (the full wire message,
            including the 16-byte header).
        bot_ip: The bot's IP address (for logging).

    Returns:
        A complete OP_MSG wire protocol reply.
    """
    if isinstance(raw_data, str):
        raw_data = raw_data.encode('latin-1')
    try:
        (message_length,) = struct.unpack_from('<I', raw_data, 0)
        response_to = struct.unpack_from('<I', raw_data, 4)[0]
        if len(raw_data) < 16 or message_length != len(raw_data):
            # Malformed frame — fall back to a generic OP_MSG hello reply
            # with responseTo 0 rather than letting the driver desync.
            response_to = 0
        section_pos = 20
        # Skip any section kinds we don't decode (we only need the first one).
        doc: dict[str, Any] = {}
        if section_pos < len(raw_data):
            section_kind = raw_data[section_pos]
            if section_kind == 0x00:
                doc, _ = _bson_decode_doc(raw_data, section_pos + 1)
            # kind 1 (document sequence) is not expected for handshake
            # commands; ignore it.
        command = _bson_first_key(doc)
        # Capture credentials if the handshake carried auth material.
        if command in ('saslStart', 'authenticate') or re.search(
            r'(?:saslStart|authenticate|SCRAM)',
            str(doc),
            re.IGNORECASE,
        ):
            creds = extract_mongodb_credentials(raw_data)
            if creds:
                logger.info(
                    'Captured MongoDB credentials from %s: user=%s',
                    bot_ip,
                    creds[0],
                )
        return _build_op_msg(_bson_encode_doc(_hello_reply_doc()), response_to)
    except Exception:  # noqa: BLE001 - never let a parse error crash the handler
        logger.debug('Failed to parse OP_MSG from %s', bot_ip, exc_info=True)
        return _build_op_msg(_bson_encode_doc(_hello_reply_doc()))


def extract_mongodb_credentials(raw_data: bytes) -> Tuple[str, str] | None:
    """Extract credentials from MongoDB authentication commands in raw data.

    Parses both legacy 'authenticate' command and modern saslStart mechanism.

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        Tuple of (username, password) if auth detected, else None.
    """
    try:
        text = raw_data.decode('utf-8', errors='replace')
    except Exception:
        return None

    # Legacy authenticate command: {authenticate: 1, user: "...", pwd: "..."}
    auth_match = re.search(
        r'"(?:user|username)\s*:\s*"([^"]+)"[^}]*?(?:pwd|password)\s*:\s*"([^"]+)"',
        text,
    )
    if not auth_match:
        # Try reversed order (pwd before user)
        auth_match = re.search(
            r'"(?:pwd|password)\s*:\s*"([^"]+)"[^}]*?(?:user|username)\s*:\s*"([^"]+)"',
            text,
        )

    if auth_match:
        return (auth_match.group(2), auth_match.group(1))

    # SCRAM-SHA-256 saslStart: look for firstStepData containing user and mechanism
    scram_match = re.search(r'"user"\s*:\s*"([^"]+)"', text)
    if scram_match:
        username = scram_match.group(1)
        nonce_match = re.search(r'"nonce"\s*:\s*"([^"]+)"', text)
        if nonce_match:
            return (username, f'scram-nonce:{nonce_match.group(1)}')
        return (username, '')

    return None


def generate_mongodb_response(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic MongoDB wire protocol response for the given probe data.

    Args:
        raw_data: Raw bytes received from the bot connection.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Protocol-compliant MongoDB wire protocol message as bytes.
    """
    if isinstance(raw_data, str):
        raw_data = raw_data.encode('latin-1')
    # Dispatch on the wire opcode first. Modern drivers (4.2+) open the
    # handshake with an OP_MSG `hello`/`isMaster`; replying to that with a
    # legacy OP_REPLY makes them bail immediately. Keep OP_REPLY for old
    # clients (and OP_MSG for modern ones).
    if len(raw_data) >= 20:
        opcode = struct.unpack_from('<I', raw_data, 12)[0]
        if opcode == OP_MSG:
            return generate_op_msg_reply(raw_data, bot_ip)
        # Other modern opcodes (OP_QUERY=2004, OP_COMPRESSED=2012, …) and
        # legacy ones all fall through to the OP_REPLY text path below.

    try:
        text = raw_data.decode('utf-8', errors='replace')
    except Exception:
        return _build_message(b'')

    # Detect authentication commands and capture credentials
    if re.search(r'(?:authenticate|saslStart|SCRAM)', text, re.IGNORECASE):
        creds = extract_mongodb_credentials(raw_data)
        if creds:
            logger.info(
                'Captured MongoDB credentials from %s: user=%s',
                bot_ip,
                creds[0],
            )

    # saslStart command — return a wire-valid SCRAM authentication challenge.
    # The SCRAM first-server-message is `r=...,s=...,i=...`. We echo the
    # client-provided nonce (the part after the last ',' in the client's
    # `r=`) and append our own server nonce; if the client did not send one
    # we generate a fresh one. The client identity `n=` is left to the
    # client (we do not inject a magic octet).
    if re.search(r'saslStart', text, re.IGNORECASE):
        mechanism = random.choice(['SCRAM-SHA-1', 'SCRAM-SHA-256'])
        client_nonce = ''
        cm = re.search(r'"r":"([^"]*)"', text)
        if cm:
            # client nonce is everything before the last ','
            client_nonce = cm.group(1).rsplit(',', 1)[0]
        nonce = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=24))
        combined = (client_nonce + nonce) if client_nonce else nonce
        salt = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=24))
        iterations = 4096
        payload = f'r={combined},s={salt},i={iterations}'
        body_str = (
            f'{{"done":false,"conversationId":1,"mechanism":"{mechanism}","payload":"{payload}"}}'
        )
        return _build_message(body_str.encode('utf-8'))

    # authenticate command (legacy) — return auth failure
    if re.search(r'(?:authenticate|auth)', text, re.IGNORECASE):
        body_str = '{"ok":0.0,"code":18,"errmsg":"Authentication failed.","data":null}'
        return _build_message(body_str.encode('utf-8'))

    # ismaster / hello command — respond as primary replica set member.
    # The authMechanisms array is properly closed so the body is valid JSON.
    # We accept both the modern `hello` command and the legacy `isMaster`
    # alias (drivers send either, and some send a bare `isMaster:1` without a
    # trailing delimiter, so we match the bare keyword too).
    if re.search(r'(?:ismaster|isMaster|hello)', text, re.IGNORECASE):
        ts = str(int(random.randint(1700000000, 1900000000)))
        body_str = (
            '{"isWritablePrimary":true,'
            '"topologyVersion":{"processId":"000000000000000000000001",'
            '"counter":0},'
            '"hosts":["mongo-honeypot:27017"],'
            '"setName":"honeypot-rs",'
            '"setVersion":1,'
            '"me":"mongo-honeypot:27017",'
            '"maxBsonObjectSize":16777216,'
            '"maxMessageSizeBytes":48000000,'
            '"maxWriteBatchSize":1000,'
            f'"localTime":{ts},'
            '"logicalSessionTimeoutMinutes":30,'
            '"minWireVersion":0,'
            '"maxWireVersion":21,'
            '"readOnlySecondaryElects":false,'
            '"authMechanisms":["MONGODB-CR","SCRAM-SHA-1","SCRAM-SHA-256"],'
            '"saslSupportedMechs":["PLAIN"],'
            '"compression":[],"ok":1.0'
            '}'
        )
        return _build_message(body_str.encode('utf-8'))

    # find / count / aggregate — return empty result set
    if re.search(r'(?:find|count|aggregate|distinct)', text, re.IGNORECASE):
        body_str = '{"cursor":{"id":0,"ns":"test.collection","firstBatch":[]},"ok":1.0}'
        return _build_message(body_str.encode('utf-8'))

    # insert — acknowledge success
    if re.search(r'(?:insert|bulkWrite)', text, re.IGNORECASE):
        body_str = '{"n":1,"writeConcernError":null,"ok":1.0}'
        return _build_message(body_str.encode('utf-8'))

    # Default: OP_REPLY with empty body
    return _build_message(b'')


def generate_mongodb_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate an initial MongoDB greeting (empty — server waits for client).

    Args:
        bot_ip: The bot's IP address (for logging).

    Returns:
        Empty bytes (MongoDB servers don't send greetings; they wait for the client).
    """
    logger.info('Waiting for MongoDB handshake from %s', bot_ip)
    return b''
