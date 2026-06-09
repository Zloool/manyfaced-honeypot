"""MongoDB Wire Protocol handler for the manyfaced honeypot.

Generates realistic MongoDB wire protocol responses and captures credentials
from authentication commands (saslStart, authenticate).

Protocol reference: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
"""

from __future__ import annotations

import logging
import random
import re
import struct
from typing import Tuple

logger = logging.getLogger(__name__)


def _build_message(body: bytes) -> bytes:
    """Build a complete MongoDB wire protocol message.

    Format: {length(4 LE)+flags(4 LE)+cursor_id(8 BE)+response_to(4 LE)+opcode(4 LE)}

    Args:
        body: The message body (without the 16-byte header).

    Returns:
        Complete wire protocol message as bytes.
    """
    length = 16 + len(body)
    return (
        struct.pack('<I', length)
        + b'\x00\x00\x00\x00'
        + struct.pack('<q', 0)
        + struct.pack('<i', 0)
        + struct.pack('<I', 1)
        + body
    )


def _build_op_reply(body: bytes) -> bytes:
    """Build an OP_REPLY message (legacy wire protocol).

    Args:
        body: The reply body.

    Returns:
        Complete OP_REPLY message as bytes.
    """
    return (
        struct.pack('<I', 1)
        + b'\x00\x00\x00\x00'
        + struct.pack('<q', 0)
        + struct.pack('<i', 0)
        + body
    )


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
    try:
        text = raw_data.decode('utf-8', errors='replace')
    except Exception:
        return _build_op_reply(b'')

    # Detect authentication commands and capture credentials
    if re.search(r'(?:authenticate|saslStart|SCRAM)', text, re.IGNORECASE):
        creds = extract_mongodb_credentials(raw_data)
        if creds:
            logger.info(
                'Captured MongoDB credentials from %s: user=%s',
                bot_ip,
                creds[0],
            )

    # saslStart command — return authentication challenge
    if re.search(r'saslStart', text, re.IGNORECASE):
        mechanisms = ['SCRAM-SHA-1', 'SCRAM-SHA-256']
        mechanism = random.choice(mechanisms)
        nonce = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=24))

        if mechanism == 'SCRAM-SHA-1':
            body_str = (
                '{"done":false,'
                '"conversationId":1,'
                f'"mechanism":"{mechanism}",'
                f'"payload":"{nonce}n,,n={bot_ip.split(".")[-1]},r={nonce}"'
                '}'
            )
        else:
            body_str = (
                '{"done":false,'
                '"conversationId":1,'
                f'"mechanism":"{mechanism}",'
                f'"payload":"n,,n=*,r={nonce}"'
                '}'
            )

        return _build_op_reply(body_str.encode('utf-8'))

    # authenticate command (legacy) — return auth failure
    if re.search(r'(?:authenticate|auth)', text, re.IGNORECASE):
        body_str = '{"ok":0.0,"code":18,"errmsg":"Authentication failed.","data":null}'
        return _build_op_reply(body_str.encode('utf-8'))

    # ismaster / hello command — respond as primary replica set member
    if re.search(r'(?:ismaster|hello)\s*[:\s]', text, re.IGNORECASE):
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
            '"authMechanisms":["MONGODB-CR","SCRAM-SHA-1","SCRAM-SHA-256",'
            '"saslSupportedMechs":"PLAIN",'
            '"compression":[],"ok":1.0'
            '}'
        )
        return _build_op_reply(body_str.encode('utf-8'))

    # find / count / aggregate — return empty result set
    if re.search(r'(?:find|count|aggregate|distinct)', text, re.IGNORECASE):
        body_str = '{"cursor":{"id":0,"ns":"test.collection","firstBatch":[]},"ok":1.0}'
        return _build_op_reply(body_str.encode('utf-8'))

    # insert — acknowledge success
    if re.search(r'(?:insert|bulkWrite)', text, re.IGNORECASE):
        body_str = '{"n":1,"writeConcernError":null,"ok":1.0}'
        return _build_op_reply(body_str.encode('utf-8'))

    # Default: OP_REPLY with empty body
    return _build_op_reply(b'')


def generate_mongodb_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate an initial MongoDB greeting (empty — server waits for client).

    Args:
        bot_ip: The bot's IP address (for logging).

    Returns:
        Empty bytes (MongoDB servers don't send greetings; they wait for the client).
    """
    logger.info('Waiting for MongoDB handshake from %s', bot_ip)
    return b''
