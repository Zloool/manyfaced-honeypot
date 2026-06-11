"""Redis RESP protocol handler for the manyfaced honeypot.

Generates realistic Redis Serialization Protocol (RESP) responses and captures
credentials from AUTH commands sent by probing bots.

Protocol reference: https://redis.io/docs/latest/develop/interact/protocol/
"""

from __future__ import annotations

import logging
import re
from typing import Tuple

logger = logging.getLogger(__name__)


def extract_redis_credentials(raw_data: bytes) -> Tuple[str, str] | None:
    """Extract credentials from a Redis AUTH command in raw data.

    Parses RESP-formatted AUTH commands to capture username and password.

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        Tuple of (username, password) if an AUTH command is detected, else None.
    """
    try:
        text = raw_data.decode('utf-8', errors='replace')
    except Exception:
        return None

    # Match AUTH <user> <pass> in plain text format (single line, no RESP formatting)
    auth_match = re.search(r'AUTH\s+(\S+)\s+(\S+)', text, re.IGNORECASE | re.MULTILINE)
    if auth_match:
        user = auth_match.group(1)
        password = auth_match.group(2)
        # Skip RESP length indicators like $4, $5, etc.
        if not user.startswith('$') and not password.startswith('$'):
            return (user, password)

    # RESP bulk string format: *3\r\n$4\r\nAUTH\r\n$5\r\nuser\r\n$6\r\npass\r\n
    # Parse RESP array elements manually using a while loop
    parts = text.split('\r\n')
    creds = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if re.match(r'^\$(\d+)$', part):
            # This is a bulk string length indicator, next line is the value
            if i + 1 < len(parts):
                creds.append(parts[i + 1])
                i += 2
                continue
        i += 1

    # Check if AUTH command was found and we have credentials
    if 'AUTH' in text.upper() and len(creds) >= 3:
        # First element is the command name (AUTH), skip it
        return (creds[1], creds[2])

    return None


def generate_redis_response(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic Redis RESP response for the given probe data.

    Args:
        raw_data: Raw bytes received from the bot connection.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Protocol-compliant Redis RESP response as bytes.
    """
    try:
        text = raw_data.decode('utf-8', errors='replace')
    except Exception:
        return b'-ERR invalid request\r\n'

    # Check for AUTH command and capture credentials
    if re.search(r'AUTH\s+', text, re.IGNORECASE):
        creds = extract_redis_credentials(raw_data)
        if creds:
            logger.info(
                'Captured Redis credentials from %s: user=%s',
                bot_ip,
                creds[0],
            )

    # PING command — return +PONG
    if re.search(r'^\*1\r\n\$4\r\nPING\r\n$', text) or re.search(r'PING\s*$', text.strip()):
        return b'+PONG\r\n'

    # AUTH without credentials — return -NOAUTH
    if re.search(r'AUTH\s+', text, re.IGNORECASE):
        creds = extract_redis_credentials(raw_data)
        if not creds:
            return b'-NOAUTH Authentication required.\r\n'

    # Commands that require authentication
    if re.search(r'(?:KEYS|GET|SET|DEL|FLUSHALL|CONFIG|SHUTDOWN)', text, re.IGNORECASE):
        return b'-NOAUTH Authentication required.\r\n'

    # Default: respond with +PONG for unknown commands (some bots expect this)
    return b'+PONG\r\n'


def generate_redis_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate the initial Redis greeting sent when a client connects.

    Args:
        bot_ip: The bot's IP address (for logging).

    Returns:
        Initial greeting as bytes (+PONG).
    """
    logger.info('Sending Redis greeting to %s', bot_ip)
    return b'+PONG\r\n'
