"""VNC (Virtual Network Computing) protocol handler for the manyfaced honeypot.

Generates realistic VNC version strings and security type negotiation,
captures credentials from password authentication challenges.

Protocol reference: https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst
"""

from __future__ import annotations

import logging
import random
import struct
from typing import Tuple

logger = logging.getLogger(__name__)

# Fake VNC server versions
VNC_VERSIONS = [
    'RFB 003.008\n',  # RealVNC-style
    'RFB 003.007\n',  # Older RealVNC
    'RFB 003.003\n',  # UltraVNC / tightvnc style
]

# Fake VNC server names
VNC_SERVER_NAMES = [
    'RealVNC 6.24.159',
    'TigerVNC 1.13.1',
    'UltraVNC 1.3.1',
    'x11vnc 0.9.16',
]


def extract_vnc_credentials(raw_data: bytes) -> Tuple[str, str] | None:
    """Extract credentials from VNC authentication data in raw data.

    Parses VNC password hash attempts (8-byte DES encryption of the password).

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        Tuple of ('vnc-authenticated', challenge_hash) if auth detected, else None.
    """
    # VNC authentication uses an 8-byte challenge-response
    # The client sends exactly 16 bytes (two 8-byte DES blocks) after security type 1
    if len(raw_data) == 16:
        return ('vnc-authenticated', raw_data.hex())

    # Check for longer auth attempts (some bots send more data)
    if len(raw_data) >= 16 and b'\x00' not in raw_data[:4]:
        return ('vnc-authenticated', raw_data[:16].hex())

    return None


def generate_vnc_response(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic VNC response for the given probe data.

    Handles version negotiation and security type selection.

    Args:
        raw_data: Raw bytes received from the bot connection.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Protocol-compliant VNC response as bytes.
    """
    # Check if this is a password authentication attempt (16-byte challenge-response)
    if len(raw_data) == 16:
        creds = extract_vnc_credentials(raw_data)
        if creds:
            logger.info(
                'Captured VNC credentials from %s: user=%s',
                bot_ip,
                creds[0],
            )
        # Return auth failure (most honeypot probes fail VNC auth)
        return _generate_auth_failure()

    # Check for longer authentication data
    if len(raw_data) >= 16 and raw_data[:4] != b'RFB ':
        creds = extract_vnc_credentials(raw_data)
        if creds:
            logger.info(
                'Captured VNC credentials from %s: user=%s',
                bot_ip,
                creds[0],
            )

    # Version negotiation — client sends "RFB xxx.yyy\n" or "RFB xxx.yyy\r\n"
    if raw_data[:3] == b'RFB':
        return _handle_version_negotiation(raw_data, bot_ip)

    # Security type selection — client sends 4-byte count + list of security types
    if len(raw_data) >= 4 and raw_data[0:1] in (b'\x02', b'\x03'):
        return _handle_security_selection()

    # Default: send version string
    return _generate_version_string()


def _handle_version_negotiation(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Handle VNC version negotiation.

    Responds with the server's preferred version (highest supported).

    Args:
        raw_data: Raw bytes containing client version string.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Server version response as bytes.
    """
    # Parse client version
    try:
        client_ver = raw_data.decode('ascii', errors='replace').strip()
    except Exception:
        client_ver = 'unknown'

    logger.info(
        'VNC version negotiation from %s: client=%s',
        bot_ip,
        client_ver,
    )

    # Always respond with RFB 003.008 (widely supported)
    return b'RFB 003.008\n'


def _handle_security_selection() -> bytes:
    """Handle VNC security type selection.

    Returns the server's chosen security type and challenge if applicable.

    Returns:
        Security type response as bytes.
    """
    # Security types we support:
    # 1 = None (no auth) — rarely used in real scenarios
    # 2 = VNC Auth (password-based, 8-byte DES)
    # 16 = TLS with X509 authentication
    # 17 = TightVNC security type

    # Choose a random security type to make it look realistic
    security_types = [2, 16, 17]
    chosen_type = random.choice(security_types)

    response = struct.pack('B', chosen_type)  # Server's choice (1 byte)

    if chosen_type == 2:
        # VNC Auth — send 16-byte challenge for password hash
        challenge = bytes(random.getrandbits(8) for _ in range(16))
        response += challenge

    return response


def _generate_version_string() -> bytes:
    """Generate a VNC version string.

    Returns:
        Version string as bytes.
    """
    return random.choice(VNC_VERSIONS).encode('utf-8')


def _generate_auth_failure() -> bytes:
    """Generate a VNC authentication failure response.

    Returns:
        Auth failure message as bytes (reason code + text).
    """
    # Reason codes: 0=none, 1=unauthorized, 2=no-shared mode
    reason = random.choice([1, 1, 1, 2])  # Mostly unauthorized
    messages = {
        1: 'Unauthorized',
        2: 'Server is not shared',
    }
    msg = messages[reason]
    return struct.pack('IB', reason, len(msg)) + msg.encode('utf-8')


def generate_vnc_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate the initial VNC greeting sent when a client connects.

    Args:
        bot_ip: The bot's IP address (for logging).

    Returns:
        Initial version string as bytes.
    """
    logger.info('Sending VNC greeting to %s', bot_ip)
    return _generate_version_string()


def generate_vnc_server_name() -> str:
    """Return a random fake VNC server name for display purposes.

    Returns:
        Server name string.
    """
    return random.choice(VNC_SERVER_NAMES)
