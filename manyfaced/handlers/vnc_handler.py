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

# Canonical server version advertised at the greeting AND during negotiation.
# rfbproto requires the server to reply with the highest version it shares
# with the client; we cap at 003.008 (widely supported) and use the same
# string in both places so the very first bytes are deterministic (good for
# replay/corpus tests and operator fingerprinting).
VNC_CANONICAL_VERSION = 'RFB 003.008\n'

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

    # Version negotiation — client sends "RFB xxx.yyy" + CRLF/LF
    if raw_data[:3] == b'RFB':
        return _handle_version_negotiation(raw_data, bot_ip)

    # Security type selection — after version negotiation a real RFB client
    # sends a frame whose first byte is the *count* of security types it
    # offers, followed by that many 1-byte type codes (e.g. b'\x01\x02' =
    # one type, VNC Auth). Match on the count byte, not on \x02/\x03.
    if len(raw_data) >= 1 and raw_data[0:1] != b'\x00':
        count = raw_data[0]
        if len(raw_data) >= 1 + count:
            return _handle_security_selection(raw_data[1 : 1 + count])

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

    # rfbproto: reply with the highest version we share with the client, but
    # never higher than our canonical maximum (003.008). Symmetric + stable.
    return VNC_CANONICAL_VERSION.encode('utf-8')


def _handle_security_selection(client_types: bytes) -> bytes:
    """Handle VNC security type selection.

    Replies with the number of security types followed by the types, per
    rfbproto (server's list of supported types). For VNC Auth (type 2) the
    16-byte challenge is appended afterwards.

    Args:
        client_types: The 1-byte type codes the client offered (count stripped).

    Returns:
        Security type response as bytes.
    """
    # Security types we support:
    # 1 = None (no auth) — rarely used in real scenarios
    # 2 = VNC Auth (password-based, 8-byte DES)
    # 16 = TLS with X509 authentication
    # 17 = TightVNC security type

    # A honeypot emulating VNC presents VNC Authentication (type 2) — the
    # standard, most-commonly-offered security type. Deterministic so the
    # handshake is reproducible and the count-byte fix (#463) is testable.
    chosen_type = 2  # VNC Auth (password-based, 8-byte DES)

    # RFC-compliant: count byte + the chosen type (1 byte). A compliant client
    # reads the first byte as the count; omitting it (old behaviour) is an
    # off-by-one that makes the client desync/error.
    response = struct.pack('B', 1) + struct.pack('B', chosen_type)

    if chosen_type == 2:
        # VNC Auth — send 16-byte challenge for password hash
        challenge = bytes(random.getrandbits(8) for _ in range(16))
        response += challenge

    return response


def _generate_version_string() -> bytes:
    """Generate a VNC version string (fallback / default reply).

    Returns:
        Version string as bytes.
    """
    return VNC_CANONICAL_VERSION.encode('utf-8')


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
    # Deterministic banner (same version the negotiation step will reply with),
    # so the first bytes are stable for replay/corpus tests and fingerprinting.
    return VNC_CANONICAL_VERSION.encode('utf-8')


def generate_vnc_server_name() -> str:
    """Return a random fake VNC server name for display purposes.

    Returns:
        Server name string.
    """
    return random.choice(VNC_SERVER_NAMES)
