"""RDP (Remote Desktop Protocol) handler for the manyfaced honeypot.

Generates realistic RDP TPKT/X.224 connection confirm sequences and captures
credentials from NLA (Network Level Authentication) negotiation.

Protocol reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
"""

from __future__ import annotations

import logging
import random
import re
import struct
from typing import Tuple

logger = logging.getLogger(__name__)


def extract_rdp_credentials(raw_data: bytes) -> Tuple[str, str] | None:
    """Extract credentials from RDP authentication data in raw data.

    Parses NLA (TSRequest) messages for username and password fields.

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        Tuple of (username, password) if auth detected, else None.
    """
    try:
        text = raw_data.decode('utf-8', errors='replace')
    except Exception:
        return None

    # NLA/TSRequest often contains username in base64-encoded ASN.1
    user_match = re.search(r'(?i)username\s*[:=]\s*"([^"]+)"', text)
    if not user_match:
        user_match = re.search(r'(?i)<userName>([^<]+)</userName>', text)

    pass_match = re.search(r'(?i)password\s*[:=]\s*"([^"]+)"', text)
    if not pass_match:
        pass_match = re.search(r'(?i)<password>([^<]+)</password>', text)

    if user_match and pass_match:
        return (user_match.group(1), pass_match.group(1))
    elif user_match:
        return (user_match.group(1), '')

    # Check for base64-encoded NLA data that might contain credentials
    b64_match = re.search(r'(?i)(?:credentials|auth)[=:]\s*([A-Za-z0-9+/=]{20,})', text)
    if b64_match:
        return ('nla-authenticated', b64_match.group(1)[:50])

    return None


def generate_rdp_response(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic RDP response for the given probe data.

    Handles TPKT/X.224 connection confirm and NLA negotiation.

    Args:
        raw_data: Raw bytes received from the bot connection.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Protocol-compliant RDP response as bytes.
    """
    # Check for credential extraction on any data after initial handshake
    if len(raw_data) > 50:
        creds = extract_rdp_credentials(raw_data)
        if creds and creds[0]:
            logger.info(
                'Captured RDP credentials from %s: user=%s',
                bot_ip,
                creds[0],
            )

    # Detect NLA/TSRequest (contains authentication data)
    text_lower = raw_data.lower() if isinstance(raw_data, bytes) else b''
    if len(raw_data) > 100 and (b'nla' in text_lower or b'tsrequest' in text_lower):
        return _generate_nla_challenge()

    # Detect RDP client hello (Client Core Request)
    if len(raw_data) > 20 and raw_data[4:5] == b'\x0e':
        return _generate_connection_confirm()

    # Default: send TPKT/X.224 connection confirm
    return _generate_initial_response()


def _generate_initial_response() -> bytes:
    """Generate the initial RDP TPKT/X.224 connection confirm response.

    This is sent immediately after receiving an RDP client hello.

    Returns:
        TPKT header + X.224 Connection-Confirm as bytes.
    """
    # X.224 Connection-Confirm (CC_TPDU), per ITU-T X.224 / ISO 8073.
    # Header octets (LI counts the octets that follow it):
    #   octet 0 : Length Indicator (LI) = 6 (code + dst-ref + src-ref + options)
    #   octet 1 : TPDU code 0xD0 (high nibble 0xD = CC), low nibble = credit (0)
    #   octet 2-3 : Destination reference
    #   octet 4-5 : Source reference (this end)
    #   octet 6 : variable-part / class options (0x00 = none)
    # The previous code inverted the header (LI slot held 0xE0 and 0xD0 sat in
    # the source-reference slot), so a real client misread LI and waited for
    # phantom bytes. See issue #594.
    x224 = (
        b'\x06'  # LI = 6 trailing octets
        b'\xd0'  # CC_TPDU code (0xD0)
        b'\x00\x00'  # Destination reference
        b'\x00\x00'  # Source reference (this end)
        b'\x00'  # class options
    )

    # TPKT header: version=3, reserved=0, length = total payload bytes.
    # Real RDP clients (mstsc/FreeRDP/rdesktop) parse this length to know how
    # many bytes to read; a mismatch causes them to wait for phantom bytes and
    # desync/abort the handshake. Compute it from the actual bytes sent.
    payload = x224
    tpkt = b'\x03\x00' + struct.pack('!H', len(payload))

    return tpkt + payload


def _generate_connection_confirm() -> bytes:
    """Generate RDP Connection-Confirm with MCS parameters.

    Returns:
        Full connection confirm sequence as bytes.
    """
    # X.224 Connection-Confirm (CC_TPDU). Same 7-octet layout as
    # _generate_initial_response; this variant simply uses a non-zero source
    # reference (0x0001). The previous code inverted the header (LI slot held
    # 0xE0 and 0xD0 sat in the source-reference slot) — see issue #594.
    x224 = (
        b'\x06'  # LI = 6 trailing octets
        b'\xd0'  # CC_TPDU code (0xD0)
        b'\x00\x00'  # Destination reference
        b'\x00\x01'  # Source reference (this end)
        b'\x00'  # class options
    )

    # MCS Connect-Initial (simplified)
    mcs = bytes(
        [
            0x7F,
            0xE6,
            0x80,
            0xA4,
            0x04,
            0x01,
            0x01,
            0xFF,
            0x02,
            0x00,
            0x01,
            0x01,
            0xFF,
            0x02,
            0x01,
            0x03,
            0x30,
            0x00,
        ]
    )

    # TPKT length must equal len(tpkt + x224 + mcs) of the on-the-wire bytes
    # (the TPKT length field itself excludes the 4-byte TPKT header, so it is
    # the length of x224 + mcs).
    payload = x224 + mcs
    tpkt = b'\x03\x00' + struct.pack('!H', len(payload))

    return tpkt + payload


def _generate_nla_challenge() -> bytes:
    """Generate an RDP NLA (Network Level Authentication) challenge.

    Returns a TSRequest with NegotiateSecurityLayer challenge, wrapped in a
    proper TPKT + X.224 envelope so a real client can parse it.

    Returns:
        NLA challenge as bytes.
    """
    # Generate a random challenge nonce
    nonce = bytes(random.getrandbits(8) for _ in range(16))

    # Build a simplified TSRequest with NLA challenge using ASN.1 DER encoding
    ts_request = (
        bytes([0x30, 4 + len(nonce)])  # SEQUENCE tag + length
        + bytes([0xA0, 2 + len(nonce)])  # Credential Type context [0]
        + bytes([0x30, len(nonce)])
        + nonce  # OCTET STRING with challenge
    )

    # Wrap the TSRequest in a minimal X.224 Data TPDU (DT) so a real client can
    # reach it. X.224 DT layout: octet 0 = Length Indicator (count of bytes after
    # this octet, i.e. the DT header + user data, = len(ts_request) + 1 for the
    # code octet), octet 1 = TPDU code 0xF0 (DT), then user data. The previous
    # code placed 0xF0 in the LI slot and the length where the code belongs,
    # inverting the header (issue #594).
    x224 = bytes([1 + len(ts_request)]) + b'\xf0' + ts_request  # Data TPDU (DT)

    # TPKT length excludes the 4-byte TPKT header → len(x224).
    payload = x224
    tpkt = b'\x03\x00' + struct.pack('!H', len(payload))

    return tpkt + payload


def generate_rdp_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate the initial RDP greeting sent when a client connects.

    Args:
        bot_ip: The bot's IP address (for logging).

    Returns:
        Initial TPKT/X.224 response as bytes.
    """
    logger.info('Sending RDP greeting to %s', bot_ip)
    return _generate_initial_response()
