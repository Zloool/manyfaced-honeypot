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

from manyfaced.common.status import EMPTY_CONNECTION

logger = logging.getLogger(__name__)

# X.224 TPDU codes (high nibble; low nibble carries CDT/credit for CR/CC).
_X224_CR = 0xE0  # Connection-Request
_X224_CC = 0xD0  # Connection-Confirm

# RDP negotiation structure types (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1).
_RDP_NEG_REQ = 0x01
_RDP_NEG_RSP = 0x02

# requestedProtocols flags (MS-RDPBCGR 2.2.1.1.1).
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008


def rdp_probe_signal(raw_data: bytes) -> int | None:
    """Classify an RDP probe's raw payload for the capture pipeline (issue #630).

    69% of production RDP sessions carried an empty ``request_raw`` but were
    recorded under the normal RDP sentinel, hiding the fact that no client
    frame ever arrived. When the raw payload is empty or whitespace-only, the
    session must be stamped with the ``EMPTY_CONNECTION`` marker that the
    caller / classification pipeline already understands (see
    ``manyfaced.common.status`` and ``manyfaced/db/storage.py``).

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        ``EMPTY_CONNECTION`` if the payload is empty/whitespace-only, else
        ``None`` (no reclassification needed).
    """
    if not raw_data or not raw_data.strip():
        return EMPTY_CONNECTION
    return None


def _parse_x224_connection_request(raw_data: bytes) -> int | None:
    """Parse a TPKT-framed X.224 Connection-Request; return requestedProtocols.

    Returns:
        The requestedProtocols flags from a trailing RDP_NEG_REQ (0 when the
        CR carries no negotiation request), or ``None`` if the frame is not a
        valid X.224 Connection-Request.
    """
    # TPKT header: version 3, reserved 0, 2-byte length; then X.224 TPDU.
    if len(raw_data) < 7 or raw_data[0] != 0x03:
        return None
    x224 = raw_data[4:]
    if len(x224) < 2:
        return None
    li, code = x224[0], x224[1]
    if code & 0xF0 != _X224_CR:
        return None
    # LI counts the octets following it; a bare CR header has LI >= 6.
    if li < 6 or len(x224) < 1 + li:
        return None
    # Variable part / user data after the fixed 7-octet CR header may contain
    # an RDP Negotiation Request: type(1) flags(1) length(2, LE, =8) protos(4, LE).
    user_data = x224[7 : 1 + li]
    idx = user_data.find(bytes([_RDP_NEG_REQ]))
    while idx != -1:
        chunk = user_data[idx : idx + 8]
        if len(chunk) == 8 and struct.unpack('<H', chunk[2:4])[0] == 8:
            return struct.unpack('<I', chunk[4:8])[0]
        idx = user_data.find(bytes([_RDP_NEG_REQ]), idx + 1)
    return 0


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

    # Detect a real X.224 Connection-Request (TPKT + CR TPDU, code 0xE0).
    # The previous check (`raw_data[4:5] == b'\x0e'`) matched the LI octet of
    # one specific client and missed every other CR layout, so most real
    # clients got only the bare CC without an RDP Negotiation Response and
    # reset the connection (issue #630).
    requested = _parse_x224_connection_request(raw_data)
    if requested is not None:
        return _generate_connection_confirm(requested)

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


def _generate_connection_confirm(requested_protocols: int = 0) -> bytes:
    """Generate an X.224 Connection-Confirm carrying an RDP Negotiation Response.

    Per MS-RDPBCGR 2.2.1.2, the server answers the client's X.224
    Connection-Request with a Connection-Confirm whose user-data is an
    RDP Negotiation Response (RDP_NEG_RSP, type 0x02). The previous code
    appended a bogus "MCS Connect-Initial" blob after the CC in the same
    TPKT — not a valid CC payload — so real clients (mstsc/FreeRDP) reset
    instead of proceeding (issue #630).

    Args:
        requested_protocols: requestedProtocols flags from the client's
            RDP_NEG_REQ (0 when the CR carried no negotiation request).

    Returns:
        TPKT + X.224 CC + RDP_NEG_RSP as bytes.
    """
    # RDP Negotiation Response (8 octets, little-endian fields):
    #   type(1)=0x02  flags(1)=0x00  length(2)=8  selectedProtocol(4)
    # We speak classic RDP security only (no TLS termination in the honeypot),
    # so select PROTOCOL_RDP — always a legal choice because standard RDP
    # security is implicitly supported by every client, regardless of the
    # requestedProtocols flags the client advertised.
    logger.debug('RDP CR requestedProtocols=%#010x → selecting RDP', requested_protocols)
    neg_rsp = struct.pack('<BBHI', _RDP_NEG_RSP, 0x00, 8, PROTOCOL_RDP)

    # X.224 Connection-Confirm (CC_TPDU). LI counts every octet after itself,
    # including the negotiation-response user data: 6 header octets + 8.
    x224 = (
        bytes([6 + len(neg_rsp)])  # LI = header (6) + user data (8) = 14
        + b'\xd0'  # CC_TPDU code (0xD0)
        + b'\x00\x00'  # Destination reference
        + b'\x00\x01'  # Source reference (this end)
        + b'\x00'  # class options
        + neg_rsp  # RDP Negotiation Response (MS-RDPBCGR 2.2.1.2.1)
    )

    # TPKT length excludes the 4-byte TPKT header → len(x224).
    payload = x224
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
