"""VNC (Virtual Network Computing) protocol handler for the manyfaced honeypot.

Emulates the full RFB (Remote Framebuffer) authentication handshake so the
honeypot can drive a credential-capable exchange with scanners and bots:

    greeting (server version)        -- sent by the client layer on accept
    -> client version   ("RFB 003.00x\\n")
    -> server security-types list    (count + [VNC Auth])
    -> client security-type selection (single type byte)
    -> server 16-byte auth challenge
    -> client 16-byte DES response   (captured as credentials)
    -> server SecurityResult (OK)    + minimal ServerInit

Because a face ``respond`` callback is invoked once per client frame (see
``manyfaced/client/client.py``), the handshake is implemented as a stateless
frame classifier: each incoming frame is matched by shape/content and the
correct next server message is returned.

Also covers the coverage gaps found in production recon on 5900/5901
(issues #651/#652): HTTP probes on the VNC port return an HTTP-shaped reply
(the client layer flags them as HTTP_ON_NONHTTP_PORT), and the masscan
``MGLNDD_<ip>_<port>`` banner probe is recognised.

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

# RFB security types (rfbproto §7.1.2).
SECURITY_TYPE_INVALID = 0
SECURITY_TYPE_NONE = 1  # No authentication
SECURITY_TYPE_VNC_AUTH = 2  # VNC Authentication (challenge-response, 8-byte DES)
SECURITY_TYPE_TLS = 18  # TLS
SECURITY_TYPE_VENCRYPT = 19  # VeNCrypt
# The security types a real client legitimately selects. Used to tell a
# 1-byte security-type SELECTION frame apart from other short frames.
VALID_SECURITY_TYPES = frozenset({1, 2, 16, 17, 18, 19, 30, 35})

# SecurityResult codes (rfbproto §7.1.3).
SECURITY_RESULT_OK = 0
SECURITY_RESULT_FAILED = 1

# Length (bytes) of both the VNC-Auth challenge and the client's DES response.
VNC_AUTH_CHALLENGE_LEN = 16

# masscan's application-layer banner probe: ``MGLNDD_<ip>_<port>\r\n``.
MASSCAN_PROBE_PREFIX = b'MGLNDD_'

# HTTP request methods — an HTTP probe arriving on the VNC port is a protocol
# mismatch (a scanner sweeping HTTP across all ports), not a genuine VNC probe.
_HTTP_METHODS = (
    b'GET ',
    b'POST ',
    b'HEAD ',
    b'PUT ',
    b'DELETE ',
    b'OPTIONS ',
    b'PATCH ',
    b'CONNECT ',
    b'TRACE ',
)

# Fake VNC server names
VNC_SERVER_NAMES = [
    'RealVNC 6.24.159',
    'TigerVNC 1.13.1',
    'UltraVNC 1.3.1',
    'x11vnc 0.9.16',
]


def extract_vnc_credentials(raw_data: bytes) -> Tuple[str, str] | None:
    """Extract credentials from VNC authentication data in raw data.

    Parses VNC password hash attempts (16-byte DES challenge-response, two
    8-byte blocks) sent by the client after it selects VNC Authentication.

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        Tuple of ('vnc-authenticated', challenge_hash) if auth detected, else None.
    """
    # VNC authentication response is exactly 16 bytes (two 8-byte DES blocks).
    if len(raw_data) == VNC_AUTH_CHALLENGE_LEN:
        return ('vnc-authenticated', raw_data.hex())

    # Some bots send extra trailing bytes; treat a >=16-byte non-RFB frame as an
    # auth response and capture the first 16 bytes.
    if len(raw_data) >= VNC_AUTH_CHALLENGE_LEN and raw_data[:4] != b'RFB ':
        return ('vnc-authenticated', raw_data[:VNC_AUTH_CHALLENGE_LEN].hex())

    return None


def _is_http_probe(raw_data: bytes) -> bool:
    """True if the frame is an HTTP request (protocol mismatch on the VNC port)."""
    return raw_data.startswith(_HTTP_METHODS)


def generate_vnc_response(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic VNC response for the given client frame.

    Implements the RFB handshake as a stateless per-frame classifier (each
    frame maps to the next server message). Also handles HTTP-on-VNC-port and
    masscan probes (issues #651/#652).

    Args:
        raw_data: Raw bytes received from the bot connection.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Protocol-compliant VNC (or HTTP-shaped) response as bytes.
    """
    # ── HTTP probe on the VNC port — protocol mismatch ─────────────────────
    # Return an HTTP-shaped reply. The client layer independently re-sniffs the
    # frame with is_http_request() and stamps it HTTP_ON_NONHTTP_PORT, so this
    # response simply keeps the scanner's HTTP client happy (#652).
    if _is_http_probe(raw_data):
        logger.info('HTTP probe on VNC port from %s (flagged HTTP-on-non-HTTP)', bot_ip)
        return _generate_http_response()

    # ── masscan MGLNDD_<ip>_<port> banner probe ────────────────────────────
    # masscan sends this app-layer probe to elicit a banner; reply with the
    # version banner so it records the (fake) RFB service (#652).
    if raw_data.startswith(MASSCAN_PROBE_PREFIX):
        logger.info('masscan MGLNDD probe on VNC port from %s', bot_ip)
        return _generate_version_string()

    # ── Client version → server security-types list ────────────────────────
    # The greeting (server version) is sent by the client layer on accept; the
    # client answers with its own "RFB 003.00x\n". We reply with the list of
    # security types we support (count byte + type codes), per rfbproto §7.1.2.
    if raw_data[:3] == b'RFB':
        return _handle_version_negotiation(raw_data, bot_ip)

    # ── Client auth response → SecurityResult + ServerInit ─────────────────
    # A 16-byte frame is the DES-encrypted challenge response. Capture it as a
    # credential attempt, then send SecurityResult(OK) followed by a minimal
    # ServerInit so the session looks complete (#651/#652).
    if len(raw_data) == VNC_AUTH_CHALLENGE_LEN or (
        len(raw_data) > VNC_AUTH_CHALLENGE_LEN and raw_data[:4] != b'RFB '
    ):
        creds = extract_vnc_credentials(raw_data)
        if creds:
            logger.info(
                'Captured VNC credentials from %s: user=%s hash=%s',
                bot_ip,
                creds[0],
                creds[1],
            )
        return _generate_security_result_ok() + _generate_server_init()

    # ── Client security-type selection → 16-byte auth challenge ────────────
    # After the security-types list, a real RFB 3.7+ client sends a single byte
    # naming the type it chose. Reply with the 16-byte VNC-Auth challenge.
    if len(raw_data) >= 1 and raw_data[0] in VALID_SECURITY_TYPES:
        return _generate_auth_challenge()

    # Default: (re)send the version string.
    return _generate_version_string()


def _handle_version_negotiation(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Handle VNC version negotiation → reply with the security-types list.

    The greeting already advertised the server version; on receiving the
    client's version string the server's next message (rfbproto §7.1.2) is the
    list of supported security types, NOT another version echo.

    Args:
        raw_data: Raw bytes containing client version string.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Security-types list message as bytes.
    """
    try:
        client_ver = raw_data.decode('ascii', errors='replace').strip()
    except Exception:
        client_ver = 'unknown'

    logger.info('VNC version negotiation from %s: client=%s', bot_ip, client_ver)

    return _generate_security_types()


def _generate_security_types() -> bytes:
    """Build the server's security-types list message.

    Format (rfbproto §7.1.2): 1-byte count, then that many 1-byte type codes.
    We offer exactly one type — VNC Authentication (2) — the standard,
    most-commonly-offered type, so the handshake proceeds to the challenge.

    Returns:
        ``\\x01\\x02`` (one type: VNC Auth) as bytes.
    """
    types = bytes([SECURITY_TYPE_VNC_AUTH])
    return struct.pack('B', len(types)) + types


def _generate_auth_challenge() -> bytes:
    """Build the 16-byte VNC-Auth challenge the client must DES-encrypt.

    Returns:
        16 random bytes.
    """
    return bytes(random.getrandbits(8) for _ in range(VNC_AUTH_CHALLENGE_LEN))


def _generate_security_result_ok() -> bytes:
    """Build a SecurityResult(OK) message (4-byte big-endian 0)."""
    return struct.pack('>I', SECURITY_RESULT_OK)


def _generate_server_init() -> bytes:
    """Build a minimal, valid ServerInit message (rfbproto §7.3.2).

    Layout: framebuffer width (u16), height (u16), 16-byte PIXEL_FORMAT,
    name-length (u32), name (name-length bytes). Makes the post-auth session
    look complete (#652).

    Returns:
        A ServerInit frame as bytes.
    """
    width = 1024
    height = 768
    # PIXEL_FORMAT: bpp=32, depth=24, big-endian=0, true-colour=1,
    # red/green/blue-max=255, red/green/blue-shift=16/8/0, + 3 padding bytes.
    pixel_format = struct.pack(
        '>BBBBHHHBBBxxx',
        32,  # bits-per-pixel
        24,  # depth
        0,  # big-endian-flag
        1,  # true-colour-flag
        255,  # red-max
        255,  # green-max
        255,  # blue-max
        16,  # red-shift
        8,  # green-shift
        0,  # blue-shift
    )
    name = generate_vnc_server_name().encode('ascii', errors='replace')
    return struct.pack('>HH', width, height) + pixel_format + struct.pack('>I', len(name)) + name


def _generate_version_string() -> bytes:
    """Generate a VNC version string (fallback / default reply).

    Returns:
        Version string as bytes.
    """
    return VNC_CANONICAL_VERSION.encode('utf-8')


def _generate_http_response() -> bytes:
    """Generate a minimal HTTP-shaped reply for an HTTP probe on the VNC port.

    The client layer flags the frame as HTTP_ON_NONHTTP_PORT; this reply just
    satisfies the scanner's HTTP client (#652).

    Returns:
        A small HTTP/1.1 response as bytes.
    """
    body = b'<!DOCTYPE html><html><head><title>VNC</title></head><body></body></html>'
    return (
        b'HTTP/1.1 200 OK\r\n'
        b'Server: Apache/2.4.57 (Ubuntu)\r\n'
        b'Content-Type: text/html; charset=UTF-8\r\n'
        b'Content-Length: ' + str(len(body)).encode('ascii') + b'\r\n'
        b'Connection: close\r\n\r\n' + body
    )


def _generate_auth_failure() -> bytes:
    """Generate a VNC SecurityResult(failed) response with a reason string.

    RFB 3.8 SecurityResult on failure is a 4-byte status (1) followed by a
    4-byte reason-length and the reason text. Retained for callers that want an
    explicit failure path.

    Returns:
        SecurityResult(failed) + reason as bytes.
    """
    reason = random.choice(['Authentication failure', 'Too many security failures'])
    msg = reason.encode('utf-8')
    return struct.pack('>II', SECURITY_RESULT_FAILED, len(msg)) + msg


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
