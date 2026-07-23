"""SSH credential capture for honeypot client.

Provides functions to intercept and parse SSH authentication data from bot connections.
Extracted from client.py to reduce cyclomatic complexity of the main module.
"""

import re
from socket import error as socket_error, timeout as socket_timeout
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from socket import socket as SocketType

from manyfaced.common.logging_setup import get_logger

logger = get_logger(__name__)


def _capture_ssh_credentials(connection_socket: 'SocketType', bot_ip: str) -> str | None:
    """Capture SSH credentials by keeping the connection open and parsing auth messages.

    Args:
        connection_socket: The open socket connection to the bot.
        bot_ip: IP address of the bot.

    Returns:
        String with captured credentials, or None if no credentials captured.
    """
    try:
        # Set a longer timeout for SSH credential capture
        connection_socket.settimeout(30)
        all_data = b''
        while True:
            try:
                data = connection_socket.recv(4096)
                if not data:
                    break
                all_data += data
                # Keep accumulating until the client stops sending, but bound the
                # buffer so a misbehaving client can't make us buffer forever.
                # 4 KiB comfortably holds a full USERAUTH_REQUEST with keys/certs.
                if len(all_data) > 4096:
                    break
            except socket_timeout:
                break
            except socket_error:
                break

        if all_data:
            # Decode the data for text-based parsing
            raw_str = all_data.decode('utf-8', errors='replace')

            # Try structured SSH protocol parsing first
            creds = _parse_ssh_binary_protocol(all_data)
            if creds:
                return creds

            # Fallback to plaintext extraction
            creds = _parse_ssh_auth_data(raw_str)
            if creds:
                return creds

            # If no credentials found, log raw data for debugging
            logger.debug(
                'SSH raw data from %s (length=%d): %s',
                bot_ip,
                len(all_data),
                repr(all_data[:200]),
            )
            return None
    except Exception as e:
        logger.debug('Error capturing SSH credentials from %s: %s', bot_ip, e)
    return None


def _parse_ssh_binary_protocol(data: bytes) -> str | None:
    """Parse SSH binary protocol to extract authentication credentials.

    The client sends SSH binary packets: ``[4-byte length][1-byte pad]``
    followed by the payload. The first payload byte is the message code; a
    ``USERAUTH_REQUEST`` carries code ``0x32`` (50) and the structure
    ``username(string) service(string) method(string) ...``. We walk the
    length-prefixed frames instead of doing a brittle ``find(b'\\x32')`` so a
    ``0x32`` byte inside padding/length fields does not mislead the parser
    (issue #628). Real clients send ``SSH-2.0-*`` banners, and we must also
    handle ``SSH-1.99-*`` compatibility banners.
    """
    try:
        off = 0
        n = len(data)
        while off + 4 <= n:
            # Respect the SSH-2.0 banner line (ends in \\n); binary frames start
            # after it. If we are still in the banner region, skip to the first
            # binary-looking offset.
            pkt_len = int.from_bytes(data[off : off + 4], 'big')
            if pkt_len <= 0 or pkt_len > 4096:
                # Not a frame boundary here (likely banner text or mid-frame);
                # advance one byte and retry.
                off += 1
                continue
            end = off + 4 + pkt_len
            if end > n:
                break
            payload = data[off + 5 : end]  # skip 4-byte length + 1-byte pad
            if payload and payload[0] == 0x32:  # USERAUTH_REQUEST
                return _parse_userauth_request(payload[1:])
            off = end
    except Exception as e:
        logger.debug('SSH binary protocol framing error: %s', e)
    return None


def _parse_userauth_request(payload: bytes) -> str | None:
    """Extract username (+password when ``password`` auth is used) from a
    USERAUTH_REQUEST payload (message code already stripped)."""
    try:
        pos = 0

        def _read_string(buf: bytes, p: int):
            if p + 4 > len(buf):
                return None, p
            slen = int.from_bytes(buf[p : p + 4], 'big')
            p += 4
            if p + slen > len(buf):
                return None, p
            return buf[p : p + slen], p + slen

        username, pos = _read_string(payload, pos)
        if username is None:
            return None
        # service name string (usually "ssh-connection")
        _, pos = _read_string(payload, pos)
        # auth method string (e.g. "password", "none", "publickey")
        method, pos = _read_string(payload, pos)
        if method is None:
            return f'user={username.decode("utf-8", errors="replace")}'
        method_s = method.decode('latin-1', errors='replace')
        if method_s == 'password':
            # boolean (1 byte) then password string
            if pos < len(payload):
                has_password = payload[pos]
                pos += 1
                if has_password == 1:
                    password, _ = _read_string(payload, pos)
                    if password is not None:
                        return (
                            f'user={username.decode("utf-8", errors="replace")}, '
                            f'pass={password.decode("utf-8", errors="replace")}'
                        )
        return f'user={username.decode("utf-8", errors="replace")}'
    except Exception as e:
        logger.debug('Failed to parse USERAUTH_REQUEST: %s', e)
    return None


def _parse_ssh_auth_data(raw_data: str) -> str | None:
    """Parse SSH authentication data to extract credentials.

    Looks for plaintext username/password in the data (common with some scanners).

    Args:
        raw_data: Raw SSH protocol data as string.

    Returns:
        String with extracted credentials, or None.
    """
    username = None
    password = None

    # Common patterns for SSH credential disclosure
    patterns = [
        r'username[=:\s]+(\w+)',
        r'user[=:\s]+(\w+)',
        r'login[=:\s]+(\w+)',
        r'password[=:\s]+(\S+)',
        r'pass[=:\s]+(\S+)',
    ]

    for pattern in patterns[:3]:  # Check username patterns first
        match = re.search(pattern, raw_data, re.IGNORECASE)
        if match:
            username = match.group(1)
            break

    for pattern in patterns[3:]:  # Check password patterns
        match = re.search(pattern, raw_data, re.IGNORECASE)
        if match:
            password = match.group(1)
            break

    if username and password:
        return f'user={username}, pass={password}'
    elif username:
        return f'user={username}'
    elif password:
        return f'pass={password}'

    return None
