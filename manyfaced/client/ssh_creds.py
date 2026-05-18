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
                # Check if we have enough data to parse
                if len(all_data) > 500:
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

    Looks for SSH_MSG_USERAUTH_REQUEST (type 50/0x32) messages which contain
    username and service information.

    Args:
        data: Raw SSH protocol data as bytes.

    Returns:
        String with extracted credentials, or None if not found.
    """
    try:
        # Look for SSH_MSG_USERAUTH_REQUEST (byte 0x32 = 50)
        # Format: length(4 bytes) | type(1 byte) | string(username) | ...
        idx = data.find(b'\x32')  # 0x32 = 50

        if idx >= 0 and idx + 5 < len(data):
            # Extract username from the message
            # After type byte, next is a string (4-byte length + content)
            try:
                # Skip to after the message type
                pos = idx + 1

                # Read username string (4-byte length prefix)
                if pos + 4 <= len(data):
                    username_len = int.from_bytes(data[pos : pos + 4], 'big')
                    pos += 4

                    if pos + username_len <= len(data):
                        username = data[pos : pos + username_len].decode('utf-8', errors='replace')

                        # Look for password in subsequent data
                        password = None
                        pos += username_len

                        # Skip service name string (usually "ssh-connection")
                        if pos + 4 <= len(data):
                            service_len = int.from_bytes(data[pos : pos + 4], 'big')
                            pos += 4 + service_len

                            # Skip auth method string (usually "password")
                            if pos + 4 <= len(data):
                                auth_method_len = int.from_bytes(data[pos : pos + 4], 'big')
                                pos += 4 + auth_method_len

                                # Now we should be at the password data
                                # For password auth, there's a boolean (1 byte) then string
                                if pos < len(data):
                                    has_password = data[pos]
                                    pos += 1

                                    if has_password == 1 and pos + 4 <= len(data):
                                        pwd_len = int.from_bytes(data[pos : pos + 4], 'big')
                                        pos += 4

                                        if pos + pwd_len <= len(data):
                                            password = data[pos : pos + pwd_len].decode(
                                                'utf-8', errors='replace'
                                            )

                        if username:
                            if password:
                                return f'user={username}, pass={password}'
                            return f'user={username}'
            except (IndexError, ValueError) as e:
                logger.debug('Failed to parse SSH binary protocol: %s', e)
    except Exception as e:
        logger.debug('SSH binary protocol parsing error: %s', e)

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
