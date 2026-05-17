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
            # Decode the data
            raw_str = all_data.decode('utf-8', errors='replace')
            # Look for username/password in the raw data
            creds = _parse_ssh_auth_data(raw_str)
            if creds:
                return creds
            # If no structured credentials found, log the raw data
            logger.debug(
                'SSH raw data from %s: %s',
                bot_ip,
                repr(all_data[:200]),
            )
            return f'SSH data: {repr(all_data[:100])}'
    except Exception as e:
        logger.debug('Error capturing SSH credentials from %s: %s', bot_ip, e)
    return None


def _parse_ssh_auth_data(raw_data: str) -> str | None:
    """Parse SSH authentication data to extract credentials.

    Args:
        raw_data: Raw SSH protocol data as string.

    Returns:
        String with extracted credentials, or None.
    """
    # Try to parse SSH binary protocol
    try:
        data_bytes = raw_data.encode('latin-1')
        # Look for SSH_MSG_USERAUTH_REQUEST (byte 50)
        idx = data_bytes.find(b'\x32')  # 0x32 = 50
        if idx >= 0:
            # Skip message type and length
            # SSH binary protocol: length(4), type(1), data...
            # Look for the username string
            pass
    except Exception:
        logger.debug('Failed to parse SSH binary protocol data')

    # Fallback: look for plaintext username/password in the data
    username = None
    password = None

    # Some SSH clients send credentials in plaintext
    username_match = re.search(r'username[=:\s]+(\w+)', raw_data, re.IGNORECASE)
    if username_match:
        username = username_match.group(1)

    password_match = re.search(r'password[=:\s]+(\S+)', raw_data, re.IGNORECASE)
    if password_match:
        password = password_match.group(1)

    if username and password:
        return f'user={username}, pass={password}'
    elif username:
        return f'user={username}'
    elif password:
        return f'pass={password}'

    return None
