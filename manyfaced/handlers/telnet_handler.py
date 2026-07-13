"""Telnet protocol handler for the manyfaced honeypot.

Generates realistic Telnet responses including IAC (Interpret As Command)
negotiation, login prompts, and credential capture from user input.

Protocol reference: https://datatracker.ietf.org/doc/html/rfc854
"""

from __future__ import annotations

import logging
import random
import re
from typing import Tuple

logger = logging.getLogger(__name__)

# Telnet IAC (Interpret As Command) byte
IAC = b'\xff'

# Telnet commands
WILL = b'\xfb'
WONT = b'\xfc'
DO = b'\xfd'
DONT = b'\xfe'
SB = b'\xfa'  # Subnegotiation
SE = b'\xf0'  # Subnegotiation end

# Telnet options
OPT_BINARY = b'\x01'  # Binary Transmission
OPT_ECHO = b'\x03'  # Echo
OPT_SUPPRESS_GO_AHEAD = b'\x05'  # Suppress Go Ahead
OPT_TTYPE = b'\x18'  # Terminal Type
OPT_NAWS = b'\x1f'  # Negotiate About Window Size

# Fake telnet server banners
TELNET_BANNERS = [
    'Debian GNU/Linux 12\n',
    'Ubuntu 22.04 LTS\n',
    'CentOS Linux release 8.5\n',
    'Red Hat Enterprise Linux Server release 7.9\n',
]


def extract_telnet_credentials(raw_data: bytes) -> Tuple[str, str] | None:
    """Extract credentials from Telnet login interaction in raw data.

    Parses the telnet login flow: "login: <user>" followed by "Password: <pass>".

    Args:
        raw_data: Raw bytes received from the bot connection.

    Returns:
        Tuple of (username, password) if both are detected, else None.
    """
    try:
        # Strip IAC negotiation sequences first so the remaining text is pure
        # username/password content. A single frame is often a mix of IAC bytes
        # and the trailing username (e.g. ``IAC WILL ECHO ... root``); without
        # stripping, the username is captured as ``\xff\x01...root`` (issue #598).
        cleaned = _strip_iac(raw_data)
        text = cleaned.decode('utf-8', errors='replace')
    except Exception:
        return None

    # Remove IAC sequences for easier parsing
    clean_text = re.sub(r'\xff[\xfc\xfd\xfe\xf0\xfa]', '', text)
    clean_text = re.sub(r'\xff[\x01-\x3f]', '', clean_text)

    lines = clean_text.split('\n')

    username = None
    password = None

    # First pass: look for explicit login/password prompts with values
    for i, line in enumerate(lines):
        stripped = line.strip().rstrip('\r')
        lower_line = stripped.lower()

        if 'login:' in lower_line and not re.match(r'^[Pp]assword', stripped):
            # Extract username from "login: <username>" or just after login prompt
            idx = lower_line.index('login:') + len('login:')
            remaining = stripped[idx:].strip()
            if remaining:
                username = remaining

        elif 'password:' in lower_line:
            # Extract password from "Password: <pass>" or just after password prompt
            idx = lower_line.index('password:') + len('password:')
            remaining = stripped[idx:].strip()
            if remaining:
                password = remaining

    # Second pass: look for bare lines (username/password without prompts)
    if not username or not password:
        for line in lines:
            stripped = line.strip().rstrip('\r')
            if stripped and ':' not in stripped and len(stripped) > 0:
                if not username:
                    username = stripped
                elif not password:
                    password = stripped

    # Third pass: look for "user/pass" patterns in single lines
    if not username or not password:
        for line in lines:
            stripped = line.strip().rstrip('\r')
            user_match = re.search(r'(?i)(?:user|login)\s*[:=]\s*(\S+)', stripped)
            pass_match = re.search(r'(?i)(?:pass|password)\s*[:=]\s*(\S+)', stripped)
            if user_match and not username:
                username = user_match.group(1)
            if pass_match and not password:
                password = pass_match.group(1)

    if username or password:
        return (username or '', password or '')

    return None


def _strip_iac(raw_data: bytes) -> bytes:
    """Return ``raw_data`` with all IAC (Interpret As Command) sequences removed.

    An IAC sequence is ``IAC`` (0xff) followed by a command byte and, for most
    commands, an option byte. Subnegotiation (``IAC SB ... IAC SE``) is stripped
    across its whole span.

    Args:
        raw_data: Raw Telnet bytes that may contain IAC negotiation.

    Returns:
        The remaining payload bytes (the human-readable username/login text).
    """
    out = bytearray()
    i = 0
    n = len(raw_data)
    while i < n:
        if raw_data[i : i + 1] == IAC:
            if i + 1 >= n:
                break
            cmd = raw_data[i + 1]
            if cmd == SB:  # 0xfa: subnegotiation, runs until IAC SE
                # Skip IAC SB <opt>, then everything up to IAC SE (0xff 0xf0)
                i += 2
                while i + 1 < n and not (raw_data[i] == IAC[0] and raw_data[i + 1] == SE):
                    i += 1
                i += 2  # consume IAC SE
                continue
            # Two-byte commands (WILL/WONT/DO/DONT) and option variants: skip
            # IAC + command + option. Single-byte commands (e.g. 0xf0 SE) skip
            # only IAC + command.
            if cmd in (SE,):
                i += 2
            else:
                i += 3
            continue
        out.append(raw_data[i])
        i += 1
    return bytes(out)


def generate_telnet_response(raw_data: bytes, bot_ip: str = '127.0.0.1') -> bytes:
    """Generate a realistic Telnet response for the given probe data.

    Handles IAC negotiation AND the embedded username/login so a real telnet
    bot (Mirai/etc.) gets a believable auth exchange instead of a silent drop.

    A single frame is often a mix of IAC negotiation bytes and the trailing
    username the bot just typed (e.g. ``IAC WILL ECHO ... root\
\\n``). The
    previous implementation short-circuited any frame containing ``0xff`` to
    negotiation-only reflexive ACKs, discarding the username and never emitting
    a ``Password:`` prompt (issue #598). We now always honour the negotiation
    first, then parse the residual text to decide which prompt to send.

    Args:
        raw_data: Raw bytes received from the bot connection.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Protocol-compliant Telnet response as bytes.
    """
    raw_bytes = raw_data.encode('latin-1') if isinstance(raw_data, str) else raw_data

    response = b''
    had_iac = b'\xff' in raw_bytes

    # 1) Always honour any IAC negotiation present (reflexive ACKs). This is the
    #    server's first duty on every frame that carries 0xff.
    if had_iac:
        response += _handle_telnet_negotiation(raw_bytes, bot_ip)

    # 2) Parse the residual (non-IAC) text for embedded credentials.
    creds = extract_telnet_credentials(raw_bytes)
    if creds and creds[0] and creds[1]:
        logger.info(
            'Captured Telnet credentials from %s: user=%s',
            bot_ip,
            creds[0],
        )
        # Full username+password observed in one frame -> believable auth
        # failure, then re-prompt a fresh login so the bot keeps trying.
        response += generate_auth_failure() + _generate_login_prompt()
        return response

    if creds and creds[0]:
        logger.info(
            'Partial Telnet credentials from %s: user=%s',
            bot_ip,
            creds[0],
        )
        # Username seen but no password yet -> ask for the password. This is the
        # exact Mirai frame path (IAC ... then the username) that used to be
        # dropped by the old short-circuit.
        response += generate_password_prompt()
        return response

    # 3) No recognisable credential text in this frame.
    residual = _strip_iac(raw_bytes).strip()
    if residual:
        # Some free-text we could not classify -> give the login prompt so the
        # bot is not left hanging.
        response += _generate_login_prompt()
    elif not had_iac:
        # No IAC and no text (e.g. the initial empty connection frame, or a
        # bare CR/LF keepalive): this is the server-first greeting request, so
        # emit the login prompt/banner. We only suppress the banner for *pure*
        # negotiation frames (had_iac and no residual) to avoid echoing a
        # duplicate banner on every IAC exchange.
        response += _generate_login_prompt()

    return response


def _handle_telnet_negotiation(raw_data: bytes, bot_ip: str) -> bytes:
    """Handle Telnet IAC negotiation requests.

    Responds to DO/DONT/WILL/WONT commands with appropriate replies.

    Args:
        raw_data: Raw bytes containing IAC negotiation sequences.
        bot_ip: The bot's IP address (for logging).

    Returns:
        Negotiation response as bytes.
    """
    response = b''
    iac_pos = 0

    while iac_pos < len(raw_data):
        if raw_data[iac_pos : iac_pos + 1] == IAC:
            cmd_pos = iac_pos + 1
            if cmd_pos >= len(raw_data):
                break

            command = raw_data[cmd_pos : cmd_pos + 1]
            opt_pos = cmd_pos + 1
            if opt_pos >= len(raw_data):
                break
            option = raw_data[opt_pos : opt_pos + 1]

            # Bot sends DO or WILL — we respond with WONT or DONT (refuse)
            if command == DO:
                # A client DO ECHO asks US (the server) to echo what the user
                # types. The server MUST accept echo (so the login prompt works),
                # so answer DO ECHO with WILL ECHO rather than WONT.
                if option == OPT_ECHO:
                    response += IAC + WILL + option
                else:
                    response += IAC + WONT + option
                    logger.debug('Refused telnet option %s from %s', option.hex(), bot_ip)
            elif command == WILL:
                # Echo and binary we accept, others refuse
                if option in (OPT_ECHO, OPT_BINARY):
                    response += IAC + DO + option
                else:
                    response += IAC + DONT + option
            elif command == WONT or command == DONT:
                # Bot refuses something — acknowledge with DONT/WONT
                response += IAC + DONT + option if command == WONT else IAC + WONT + option

            iac_pos = opt_pos + 1
        else:
            iac_pos += 1

    return response


def _generate_login_prompt() -> bytes:
    """Generate a Telnet login prompt sequence.

    Returns:
        Login prompt with IAC sequences as bytes.
    """
    banner = random.choice(TELNET_BANNERS)
    # Send banner, then IAC DO ECHO (ask the *client* to echo what the user
    # types - per RFC 854 echo is the client's responsibility), then login
    # prompt. (Old code sent IAC WILL ECHO, a server->server option assertion
    # that is protocol-impossible for echo and confused strict clients.)
    return (
        b'\xff\xfd\x03'  # IAC DO ECHO - server wants the client to echo
        b'\xff\xfb\x01'  # IAC WILL BINARY
        b'\xff\xfd\x18' + banner.encode('utf-8') + b'\r\nlogin: '  # IAC DO TTYPE
    )


def generate_telnet_greeting(bot_ip: str = '127.0.0.1') -> bytes:
    """Generate the initial Telnet greeting sent when a client connects.

    Args:
        bot_ip: The bot's IP address (for logging).

    Returns:
        Initial greeting with banner and IAC negotiation as bytes.
    """
    logger.info('Sending Telnet greeting to %s', bot_ip)
    return _generate_login_prompt()


def generate_password_prompt() -> bytes:
    """Generate a Telnet password prompt after username is received.

    Returns:
        Password prompt as bytes.
    """
    return b'\r\nPassword: '


def generate_auth_failure() -> bytes:
    """Generate a Telnet authentication failure response.

    Returns:
        Auth failure message as bytes.
    """
    messages = [
        '\r\nLogin incorrect\r\n',
        '\r\nAccess denied\r\n',
        '\r\nAuthentication failed\r\n',
    ]
    return random.choice(messages).encode('utf-8')


def generate_auth_success() -> bytes:
    """Generate a Telnet authentication success response.

    Returns:
        Auth success message with shell prompt as bytes.
    """
    prompts = [
        '\r\nWelcome to Debian GNU/Linux 12 (bookworm)\r\n',
        '\r\nWelcome to Ubuntu 22.04 LTS\r\n',
        '\r\nLast login: Mon Jun  9 03:14:22 UTC 2026 from {}\r\n'.format(
            '.'.join(str(random.randint(1, 254)) for _ in range(4)),
        ),
    ]
    return random.choice(prompts).encode('utf-8') + b'$ '
