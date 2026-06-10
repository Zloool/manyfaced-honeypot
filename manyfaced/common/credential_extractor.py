"""Unified HTTP credential extraction utility.

Provides a single source of truth for extracting credentials from HTTP POST requests.
All handlers should import and use this module instead of duplicating logic.

Usage::

    from manyfaced.common.credential_extractor import extract_http_credentials

    creds = extract_http_credentials(raw_request, headers)
"""

from __future__ import annotations

import re
from typing import Any


# Common username field names (order matters — first match wins)
USERNAME_FIELDS: list[str] = [
    'log',
    'user',
    'username',
    'login',
    'user_login',
    'USER_LOGIN',
    'j_username',
    'uid',
    'email',
    'pma_username',
    'server[0][user]',
]

# Common password field names (order matters — first match wins)
PASSWORD_FIELDS: list[str] = [
    'pwd',
    'pass',
    'password',
    'login_password',
    'j_password',
    'passwort',
    'user_pass',
    'USER_PASSWORD',
    'pma_password',
    'server[0][password]',
]


def _url_decode(body: str) -> str:
    """URL-decode a form body using urllib.parse.unquote_plus.

    This is the correct, standard way to decode URL-encoded data — it handles
    percent-encoding in the right order and supports + as space.

    Args:
        body: The raw URL-encoded request body.

    Returns:
        Decoded string with all percent-codes resolved correctly.
    """
    from urllib.parse import unquote_plus  # noqa: PLC0415

    return unquote_plus(body)


def _extract_field_value(body: str, field_name: str) -> str | None:
    """Extract a single field value from URL-encoded form data.

    Args:
        body: The decoded request body.
        field_name: The field name to look for (e.g., 'username').

    Returns:
        The field value, or None if not found.
    """
    prefix = field_name + '='
    if prefix in body:
        value = body.split(prefix, 1)[1].split('&', 1)[0]
        return value if value else None
    return None


def extract_http_credentials(
    raw_request: str, headers: dict[str, Any] | None = None
) -> dict[str, str] | None:
    """Extract credentials from an HTTP POST request.

    Looks for common credential field names in the request body (URL-encoded form data).
    Uses urllib.parse.unquote_plus for correct URL decoding.

    Args:
        raw_request: The raw HTTP request string (headers + body).
        headers: Request headers (unused but kept for API compatibility).

    Returns:
        Dict with 'username' and/or 'password' keys, or None if no credentials found.
    """
    # Only process POST requests
    parts = raw_request.split()
    if len(parts) < 1 or parts[0].upper() != 'POST':
        return None

    # Split headers from body
    header_body_split = raw_request.split('\r\n\r\n', 1)
    if len(header_body_split) < 2:
        return None

    body = header_body_split[1]

    # URL-decode the body using standard library (correct order, handles all cases)
    decoded_body = _url_decode(body)

    username = None
    password = None

    # Extract username from first matching field
    for field in USERNAME_FIELDS:
        value = _extract_field_value(decoded_body, field)
        if value:
            username = value
            break

    # Extract password from first matching field
    for field in PASSWORD_FIELDS:
        value = _extract_field_value(decoded_body, field)
        if value:
            password = value
            break

    # Return structured dict (not string — consistent return type)
    result: dict[str, str] = {}
    if username:
        result['username'] = username
    if password:
        result['password'] = password

    return result if result else None


def format_creds_string(creds: dict[str, str] | None) -> str | None:
    """Format credentials as a human-readable string (legacy compatibility).

    Args:
        creds: Credential dict from extract_http_credentials().

    Returns:
        String like 'user=admin, pass=secret' or None.
    """
    if not creds:
        return None

    parts = []
    if 'username' in creds:
        parts.append(f'user={creds["username"]}')
    if 'password' in creds:
        parts.append(f'pass={creds["password"]}')

    return ', '.join(parts) if parts else None
