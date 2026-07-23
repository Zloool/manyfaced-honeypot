"""Inline credential extractors for plaintext/structured non-HTTP faces.

These supplement the handler-owned extractors (``telnet_handler`` /
``rdp_handler`` already expose ``extract_telnet_credentials`` /
``extract_rdp_credentials``, which ``faces.py`` imports directly). The handlers
for POP3 / IMAP / FTP / MySQL / MSSQL do NOT ship a credential extractor, so the
wireable extractors live here and are wired into ``_FACE_DEFS`` by
``manyfaced.common.faces`` (issues #627 / #647).

Every extractor returns ``str | None`` so it can be assigned straight to
``BearStorage.login``; returning ``None`` means "no creds offered on this
frame" and the multi-frame client-first loop keeps consuming frames.
"""

from __future__ import annotations

import struct


def extract_pop3_credentials(raw: bytes) -> str | None:
    """Extract USER/PASS from a POP3 conversation (plaintext).

    A POP3 client sends ``USER <name>`` then ``PASS <secret>``. We surface
    whatever was offered (user only, pass only, or both) so a single-frame
    capture still records the partial credential attempt.
    """
    text = raw.decode('latin-1', errors='replace')
    user = None
    pw = None
    for line in text.splitlines():
        ll = line.strip()
        if ll.upper().startswith('USER '):
            user = ll[5:].strip()
        elif ll.upper().startswith('PASS '):
            pw = ll[5:].strip()
    if user or pw:
        return f'{user or ""}:{pw or ""}'
    return None


def extract_imap_credentials(raw: bytes) -> str | None:
    """Extract LOGIN user/pass from an IMAP conversation (plaintext).

    IMAP clients send ``a001 LOGIN user pass`` — the LOGIN verb is NOT at the
    start of the line (it follows the client-generated tag), so we search for
    the verb anywhere in the line. ``USER``/``PASS`` exchanges are also handled
    for clients that use the older style.
    """
    text = raw.decode('latin-1', errors='replace')
    user = None
    pw = None
    for line in text.splitlines():
        ll = line.strip()
        if 'LOGIN ' in ll.upper():
            parts = ll.upper().split('LOGIN ', 1)[1].split()
            if len(parts) >= 2:
                user, pw = parts[0], parts[1]
                break
        elif ll.upper().startswith('USER '):
            user = ll[5:].strip()
        elif ll.upper().startswith('PASS '):
            pw = ll[5:].strip()
    if user or pw:
        return f'{user or ""}:{pw or ""}'
    return None


def extract_ftp_credentials(raw: bytes) -> str | None:
    """Extract USER/PASS from an FTP conversation (plaintext)."""
    text = raw.decode('latin-1', errors='replace')
    user = None
    pw = None
    for line in text.splitlines():
        ll = line.strip()
        if ll.upper().startswith('USER '):
            user = ll[5:].strip()
        elif ll.upper().startswith('PASS '):
            pw = ll[5:].strip()
    if user or pw:
        return f'{user or ""}:{pw or ""}'
    return None


def extract_mysql_credentials(raw: bytes) -> str | None:
    """Extract the username from a MySQL HandshakeResponse41 (auth) packet.

    The auth packet carries the username as a NUL-terminated string at offset 8
    (after the 4-byte capability flags + 4-byte max-packet + 1-byte charset).
    Credentials are intentionally NOT deeply parsed here — the face only
    records that an auth attempt was made with the offered username (issue #647).
    """
    try:
        if len(raw) < 8:
            return None
        username = raw[8:].split(b'\x00', 1)[0].decode('latin-1', errors='replace')
        if username:
            return f'{username}:'
    except Exception:
        return None
    return None


def extract_mssql_credentials(raw: bytes) -> str | None:
    """Extract the username from a TDS Login packet (type 0x10).

    The TDS Login packet carries the username as a UTF-16LE string at the
    offset given by the ``offsetOfUsername`` field (uint16 at byte 48) with
    ``lenOfUsername`` (uint16 at byte 44). We surface it so a real MSSQL client
    auth attempt is recorded (issue #647).
    """
    try:
        if len(raw) < 50 or raw[0] != 0x10:
            return None
        user_len = struct.unpack('<H', raw[44:46])[0]
        user_pos = struct.unpack('<H', raw[48:50])[0]
        if user_len and user_pos and user_pos + user_len <= len(raw):
            username = raw[user_pos : user_pos + user_len].decode('utf-16-le', errors='replace')
            if username:
                return f'{username}:'
    except Exception:
        return None
    return None
