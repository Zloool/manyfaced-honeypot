"""Protocol-specific response generation for honeypot probes.

Standalone functions that generate realistic-looking responses for various
protocols (SSH, FTP, Telnet, RDP, VNC, SMTP, POP3, IMAP) and HTTP fallbacks.
These are called by HTTPHandler to keep request-handling logic clean.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone


def fake_ssh_banner() -> str:
    """Return a random realistic SSH banner string."""
    banner_versions = [
        'SSH-2.0-OpenSSH_9.6',
        'SSH-2.0-OpenSSH_8.9',
        'SSH-2.0-OpenSSH_7.9',
        'SSH-2.0-libssh2_1.10.0',
    ]
    return random.choice(banner_versions) + '\r\n'


def ftp_banners() -> list[str]:
    """Return a list of fake FTP banners."""
    return [
        '220 (vsFTPd 3.0.3)\r\n',
        '220 Welcome to FTP service.\r\n',
        '220 ProFTPD 1.3.5 Server\r\n',
    ]


def non_http_response(protocol: str) -> bytes:
    """Return appropriate response bytes for a non-HTTP protocol probe.

    Args:
        protocol: Detected protocol name (telnet, rdp, vnc, smtp, pop3, imap).

    Returns:
        Protocol-specific response bytes.
    """
    responses = {
        'ftp': lambda: random.choice(ftp_banners()).encode('utf-8'),
        'telnet': lambda: b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f',
        'rdp': lambda: b'\x03\x00\x00\x1f\x0e\xe0\x00\x00\x18\x00\x01\xc1\x00\x00\x00',
        'vnc': lambda: b'RFB 003.003\r\n',
        # SMB/NBT: NetBIOS Session Service positive session response (RFC 1002)
        'smb': lambda: b'\x82\x00\x00\x00',  # type=0x82, flags=0, length=0
    }

    if protocol in responses:
        return responses[protocol]()

    # SMTP/POP3/IMAP greetings
    greetings = {
        'smtp': '220 manyfaced-honeypot ESMTP\r\n',
        'pop3': '+OK manyfaced-honeypot POP3 ready\r\n',
        'imap': '* OK manyfaced-honeypot IMAP4 ready\r\n',
    }

    if protocol in greetings:
        return greetings[protocol].encode('utf-8')

    # Unknown protocol: empty response (close connection)
    return b''


def _fallback_html_body(path: str) -> str:
    """Return an HTML body string for fallback HTTP responses.

    Args:
        path: The requested URL path, embedded in the response.

    Returns:
        HTML body content as a string.
    """
    return (
        f'<!DOCTYPE html>\n'
        '<html><head><title>Server</title></head>\n'
        f"<body><h1>Welcome to zlol's manyface!</h1>\n"
        f'<p>Server: Apache/2.4.57 (Ubuntu)</p>\n'
        f'<p>Path: {path}</p>\n'
        '</body></html>'
    )


def _build_http_response(
    body: str, content_type: str, path: str = '', status: str = '200 OK'
) -> bytes:
    """Build a complete HTTP response with Content-Length header.

    Args:
        body: The response body string.
        content_type: The Content-Type header value.
        path: The request path (used for Link header in WordPress responses).
        status: The HTTP status line (default '200 OK').

    Returns:
        Complete HTTP response as bytes (iso-8859-1 encoded) with Content-Length.
    """
    now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    body_encoded = body.encode('iso-8859-1')

    headers = [
        f'HTTP/1.1 {status}',
        'Server: Apache/2.4.57 (Ubuntu)',
        f'Date: {now}',
        f'Content-Type: {content_type}',
        f'Content-Length: {len(body_encoded)}',
        'Connection: close',
    ]

    # Add WordPress-specific Link header if path suggests it
    if '/' in path and ('wp-login' in path or 'xmlrpc' in path):
        host = path.split('/')[1] if '/' in path else 'localhost'
        headers.append(
            f'Link: <https://{host}>; rel="https://api.w.org/"',
        )

    # Build response string then encode to bytes (iso-8859-1 for Apache compatibility)
    header_block = '\r\n'.join(headers) + '\r\n\r\n'
    return (header_block + body).encode('iso-8859-1')


def fallback_response(path: str) -> bytes:
    """Generate a full HTTP 200 OK response for unmatched paths.

    Args:
        path: The requested URL path, embedded in the response body.

    Returns:
        Complete HTTP response as bytes (iso-8859-1 encoded).
    """
    body = _fallback_html_body(path)
    return _build_http_response(body, 'text/html; charset=UTF-8', path)
