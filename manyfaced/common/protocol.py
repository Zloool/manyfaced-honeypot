"""Protocol detection for incoming honeypot connections.

Detects SSH, FTP, Telnet, and other common protocols from raw bytes
before the HTTP parser attempts to parse them.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Protocol signatures to detect from raw bytes
# Order matters: more specific patterns first to avoid false positives
_PROTOCOL_SIGNATURES = [
    # (name, regex_pattern, sample)
    ('ssh', re.compile(rb'^SSH-\d\.\d-', re.IGNORECASE), b'SSH-2.0-OpenSSH'),
    ('ftp', re.compile(rb'^220\s', re.IGNORECASE), b'220 (vsFTPd)'),
    # SMB/NBT before TELNET — \x00\x00\x00 prefix is actually NBT session requests, not telnet
    ('smb', re.compile(rb'^\x00\x00\x00[\x10\x18]'), None),  # NBT session request (16 or 24 bytes)
    # TELNET: starts with IAC (Interpret As Command) byte 0xFF
    ('telnet', re.compile(rb'^\xff'), b'\xff\xfb\x01'),
    # POP3/IMAP before Redis — both + and * can appear in other protocols, but POP3/IMAP are more specific
    ('pop3', re.compile(rb'^\+OK[ ]', re.IGNORECASE), b'+OK mailserver'),
    ('imap', re.compile(rb'^\* OK[ ]', re.IGNORECASE), b'* OK IMAP4'),
    # Redis RESP after POP3/IMAP to avoid false positives on +OK and * OK greetings
    # Use negative lookahead: match $ or *, or + that is NOT followed by OK\s
    ('redis', re.compile(rb'^[$*]|^\+(?!OK[ ])'), None),
    # SMTP after Redis since 220 could theoretically appear in other contexts
    ('smtp', re.compile(rb'^220\s', re.IGNORECASE), b'220 mail.example.com'),
    ('rdp', re.compile(rb'^\x03\x00', re.IGNORECASE), b'\x03\x00'),
    ('vnc', re.compile(rb'^(RFB \d\.\d)', re.IGNORECASE), b'RFB 003.003'),
    # TLS ClientHello: 0x16 (handshake) + 0x03 xx (version) + 2-byte length
    ('tls', re.compile(rb'^\x16\x03'), None),
    # HTTP before DNS — "GET/POST..." starts with ASCII letters that are valid DNS label bytes
    (
        'http',
        re.compile(rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s', re.IGNORECASE),
        b'GET / HTTP/1.1',
    ),
    # HTTP/2 connection preface — must be checked before DNS to avoid false positives,
    # since the ASCII text at offset 12 can match DNS label patterns.
    (
        'http2',
        re.compile(rb'^PRI \* HTTP/2\.0\r\n\r\nSM\r\n\r\n'),
        b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',
    ),
    # DNS-over-TCP: conservative detection requiring valid domain label structure.
    # After 12-byte DNS header, require a label length byte (0x01-0x3f) followed by
    # alphanumeric or hyphen — excludes HTTP/2 PRI and other noise.
    ('dns', re.compile(rb'^.{12}(?:[\x01-\x3f][\x2d\x30-\x39\x41-\x5a\x61-\x7a])'), None),
    # MongoDB wire protocol: opcode at offset 20 in {length(4)+flags(4)+cursor_id(8)+response_to(4)+opcode(4)}
    ('mongodb', re.compile(rb'^.{20}(?:\xd4\x07\x00\x00|\xe8\x03\x00\x00|\x01\x00\x00\x00)'), None),
]

# HTTP detection (for comparison) — separate from _PROTOCOL_SIGNATURES to avoid duplicate matching
_HTTP_METHOD_RE = re.compile(
    rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s', re.IGNORECASE
)


def detect_protocol(raw_data: bytes) -> str | None:
    """Detect the protocol from raw connection data.

    Args:
        raw_data: Raw bytes from the socket connection.

    Returns:
        Protocol name string, or None if no known protocol detected.
    """
    if not raw_data:
        return None

    # Try each protocol signature using match (anchored at position 0)
    for name, pattern, _sample in _PROTOCOL_SIGNATURES:
        if pattern.match(raw_data):
            return name

    return None


def is_http_request(raw_data: bytes) -> bool:
    """Check if raw data looks like an HTTP request.

    Args:
        raw_data: Raw bytes from the socket connection.

    Returns:
        True if the data appears to be an HTTP request.
    """
    if not raw_data:
        return False

    # Check for HTTP method at the start
    if _HTTP_METHOD_RE.match(raw_data):
        return True

    return False


def get_protocol_info(raw_data: bytes) -> dict:
    """Extract protocol-specific information from raw data.

    Args:
        raw_data: Raw bytes from the socket connection.

    Returns:
        Dict with protocol info (type, version, client, etc.)
    """
    info = {'protocol': None, 'raw': raw_data[:256].decode('latin-1', errors='replace')}

    if not raw_data:
        return info

    # SSH detection
    ssh_match = re.match(rb'^(SSH-\d\.\d-(.*))', raw_data)
    if ssh_match:
        info['protocol'] = 'ssh'
        info['version'] = ssh_match.group(1).decode('latin-1', errors='replace')
        # Try to extract client name
        client_match = re.match(r'SSH-\d\.\d-(.+)', info['version'])
        if client_match:
            info['client'] = client_match.group(1).split('\r\n')[0].split('\n')[0].strip()
        return info

    # FTP detection
    ftp_match = re.match(rb'^(220\s+(.*?))(\r\n|\n)', raw_data)
    if ftp_match:
        info['protocol'] = 'ftp'
        info['banner'] = ftp_match.group(1).decode('latin-1', errors='replace')
        return info

    # HTTP detection
    http_match = re.match(
        rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/([\d.]+)',
        raw_data,
    )
    if http_match:
        info['protocol'] = 'http'
        info['method'] = http_match.group(1).decode('latin-1', errors='replace')
        info['path'] = http_match.group(2).decode('latin-1', errors='replace')
        info['version'] = http_match.group(3).decode('latin-1', errors='replace')
        return info

    # SMB/NBT detection (before telnet — \x00\x00\x00 prefix is NBT, not telnet)
    if (
        len(raw_data) >= 4
        and raw_data[:3] == b'\x00\x00\x00'
        and raw_data[3:4] in (b'\x10', b'\x18')
    ):
        info['protocol'] = 'smb'
        return info

    # Telnet detection — starts with IAC (Interpret As Command) byte 0xFF
    if raw_data[:1] == b'\xff':
        info['protocol'] = 'telnet'
        return info

    # RDP detection
    if raw_data[:2] == b'\x03\x00':
        info['protocol'] = 'rdp'
        return info

    # VNC detection
    vnc_match = re.match(rb'^(RFB \d\.\d)', raw_data)
    if vnc_match:
        info['protocol'] = 'vnc'
        info['version'] = vnc_match.group(1).decode('latin-1', errors='replace')
        return info

    # TLS detection
    if len(raw_data) >= 5 and raw_data[0] == 0x16 and raw_data[1:2] == b'\x03':
        info['protocol'] = 'tls'
        version_bytes = raw_data[1:3]
        if len(version_bytes) == 2:
            info['version'] = f'TLS {version_bytes[0]}.{version_bytes[1]}'
        return info

    # DNS-over-TCP detection
    if len(raw_data) >= 4:
        import struct

        dns_len = struct.unpack('!H', raw_data[:2])[0]
        if 4 <= dns_len <= len(raw_data) - 2 and raw_data[2] in range(0x01, 0xC0):
            info['protocol'] = 'dns'
            return info

    # MongoDB wire protocol detection
    if len(raw_data) >= 24:
        import struct

        msg_len = struct.unpack('<I', raw_data[:4])[0]
        opcode = struct.unpack('<I', raw_data[20:24])[0]
        valid_opcodes = {0, 1, 3, 4, 1000, 2001, 2002, 2004, 2005}
        if msg_len > 16 and opcode in valid_opcodes:
            info['protocol'] = 'mongodb'
            return info

    # Redis RESP detection
    if raw_data[:1] in (b'$', b'*', b'+'):
        info['protocol'] = 'redis'
        return info

    # Unknown binary
    info['protocol'] = 'unknown'
    info['is_binary'] = True
    return info
