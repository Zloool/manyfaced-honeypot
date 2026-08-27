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
    # SMB/NBT before TELNET — \x00\x00\x00 prefix with SMB indicators (NT LM, SMB 2.x)
    ('smb', re.compile(rb'^\x00\x00\x00.{16}(?:NT\sLM|SMB\s\d)'), None),
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
    # ── Non-HTTP request-line / binary protocols that share a leading token
    #    with the generic HTTP method regex MUST be matched BEFORE it (issue #599).
    #    RTSP and SIP both use verbs like OPTIONS/DESCRIBE that the http regex
    #    would otherwise swallow, and LDAP is a binary ASN.1 bind that must not
    #    fall through to the HTTP path.
    # RTSP — request-line verb followed by an RTSP/{version} token (RFC 2326/7826).
    (
        'rtsp',
        re.compile(
            rb'^(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|ANNOUNCE|SET_PARAMETER|GET_PARAMETER|RECORD|REDIRECT)\s.*RTSP/'
        ),
        b'OPTIONS / RTSP/1.0',
    ),
    # LDAP bind request — ASN.1 SEQUENCE (0x30) + length + INTEGER messageID
    # (0x02 0x01 <any>) + application bind tag (0x60). Placed before HTTP so an
    # LDAP-on-HTTP-port probe is not mislabeled as HTTP (issue #599). The leading
    # 0x30 also matches SNMP/DNS-but-binary patterns; the \x60 bind tag is the
    # discriminatоr that keeps it LDAP-specific.
    (
        'ldap',
        re.compile(rb'^\x30.{1,8}\x02\x01.\x60'),
        b'\x30\x14\x02\x01\x01\x60\x0f',
    ),
    # SIP — SIP request-line verb followed by a SIP/SIPS URI (sip[s]:) e.g.
    # "OPTIONS sip:nm@host SIP/2.0", OR a "SIP/2.0 200 OK" status line.
    # The URI must be a SIP URI (not "*" or "/path"), otherwise HTTP asterisk-form
    # "OPTIONS * HTTP/1.1" would be swallowed here (issue #599). Placed BEFORE
    # the generic HTTP method regex so real SIP is detected as 'sip', and BEFORE
    # DNS.
    (
        'sip',
        re.compile(
            rb'^(?:(?:INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|SUBSCRIBE|NOTIFY|PUBLISH|MESSAGE|INFO|REFER|PRACK)\s+sips?:|SIP/2\.0)'
        ),
        b'OPTIONS sip:nm@mn2 SIP/2.0',
    ),
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
    # SNMP (UDP) — version byte + community string. SNMPv1/v2c: 0x30 (SEQUENCE)
    # 0x02 0x01 0x00/0x01 (version) ... then 0x04 (OCTET STRING = community).
    ('snmp', re.compile(rb'^\x30.{1,8}\x02\x01[\x00\x01]\x04'), None),
    # DNS-over-TCP: conservative detection requiring valid domain label structure.
    # After 12-byte DNS header, require a label length byte (0x01-0x3f) followed by
    # alphanumeric or hyphen — excludes HTTP/2 PRI and other noise.
    ('dns', re.compile(rb'^.{12}(?:[\x01-\x3f][\x2d\x30-\x39\x41-\x5a\x61-\x7a])'), None),
    # MongoDB wire protocol: opcode at offset 20 in {length(4)+flags(4)+cursor_id(8)+response_to(4)+opcode(4)}.
    # Recognised opcodes (LE): OP_REPLY=1, OP_MSG=2013 (0x07dd -> \xdd\x07\x00\x00),
    # OP_UPDATE=2001, OP_INSERT=2002, OP_QUERY=2004 (0x07d4 -> \xd4\x07\x00\x00),
    # OP_GET_MORE=2005, OP_DELETE=2006, OP_KILL_CURSORS=2007, OP_COMMAND=2010,
    # OP_COMMAND_REPLY=2011, OP_COMPRESSED=2012 (issue #597). Pre-1.6 legacy
    # OP_QUERY/OP_REPLY probes and the modern OP_MSG (the default opcode used by
    # all current MongoDB drivers) must both be detected.
    (
        'mongodb',
        re.compile(
            rb'^.{20}(?:\xd4\x07\x00\x00|\xe8\x03\x00\x00|\x01\x00\x00\x00|\xdd\x07\x00\x00|\xc9\x07\x00\x00|\xca\x07\x00\x00|\xcb\x07\x00\x00|\xcc\x07\x00\x00|\xcd\x07\x00\x00|\xda\x07\x00\x00|\xdb\x07\x00\x00|\xdc\x07\x00\x00)'
        ),
        None,
    ),
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
        client_match = re.match(r'SSH-\d\.\d-(.+)', info['version'] or '')
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

    # SMB/NBT detection (before telnet — \x00\x00\x00 prefix with SMB indicators)
    if len(raw_data) >= 24 and raw_data[:3] == b'\x00\x00\x00':
        # Check for NT LM or SMB 2.x identifiers at offset 17 (after 4-byte header + 16-byte name section)
        try:
            payload = raw_data[17:].decode('ascii', errors='ignore')
            if 'NT LM' in payload or re.match(r'SMB\s\d', payload):
                info['protocol'] = 'smb'
                return info
        except Exception:
            # Payload decode/parse failed on non-ASCII bytes — fall through to
            # the next detection heuristic rather than aborting protocol sniff.
            logger.debug('swallowed exception', exc_info=True)

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
        # OP_REPLY=1, OP_MSG=2013 (the modern default driver opcode, issue #597),
        # OP_UPDATE=2001, OP_INSERT=2002, OP_QUERY=2004, OP_GET_MORE=2005,
        # OP_DELETE=2006, OP_KILL_CURSORS=2007, OP_COMMAND=2010,
        # OP_COMMAND_REPLY=2011, OP_COMPRESSED=2012. Legacy small opcodes (0..4)
        # are fuzz/version probes; keep them detected.
        valid_opcodes = {
            0,
            1,
            3,
            4,
            1000,
            2001,
            2002,
            2004,
            2005,
            2006,
            2007,
            2010,
            2011,
            2012,
            2013,
        }
        if msg_len > 16 and opcode in valid_opcodes:
            info['protocol'] = 'mongodb'
            return info

    # Redis RESP detection
    if raw_data[:1] in (b'$', b'*', b'+'):
        info['protocol'] = 'redis'
        return info

    # Unknown binary
    info['protocol'] = 'unknown'
    info['is_binary'] = True  # type: ignore[assignment]
    return info
