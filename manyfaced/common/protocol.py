"""Protocol detection for incoming honeypot connections.

Detects SSH, FTP, Telnet, and other common protocols from raw bytes
before the HTTP parser attempts to parse them.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Protocol signatures to detect from raw bytes
_PROTOCOL_SIGNATURES = [
    # (name, regex_pattern, sample)
    ("ssh", re.compile(rb"^SSH-\d\.\d-", re.IGNORECASE), b"SSH-2.0-OpenSSH"),
    ("ftp", re.compile(rb"^220\s", re.IGNORECASE), b"220 (vsFTPd)"),
    ("telnet", re.compile(rb"^\x00\x00\x00", re.IGNORECASE), b"\x00\x00\x00"),
    ("smtp", re.compile(rb"^220\s", re.IGNORECASE), b"220 mail.example.com"),
    ("pop3", re.compile(rb"^\+OK\s", re.IGNORECASE), b"+OK mailserver"),
    ("imap", re.compile(rb"^\* OK\s", re.IGNORECASE), b"* OK IMAP4"),
    ("rdp", re.compile(rb"^\x03\x00", re.IGNORECASE), b"\x03\x00"),
    ("vnc", re.compile(rb"^(RFB \d\.\d)", re.IGNORECASE), b"RFB 003.003"),
    # HTTP detection (for comparison)
    (
        "http",
        re.compile(
            rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s", re.IGNORECASE
        ),
        b"GET / HTTP/1.1",
    ),
]

# HTTP detection (for comparison)
_HTTP_METHOD_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s", re.IGNORECASE
)


def detect_protocol(raw_data: bytes) -> Optional[str]:
    """Detect the protocol from raw connection data.

    Args:
        raw_data: Raw bytes from the socket connection.

    Returns:
        Protocol name string, or None if no known protocol detected.
    """
    if not raw_data:
        return None

    # Try each protocol signature
    for name, pattern, _sample in _PROTOCOL_SIGNATURES:
        if pattern.search(raw_data[:64]):  # Check first 64 bytes
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
    info = {"protocol": None, "raw": raw_data[:256].decode("latin-1", errors="replace")}

    if not raw_data:
        return info

    # SSH detection
    ssh_match = re.match(rb"^(SSH-\d\.\d-(.*))", raw_data)
    if ssh_match:
        info["protocol"] = "ssh"
        info["version"] = ssh_match.group(1).decode("latin-1", errors="replace")
        # Try to extract client name
        client_match = re.match(r"SSH-\d\.\d-(.+)", info["version"])
        if client_match:
            info["client"] = (
                client_match.group(1).split("\r\n")[0].split("\n")[0].strip()
            )
        return info

    # FTP detection
    ftp_match = re.match(rb"^(220\s+(.*?))(\r\n|\n)", raw_data)
    if ftp_match:
        info["protocol"] = "ftp"
        info["banner"] = ftp_match.group(1).decode("latin-1", errors="replace")
        return info

    # HTTP detection
    http_match = re.match(
        rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/([\d.]+)",
        raw_data,
    )
    if http_match:
        info["protocol"] = "http"
        info["method"] = http_match.group(1).decode("latin-1", errors="replace")
        info["path"] = http_match.group(2).decode("latin-1", errors="replace")
        info["version"] = http_match.group(3).decode("latin-1", errors="replace")
        return info

    # Telnet detection
    if raw_data[:3] == b"\x00\x00\x00":
        info["protocol"] = "telnet"
        return info

    # RDP detection
    if raw_data[:2] == b"\x03\x00":
        info["protocol"] = "rdp"
        return info

    # VNC detection
    vnc_match = re.match(rb"^(RFB \d\.\d)", raw_data)
    if vnc_match:
        info["protocol"] = "vnc"
        info["version"] = vnc_match.group(1).decode("latin-1", errors="replace")
        return info

    # Unknown binary
    info["protocol"] = "unknown"
    info["is_binary"] = True
    return info
