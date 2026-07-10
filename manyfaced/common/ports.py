"""Shared port constants for honeypot configuration.

Extracted from config.py and client.py to avoid duplication.
"""

# Default top 50 ports for --top-ports mode (extracted to avoid duplication)
DEFAULT_TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    5901,
    6379,
    8080,
    8443,
    9200,
    11211,
    27017,
    5672,
    15672,
    4369,
    2181,
    9090,
    8888,
    7001,
    7002,
    11300,
    11301,
    11302,
    11303,
    11304,
    11305,
    11306,
    11307,
    11308,
    11309,
    11310,
    11311,
    5000,
]

PORT_MODES = ('single', 'top', 'all')


# ── UDP faces (issue #388) ──────────────────────────────────────────────────
# The honeypot was TCP-only before the UDP transport work. SIP (5060) and SNMP
# (161) are the #3 / top-10 most-targeted protocols in the Jan-2026 honeypot
# landscape yet are UDP, so they were invisible. These are the UDP analogues of
# DEFAULT_TOP_PORTS / PRIVILEGED_PORT_REDIRECTS, kept SEPARATE so the TCP
# dispatch logic (iptables redirect → bound high port) is never disturbed.
DEFAULT_UDP_PORTS = [
    161,  # SNMP
    5060,  # SIP
    53,  # DNS (UDP side; already in TCP top-ports but also served over UDP)
    123,  # NTP
    69,  # TFTP
    1900,  # SSDP / UPnP
    5353,  # mDNS
    500,  # IKE / ISAKMP (VPN)
    1194,  # OpenVPN
    3478,  # STUN / TURN (WebRTC / VoIP)
    4500,  # IPsec NAT-T
    514,  # Syslog
    1812,  # RADIUS
    1813,  # RADIUS accounting
    9201,  # Elasticsearch transport (UDP side)
]


# Privileged UDP ports (<1024) can't be bound by the non-root honeypot user, so
# they are redirected (via an iptables/nft REDIRECT or the same mechanism as the
# TCP PRIVILEGED_PORT_REDIRECTS) to a high bound port. This dict mirrors that
# mapping for UDP. External (attacker-visible) -> bound (honeypot-listened) port.
UDP_PRIVILEGED_PORT_REDIRECTS: dict[int, int] = {
    161: 10161,  # SNMP
    53: 10053,  # DNS (UDP)
    123: 10123,  # NTP
    69: 10069,  # TFTP
    500: 10500,  # IKE
    514: 10514,  # Syslog
    1812: 11812,  # RADIUS auth
    1813: 11813,  # RADIUS acct
    1900: 11900,  # SSDP
    5353: 15353,  # mDNS
    3478: 13478,  # STUN
    4500: 14500,  # IPsec NAT-T
}


# high (bound) -> priv (external) for UDP, generated inverse; used for display.
UDP_HIGH_TO_PRIV: dict[int, int] = {
    high: priv for priv, high in UDP_PRIVILEGED_PORT_REDIRECTS.items()
}


def external_udp_port(port: int | None) -> int:
    """Map a bound (high) UDP port back to the external privileged port.

    Returns ``port`` unchanged when it is not a known UDP redirect target.
    """
    if not port:
        return 0
    return UDP_HIGH_TO_PRIV.get(int(port), int(port))


def is_udp_redirected(port: int | None) -> bool:
    """True if ``port`` is a honeypot-bound high UDP port behind a redirect."""
    if not port:
        return False
    return int(port) in UDP_HIGH_TO_PRIV


# ── iptables PREROUTING REDIRECT mapping (issue #320) ───────────────────────
# The honeypot runs as a non-root user, so it cannot bind privileged ports
# (<1024). On the droplet, iptables PREROUTING REDIRECT rules map each
# privileged "external" port an attacker hits to a high "bound" port the
# honeypot actually listens on. Example: traffic to 22 (SSH) is redirected to
# 10022, which is what the honeypot binds and what gets recorded as
# ``listen_port`` in every capture.
#
# THIS IS THE SINGLE SOURCE OF TRUTH for that mapping. The dashboard resolves a
# bound port back to the external port so it displays what attackers actually
# targeted (the useful info), and templates/setup-iptables-privileged-ports.sh
# DERIVES its rules from this same table. Do not duplicate the mapping
# elsewhere.
PRIVILEGED_PORT_REDIRECTS: dict[int, int] = {
    80: 8080,  # HTTP
    443: 8443,  # HTTPS
    21: 10021,  # FTP
    22: 10022,  # SSH
    23: 10023,  # Telnet
    25: 10025,  # SMTP
    53: 10053,  # DNS
    110: 10110,  # POP3
    135: 10135,  # MSRPC
    139: 10139,  # NetBIOS
    143: 10143,  # IMAP
    445: 10445,  # SMB
    993: 10993,  # IMAPS
    995: 10995,  # POP3S
}

# high (bound) -> priv (external). Generated inverse; used for display.
HIGH_TO_PRIV: dict[int, int] = {high: priv for priv, high in PRIVILEGED_PORT_REDIRECTS.items()}


def external_port(port: int | None) -> int:
    """Map a bound (high) port back to the external privileged port it was
    redirected from.

    Returns ``port`` unchanged when it is not a known redirect target (i.e. the
    honeypot bound and was hit on that port directly, e.g. 3306/MySQL).
    """
    if not port:
        return 0
    return HIGH_TO_PRIV.get(int(port), int(port))


def is_redirected(port: int | None) -> bool:
    """True if ``port`` is a honeypot-bound high port that is the target of an
    iptables redirect (i.e. its external identity differs from the bound one).
    """
    if not port:
        return False
    return int(port) in HIGH_TO_PRIV


def internal_ports(external: int) -> list[int]:
    """Every ``listen_port`` value that should match a click on ``external``.

    An attacker-facing external port maps to itself, plus — when it is a
    privileged port behind an iptables redirect — the high bound port it is
    redirected to. This is the *inverse* of :func:`external_port` and is used
    to scope DB queries by the external port a user clicked (issue #330).
    """
    high = PRIVILEGED_PORT_REDIRECTS.get(int(external))
    return [int(external), high] if high else [int(external)]
