"""Non-HTTP face registry — the single source of truth for non-HTTP faces.

This module replaces the byte-sniffing-first dispatch model (issue #377). The
old client path blocked on ``receive_timeout`` *before* producing any response,
so:

* **server-first** faces (the server greets before the client speaks — SSH,
  FTP, Telnet, SMTP, POP3, IMAP, VNC, RDP, MySQL, MSSQL, AMQP, Oracle TNS) could
  never be detected from client bytes (there are none at greeting time). They
  need to be resolved by the **port** the client connected to, and greeted
  *on accept*.
* **client-first** faces (Redis, Memcached, MongoDB, Zookeeper, Postgres,
  Elasticsearch, NFS, EPMD) can be detected from client bytes, but the read→
  respond→send loop still has to actually fire.

The registry is keyed by **external port** (the attacker-visible privileged
port), built from the existing canonical mappings in
``manyfaced.common.ports`` (``PRIVILEGED_PORT_REDIRECTS`` +
``DEFAULT_TOP_PORTS``) and ``manyfaced.common.status`` (the ``detected_id``
constants). The dashboard's ``PORT_SERVICE_NAMES`` and the iptables redirect
map already derive from those same sources, so we do NOT duplicate the port
list here — we compose it.

Dispatch contract (consumed by ``manyfaced.client.client``):

    spec = FACE_REGISTRY.get(external_port(listen_port))
    if spec is None or spec.is_http:
        ... existing HTTP path ...
    if spec.direction == 'server-first' and spec.greeting:
        sock.sendall(spec.greeting)        # PRELUDE: before any recv
    message = receive_timeout(sock, BOT_TIMEOUT)   # client frame / auth
    resp = spec.respond(raw_bytes, bot_ip)  # EXCHANGE: reply
    if resp:
        sock.sendall(resp)

Every handler already exposes ``generate_<proto>_greeting`` /
``generate_<proto>_response``; this module wires them through small adapters so
the dispatch loop stays uniform and the handlers need no edits (DRY).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from manyfaced.common import ports as _ports
from manyfaced.common.status import (
    SSH_CLIENT,
    UNKNOWN_MONGODB,
    UNKNOWN_NON_HTTP,
    UNKNOWN_RDP,
    UNKNOWN_REDIS,
    UNKNOWN_TELNET,
    UNKNOWN_VNC,
)

logger = logging.getLogger(__name__)

# Handler generators + greetings (lazy imports happen inside the adapters to
# avoid import cycles at module load). We reference the functions by module so
# the registry can be imported cheaply from anywhere.
from manyfaced.handlers import protocol_responses as _pr
from manyfaced.handlers.redis_handler import generate_redis_response as _redis_resp
from manyfaced.handlers.mongodb_handler import generate_mongodb_response as _mongo_resp
from manyfaced.handlers.telnet_handler import (
    generate_telnet_response as _telnet_resp,
)
from manyfaced.handlers.rdp_handler import generate_rdp_response as _rdp_resp
from manyfaced.handlers.vnc_handler import generate_vnc_response as _vnc_resp

# Direction of the protocol handshake.
SERVER_FIRST = 'server-first'
CLIENT_FIRST = 'client-first'


@dataclass(frozen=True)
class FaceSpec:
    """Declarative description of one non-HTTP face.

    Attributes:
        name: canonical protocol name (matches ``detect_protocol`` keys).
        detected_id: the ``status`` constant used for the capture record.
        direction: ``server-first`` (greet on accept) or ``client-first``.
        greeting: banner bytes sent on accept for server-first faces (``b''``
            for client-first, where the server waits for the client).
        respond: callable ``(raw_bytes, bot_ip) -> bytes | None`` producing the
            reply to a client frame. May return ``None``/``b''`` (no reply).
        capture_creds: whether to run interactive credential capture after the
            greeting/exchange (SSH, Telnet, FTP, …).
    """

    name: str
    detected_id: int
    direction: str
    greeting: bytes
    respond: Callable[[bytes, str], bytes | None]
    capture_creds: bool = False
    # Optional credential extractor called on each client frame during the
    # client-first exchange loop so creds offered across multiple commands
    # (e.g. Redis AUTH after HELLO) are captured. ``None`` = no extraction.
    extract_creds: Callable[[bytes], object] | None = None


# ---------------------------------------------------------------------------
# Greeting builders (server-first banners).
# These reuse existing generators so behavior is unchanged for those handlers
# that already produced a greeting; for the rest we synthesize a static,
# protocol-correct banner.
# ---------------------------------------------------------------------------


def _ssh_greeting() -> bytes:
    return _pr.fake_ssh_banner().encode('utf-8')


def _ftp_greeting() -> bytes:
    return _pr.non_http_response('ftp')


def _telnet_greeting() -> bytes:
    # The dedicated handler builds a richer IAC+login-prompt greeting.
    return _telnet_resp(b'', '127.0.0.1')


def _smtp_greeting() -> bytes:
    return _pr.non_http_response('smtp')


def _pop3_greeting() -> bytes:
    return _pr.non_http_response('pop3')


def _imap_greeting() -> bytes:
    return _pr.non_http_response('imap')


def _vnc_greeting() -> bytes:
    from manyfaced.handlers.vnc_handler import generate_vnc_greeting

    return generate_vnc_greeting('127.0.0.1')


def _rdp_greeting() -> bytes:
    from manyfaced.handlers.rdp_handler import generate_rdp_greeting

    return generate_rdp_greeting('127.0.0.1')


def _amqp_greeting() -> bytes:
    # AMQP 0-9-1 protocol header (server-first).
    return b'AMQP\x00\x00\x09\x01'


def _oracle_greeting() -> bytes:
    # Oracle TNS listener: a "Refuse" packet (packet type 0x04) with an ORA
    # error. Real Oracle 19c sends a Refuse carrying "ORA-12514: TNS:listener
    # does not currently know of service requested in connect descriptor". This
    # is protocol-shaped so nmap `oracle-tns-version` / clients see a TNS reply
    # instead of an HTTP admin panel (issue #440).
    msg = b'ORA-12514: TNS:listener does not currently know of service requested'
    # TNS header: type=0x04 (Refuse), reserved=0x00, checksum=0x0000,
    # length = len(header 8) + len(msg).
    length = 8 + len(msg)
    header = bytes([0x04, 0x00, 0x00, 0x00]) + length.to_bytes(2, 'big')
    return header + msg


def _nfs_greeting() -> bytes:
    # NFS / rpcbind: the server sends nothing on accept (client-first); the
    # reply is produced in _nfs_respond. Kept empty here (issue #454/#457).
    return b''


def _epmd_greeting() -> bytes:
    # EPMD (Erlang Port Mapper Daemon) is client-first: the client sends an
    # opcode (e.g. 0x73 NAMES, 0x78 PORT_PLEASE2, 0x64 DUMP), and the daemon
    # replies. Nothing is sent on accept, so the greeting is empty (issue #451/#458).
    return b''


def _mssql_greeting() -> bytes:
    # TDS prelogin: type=0x12 (Prelogin), length=0x00 0x1f (31), fixed fields.
    return (
        b'\x12\x01\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00'
    )


def _mysql_greeting() -> bytes:
    # MySQL server greeting (server-first). A minimal but valid 5.7-style
    # handshake: protocol version 0x0a, version string, thread id, scramble,
    # capability flags, charset, status, rest of scramble, auth-plugin name.
    server_version = b'5.7.44-manyfaced\x00'
    thread_id = (1234).to_bytes(4, 'little')
    # First 8 bytes of the auth-plugin-data scramble.
    scramble1 = bytes([0x3A, 0x5C, 0x2E, 0x1F, 0x7B, 0x9D, 0x4E, 0x0C])
    capability = (0xFFFF).to_bytes(2, 'little')
    charset = b'\x21'  # utf8mb4
    status = b'\x02\x00'  # SERVER_STATUS_AUTOCOMMIT
    scramble2 = bytes([0x6F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB])
    auth_plugin = b'mysql_native_password\x00'
    # Length: 1 (proto) + len(version) + 4 (thread) + 8 (scramble1) + 1 (0x00
    # terminator) + 2 (cap) + 1 (charset) + 2 (status) + 2 (cap hi) + 1 (len of
    # scramble2=21) + 10 (scramble2) + auth_plugin
    payload = (
        b'\x0a'
        + server_version
        + thread_id
        + scramble1
        + b'\x00'
        + capability
        + charset
        + status
        + b'\x0f\x80'  # upper 2 bytes of capabilities
        + b'\x15'  # length of auth-plugin-data = 21
        + scramble2
        + b'\x00'
        + auth_plugin
    )
    pkt_len = len(payload)
    seq = b'\x00'
    return pkt_len.to_bytes(3, 'little') + seq + payload


# ---------------------------------------------------------------------------
# Response adapters (client-first reply). Each takes (raw_bytes, bot_ip).
# Handlers already have a (raw_data, bot_ip) signature, so the adapter is the
# identity for those that match; we standardize the rest here.
# ---------------------------------------------------------------------------


def _redis_respond(raw: bytes, bot_ip: str) -> bytes:
    return _redis_resp(raw, bot_ip) or b''


def _redis_extract(raw: bytes):
    from manyfaced.handlers.redis_handler import extract_redis_credentials

    return extract_redis_credentials(raw)


def _mongo_respond(raw: bytes, bot_ip: str) -> bytes:
    return _mongo_resp(raw, bot_ip) or b''


def _telnet_respond(raw: bytes, bot_ip: str) -> bytes:
    return _telnet_resp(raw, bot_ip) or b''


def _rdp_respond(raw: bytes, bot_ip: str) -> bytes:
    return _rdp_resp(raw, bot_ip) or b''


def _vnc_respond(raw: bytes, bot_ip: str) -> bytes:
    return _vnc_resp(raw, bot_ip) or b''


# Memcached / Zookeeper / Postgres / Elasticsearch / Oracle / NFS / EPMD respond
# functions are synthesized inline so the face at least answers. (See issue #377
# sub-tasks for fuller emulation.)
def _memcached_respond(raw: bytes, bot_ip: str) -> bytes:
    # Reply to a `version` command with a VERSION line; otherwise stat/empty.
    text = raw.decode('latin-1', errors='replace')
    if 'version' in text.lower():
        return b'VERSION 1.6.21 (manyfaced)\r\n'
    return b'END\r\n'


def _zookeeper_respond(raw: bytes, bot_ip: str) -> bytes:
    # Respond to a connect request (opcode 0) with a connect response.
    if len(raw) >= 4:
        return b'\x00\x00\x00\x00' + raw[4:8] + b'\x00\x00\x00\x00'
    return b'\x00\x00\x00\x00'


def _postgres_respond(raw: bytes, bot_ip: str) -> bytes:
    # On a startup packet, answer with an AuthRequest (MD5, type='R', len=12,
    # method=5). Real Postgres then expects an MD5 password — we don't need to
    # drive the whole exchange, just look like it began.
    return b'R' + (12).to_bytes(4, 'big', signed=False) + (5).to_bytes(4, 'big', signed=False)


def _elasticsearch_respond(raw: bytes, bot_ip: str) -> bytes:
    body = (
        b'{"name":"manyfaced-node","cluster_name":"manyfaced",'
        b'"version":{"number":"7.17.0","build_flavor":"default"},'
        b'"tagline":"You Know, for Search"}'
    )
    return (
        b'HTTP/1.1 200 OK\r\n'
        b'Content-Type: application/json\r\n'
        b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
        b'Connection: close\r\n\r\n' + body
    )


def _oracle_respond(raw: bytes, bot_ip: str) -> bytes:
    # Reply to a TNS CONNECT data packet with a Refuse carrying ORA-12514 so a
    # client that sends a connect (rather than receiving the pre-accept Refuse)
    # still gets a protocol-shaped answer instead of an HTTP admin panel.
    msg = b'ORA-12514: TNS:listener does not currently know of service requested'
    length = 8 + len(msg)
    header = bytes([0x04, 0x00, 0x00, 0x00]) + length.to_bytes(2, 'big')
    return header + msg


def _nfs_respond(raw: bytes, bot_ip: str) -> bytes:
    # Reply to an rpcbind/NFS RPC call with a minimal but structurally valid
    # rpcbind reply: XID (echoed from the request) + reply header claiming
    # success. Enough that a showmount/portmap probe sees a protocol-shaped
    # answer instead of an HTTP 404 (issue #454/#457).
    if len(raw) < 4:
        return b''
    xid = raw[:4]
    # RPC reply: reply_stat=MSG_ACCEPTED (0), auth_flavor=AUTH_NULL (0),
    # auth_len=0, accept_stat=SUCCESS (0), then the NULL body.
    return xid + bytes([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


def _epmd_respond(raw: bytes, bot_ip: str) -> bytes:
    # Reply to an EPMD request. A NAMES (0x73) / DUMP (0x64) query is answered
    # with an empty node list (just the 4-byte big-endian length == 0); a
    # PORT_PLEASE2 (0x78) for an unknown name is answered with a 0x78 byte
    # (the "no such node" marker). This keeps a rabbitmq/epmd probe in the
    # right (non-HTTP) face instead of being served an Apache panel (issue #451/#458).
    if not raw:
        return b''
    opcode = raw[0]
    if opcode == 0x78:  # PORT_PLEASE2 -> unknown name
        return bytes([0x78])
    # NAMES / DUMP / anything else: empty node list (length 0).
    return (0).to_bytes(4, 'big')


# Server-first protocol replies to the client's post-greeting auth frame.
def _ftp_respond(raw: bytes, bot_ip: str) -> bytes:
    text = raw.decode('latin-1', errors='replace')
    if text.upper().startswith('PASS'):
        return b'530 Login incorrect.\r\n'
    if text.upper().startswith('USER'):
        return b'331 Please specify the password.\r\n'
    if text.upper().startswith('QUIT'):
        return b'221 Goodbye.\r\n'
    return b'220 Please login with USER and PASS.\r\n'


def _smtp_respond(raw: bytes, bot_ip: str) -> bytes:
    text = raw.decode('latin-1', errors='replace')
    if 'AUTH' in text.upper():
        return b'535 5.7.8 Error: authentication failed\r\n'
    if text.upper().startswith('QUIT'):
        return b'221 2.0.0 Bye\r\n'
    return b'250 2.0.0 OK\r\n'


def _pop3_respond(raw: bytes, bot_ip: str) -> bytes:
    text = raw.decode('latin-1', errors='replace')
    if text.upper().startswith('PASS'):
        return b'-ERR authentication failed\r\n'
    if text.upper().startswith('USER'):
        return b'+OK\r\n'
    if text.upper().startswith('QUIT'):
        return b'+OK Bye\r\n'
    return b'+OK\r\n'


def _imap_respond(raw: bytes, bot_ip: str) -> bytes:
    text = raw.decode('latin-1', errors='replace')
    if 'LOGIN' in text.upper():
        return b'a NO [AUTHENTICATIONFAILED] Authentication failed.\r\n'
    return b'a OK\r\n'


# MySQL/MSSQL/AMQP/Oracle: after the server-first greeting the client drives
# the handshake; we do not need to complete it for capture purposes, so respond
# with nothing (close). Kept as an explicit no-op for clarity.
def _greeting_only_respond(raw: bytes, bot_ip: str) -> bytes:
    return b''


def _no_reply(raw: bytes, bot_ip: str) -> bytes:
    """Explicit empty reply (e.g. SSH, where client.py drives credential capture)."""
    return b''


# ---------------------------------------------------------------------------
# Registry construction.
#
# We build it from the canonical port tables so there is exactly one place that
# "knows" which ports are faces. PRIVILEGED_PORT_REDIRECTS gives us the
# external->bound mapping; DEFAULT_TOP_PORTS gives the always-bound high ports
# (MySQL/Postgres/Redis/Mongo/...). A face's registry key is its EXTERNAL port
# (the attacker-visible one); the client resolves listen_port->external_port.
#
# INVARIANT: every non-HTTP protocol port in DEFAULT_TOP_PORTS MUST have a
# complete FaceSpec here, otherwise it falls through to the HTTP handler and is
# served a fake admin panel (issue #440/#454/#492). Conversely, a port that is
# registered here MUST NOT also be treated as an HTTP port (see is_http_port /
# _is_non_http_overlap below). The two sets must be disjoint.
# ---------------------------------------------------------------------------

# External port -> (detected_id, direction, greeting-fn, respond-fn,
# capture_creds, extract_creds-or-None). Only non-HTTP faces are listed; HTTP
# ports resolve to None and fall through to the existing HTTP path.
_FACE_DEFS: dict[int, tuple] = {
    22: (
        SSH_CLIENT,
        SERVER_FIRST,
        _ssh_greeting,
        None,
        True,
        None,
    ),  # SSH: client.py drives after greeting
    23: (UNKNOWN_TELNET, SERVER_FIRST, _telnet_greeting, _telnet_respond, True, None),
    21: (UNKNOWN_NON_HTTP, SERVER_FIRST, _ftp_greeting, _ftp_respond, True, None),
    25: (UNKNOWN_NON_HTTP, SERVER_FIRST, _smtp_greeting, _smtp_respond, False, None),
    110: (UNKNOWN_NON_HTTP, SERVER_FIRST, _pop3_greeting, _pop3_respond, True, None),
    143: (UNKNOWN_NON_HTTP, SERVER_FIRST, _imap_greeting, _imap_respond, True, None),
    5900: (UNKNOWN_VNC, SERVER_FIRST, _vnc_greeting, _vnc_respond, False, None),
    5901: (UNKNOWN_VNC, SERVER_FIRST, _vnc_greeting, _vnc_respond, False, None),
    3389: (UNKNOWN_RDP, SERVER_FIRST, _rdp_greeting, _rdp_respond, True, None),
    1433: (UNKNOWN_NON_HTTP, SERVER_FIRST, _mssql_greeting, _greeting_only_respond, True, None),
    3306: (UNKNOWN_NON_HTTP, SERVER_FIRST, _mysql_greeting, _greeting_only_respond, True, None),
    5672: (UNKNOWN_NON_HTTP, SERVER_FIRST, _amqp_greeting, _greeting_only_respond, False, None),
    # Oracle TNS (issue #440): server-first Refuse packet greeting.
    1521: (UNKNOWN_NON_HTTP, SERVER_FIRST, _oracle_greeting, _oracle_respond, False, None),
    # client-first faces (high ports, no privilege redirect needed)
    6379: (UNKNOWN_REDIS, CLIENT_FIRST, lambda: b'', _redis_respond, True, _redis_extract),
    27017: (UNKNOWN_MONGODB, CLIENT_FIRST, lambda: b'', _mongo_respond, False, None),
    11211: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _memcached_respond, False, None),
    2181: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _zookeeper_respond, False, None),
    5432: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _postgres_respond, False, None),
    9200: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _elasticsearch_respond, False, None),
    15672: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _elasticsearch_respond, False, None),
    # NFS / rpcbind (issue #454/#457): client-first RPC reply.
    2049: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _nfs_respond, False, None),
    # EPMD (Erlang Port Mapper, rabbitmq companion; issue #451/#458): client-first.
    4369: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _epmd_respond, False, None),
}


def _build_registry() -> dict[int, FaceSpec]:
    """Compose FACE_REGISTRY from the canonical port tables."""
    reg: dict[int, FaceSpec] = {}
    for ext_port, (
        detected_id,
        direction,
        greet_fn,
        respond_fn,
        cap,
        extract,
    ) in _FACE_DEFS.items():
        # The SSH face reuses the SSH banner greeting; its respond path is the
        # SSH binary credential parse, handled specially in client.py, so we set
        # an empty respond here (client.py drives SSH after the greeting).
        if ext_port == 22:
            name = 'ssh'
            respond = _no_reply  # SSH credential capture is driven in client.py
        else:
            name = _port_name(ext_port)
            respond = respond_fn or _no_reply
        reg[ext_port] = FaceSpec(
            name=name,
            detected_id=detected_id,
            direction=direction,
            greeting=greet_fn(),
            respond=respond,
            capture_creds=cap,
            extract_creds=extract,
        )
    return reg


def _port_name(ext_port: int) -> str:
    """Friendly protocol name for an external port (display only)."""
    from manyfaced.common import status as _status  # noqa: F401

    names = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        110: 'pop3',
        143: 'imap',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgres',
        5900: 'vnc',
        5901: 'vnc',
        6379: 'redis',
        11211: 'memcached',
        1433: 'mssql',
        1521: 'oracle',
        2181: 'zookeeper',
        27017: 'mongodb',
        5672: 'amqp',
        9200: 'elasticsearch',
        15672: 'rabbitmq',
        2049: 'nfs',
        4369: 'epmd',
    }
    return names.get(ext_port, 'unknown')


# The module-level singleton registry, keyed by EXTERNAL (attacker-visible) port.
FACE_REGISTRY: dict[int, FaceSpec] = _build_registry()


def get_face(listen_port: int | None) -> FaceSpec | None:
    """Resolve a face spec from the port the client connected to.

    Args:
        listen_port: the bound (high) port the honeypot accepted on.

    Returns:
        The matching ``FaceSpec`` (by external port) or ``None`` for HTTP /
        unknown ports (caller falls through to the HTTP path).
    """
    if not listen_port:
        return None
    ext = _ports.external_port(listen_port)
    return FACE_REGISTRY.get(int(ext))


def is_http_port(listen_port: int | None) -> bool:
    """True when the port is an HTTP(S) face that the existing HTTP path owns.

    A port registered in the non-HTTP FACE_REGISTRY is NEVER an HTTP port, even
    if its external number would otherwise resemble a web port. This closes the
    double-ownership hole where a non-HTTP face (e.g. RDP 3389, Postgres 5432)
    could be simultaneously claimed by the HTTP handler when the port also
    appears in ``DEFAULT_TOP_PORTS`` (issues #460/#487). When the registry owns
    the port, the non-HTTP path always wins.
    """
    if not listen_port:
        return False
    # Non-HTTP faces always win: never treat a registered face port as HTTP.
    if get_face(listen_port) is not None:
        return False
    ext = _ports.external_port(listen_port)
    return int(ext) in (80, 443, 8080, 8443, 5000, 7001, 7002, 8888, 9090)


def _is_non_http_overlap() -> list[int]:
    """Return non-HTTP registry ports that ALSO appear in ``DEFAULT_TOP_PORTS``.

    Such overlap is a latent dual-ownership bug (issue #460/#487): the port is
    bound by both the generic HTTP listener and the non-HTTP face. The dispatch
    in ``client.py`` already gives the non-HTTP face precedence, so this is
    informational — it lets operators/CI assert no new overlap is introduced.
    """
    return sorted(set(_FACE_DEFS) & set(_ports.DEFAULT_TOP_PORTS))


# ---------------------------------------------------------------------------
# UDP face registry (issue #388)
#
# SIP (5060) and SNMP (161) are the #3 / top-10 most-targeted protocols in the
# Jan-2026 honeypot landscape yet are UDP, so they were invisible until the UDP
# transport was added. The TCP FACE_REGISTRY above is untouched; UDP faces live
# in their own registry keyed by external UDP port and are dispatched by the
# UDP listener in client.py. They reuse the same FaceSpec shape (server-first
# greet on accept / client-first reply to each datagram). For UDP, "greeting"
# is unused (no connection prelude) and "respond" is called per datagram.
# ---------------------------------------------------------------------------

from manyfaced.common.status import UNKNOWN_SIP, UNKNOWN_SNMP  # noqa: E402


def _sip_respond(raw: bytes, bot_ip: str) -> bytes:
    """Answer a SIP datagram with a minimal but plausible SIP reply.

    - OPTIONS  -> 200 OK (with Allow + a Server header naming a common PBX)
    - REGISTER -> 401 Unauthorized (challenges with a WWW-Authenticate so
                  credential-stuffing bots keep talking / reveal digests)
    - INVITE   -> 100 Trying then 401 (don't complete the call; toll-fraud
                  destination is logged by the capture layer, not answered)
    - anything else -> 200 OK
    """
    text = raw.decode('latin-1', errors='replace')
    method = text.split(None, 1)[0].upper() if text.strip() else ''
    server = b'Server: Asterisk PBX 18.23.0\r\n'
    if method == 'REGISTER':
        return (
            b'SIP/2.0 401 Unauthorized\r\n'
            + server
            + b'WWW-Authenticate: Digest realm="manyfaced", nonce="a1b2c3d4e5", algorithm=MD5\r\n'
            b'Content-Length: 0\r\n\r\n'
        )
    if method == 'INVITE':
        return b'SIP/2.0 100 Trying\r\n' + server + b'Content-Length: 0\r\n\r\n'
    # OPTIONS / SUBSCRIBE / NOTIFY / default
    allow = b'Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, SUBSCRIBE, INFO\r\n'
    return b'SIP/2.0 200 OK\r\n' + server + allow + b'Content-Length: 0\r\n\r\n'


def _snmp_respond(raw: bytes, bot_ip: str) -> bytes:
    """Answer an SNMP GET/GETNEXT for the `public` community with sysDescr.

    Returns a valid SNMPv1 response identifying as a common router/switch so
    recon scanners get a believable device fingerprint. For non-`public`
    communities or unparseable PDUs, returns an empty reply (stay quiet).
    """
    if not raw.startswith(b'\x30'):
        return b''
    try:
        i = 1  # skip SEQUENCE tag
        i += 1  # length
        if i >= len(raw):
            return b''
        if raw[i : i + 3] != b'\x02\x01\x00' and raw[i : i + 3] != b'\x02\x01\x01':
            return b''
        i += 3
        if raw[i] != 0x04:  # OCTET STRING (community)
            return b''
        i += 1
        clen = raw[i]
        i += 1
        community = raw[i : i + clen]
        if community != b'public':
            return b''
    except IndexError:
        return b''

    sysdescr = b'Manyfaced Router Software, Version 15.1(4)M, RELEASE SOFTWARE'
    oid = bytes([0x06, 0x09, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    val = bytes([0x04]) + bytes([len(sysdescr)]) + sysdescr
    varbind = bytes([0x30, len(oid) + len(val)]) + oid + val
    varbind_list = bytes([0x30, len(varbind)]) + varbind
    req_id = raw[3:6] if len(raw) > 5 else b'\x01\x00\x00'
    pdu = (
        bytes([0xA2])
        + bytes([2 + 3 + 3 + len(varbind_list)])
        + req_id
        + b'\x02\x01\x00'  # error-status 0
        + b'\x02\x01\x00'  # error-index 0
        + varbind_list
    )
    resp = (
        bytes([0x30])
        + bytes([len(pdu)])
        + b'\x02\x01\x00'
        + bytes([0x04, len(community)])
        + community
        + pdu
    )
    return resp


# UDP face table: external_udp_port -> (detected_id, name, respond_fn, capture_creds)
_UDP_FACE_DEFS: dict[int, tuple] = {
    5060: (UNKNOWN_SIP, 'sip', _sip_respond, True),
    161: (UNKNOWN_SNMP, 'snmp', _snmp_respond, False),
}


def _build_udp_registry() -> dict[int, FaceSpec]:
    """Compose UDP_FACE_REGISTRY from the canonical UDP port tables."""
    reg: dict[int, FaceSpec] = {}
    for ext_port, (detected_id, name, respond_fn, cap) in _UDP_FACE_DEFS.items():
        reg[ext_port] = FaceSpec(
            name=name,
            detected_id=detected_id,
            direction=CLIENT_FIRST,
            greeting=b'',
            respond=respond_fn,
            capture_creds=cap,
        )
    return reg


UDP_FACE_REGISTRY: dict[int, FaceSpec] = _build_udp_registry()


def get_udp_face(listen_port: int | None) -> FaceSpec | None:
    """Resolve a UDP face spec from the port the datagram arrived on.

    Args:
        listen_port: the bound (high) UDP port the honeypot accepted on.

    Returns:
        The matching UDP ``FaceSpec`` (by external port) or ``None`` if the port
        is not a UDP face.
    """
    if not listen_port:
        return None
    ext = _ports.external_udp_port(listen_port)
    return UDP_FACE_REGISTRY.get(int(ext))


def is_udp_port(listen_port: int | None) -> bool:
    """True when ``listen_port`` is a UDP face the UDP listener owns."""
    if not listen_port:
        return False
    ext = _ports.external_udp_port(listen_port)
    return int(ext) in _UDP_FACE_DEFS
