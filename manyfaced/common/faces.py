"""Non-HTTP face registry — the single source of truth for non-HTTP faces.

This module replaces the byte-sniffing-first dispatch model (issue #377). The
old client path blocked on ``receive_timeout`` *before* producing any response,
so:

* **server-first** faces (the server greets before the client speaks — SSH,
  FTP, Telnet, SMTP, POP3, IMAP, VNC, RDP, MySQL, MSSQL, AMQP) could never be
  detected from client bytes (there are none at greeting time). They need to be
  resolved by the **port** the client connected to, and greeted *on accept*.
* **client-first** faces (Redis, Memcached, MongoDB, Zookeeper, Postgres,
  Elasticsearch) can be detected from client bytes, but the read→respond→send
  loop still has to actually fire.

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


def _mongo_respond(raw: bytes, bot_ip: str) -> bytes:
    return _mongo_resp(raw, bot_ip) or b''


def _telnet_respond(raw: bytes, bot_ip: str) -> bytes:
    return _telnet_resp(raw, bot_ip) or b''


def _rdp_respond(raw: bytes, bot_ip: str) -> bytes:
    return _rdp_resp(raw, bot_ip) or b''


def _vnc_respond(raw: bytes, bot_ip: str) -> bytes:
    return _vnc_resp(raw, bot_ip) or b''


# Memcached / Zookeeper / Postgres / Elasticsearch respond functions live in
# dedicated handlers; until those exist we synthesize a protocol-correct reply
# inline so the face at least answers. (See issue #377 sub-tasks for fuller
# emulation.)
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


# MySQL/MSSQL/AMQP: after the server-first greeting the client drives the
# handshake; we do not need to complete it for capture purposes, so respond
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
# ---------------------------------------------------------------------------

# External port -> (name, detected_id, direction, greeting-fn, respond-fn,
# capture_creds). Only non-HTTP faces are listed; HTTP ports resolve to None
# and fall through to the existing HTTP path.
_FACE_DEFS: dict[int, tuple] = {
    22: (
        SSH_CLIENT,
        SERVER_FIRST,
        _ssh_greeting,
        None,
        True,
    ),  # SSH: client.py drives after greeting
    23: (UNKNOWN_TELNET, SERVER_FIRST, _telnet_greeting, _telnet_respond, True),
    21: (UNKNOWN_NON_HTTP, SERVER_FIRST, _ftp_greeting, _ftp_respond, True),
    25: (UNKNOWN_NON_HTTP, SERVER_FIRST, _smtp_greeting, _smtp_respond, False),
    110: (UNKNOWN_NON_HTTP, SERVER_FIRST, _pop3_greeting, _pop3_respond, True),
    143: (UNKNOWN_NON_HTTP, SERVER_FIRST, _imap_greeting, _imap_respond, True),
    5900: (UNKNOWN_VNC, SERVER_FIRST, _vnc_greeting, _vnc_respond, False),
    5901: (UNKNOWN_VNC, SERVER_FIRST, _vnc_greeting, _vnc_respond, False),
    3389: (UNKNOWN_RDP, SERVER_FIRST, _rdp_greeting, _rdp_respond, True),
    1433: (UNKNOWN_NON_HTTP, SERVER_FIRST, _mssql_greeting, _greeting_only_respond, True),
    3306: (UNKNOWN_NON_HTTP, SERVER_FIRST, _mysql_greeting, _greeting_only_respond, True),
    5672: (UNKNOWN_NON_HTTP, SERVER_FIRST, _amqp_greeting, _greeting_only_respond, False),
    # client-first faces (high ports, no privilege redirect needed)
    6379: (UNKNOWN_REDIS, CLIENT_FIRST, lambda: b'', _redis_respond, True),
    27017: (UNKNOWN_MONGODB, CLIENT_FIRST, lambda: b'', _mongo_respond, False),
    11211: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _memcached_respond, False),
    2181: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _zookeeper_respond, False),
    5432: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _postgres_respond, False),
    9200: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _elasticsearch_respond, False),
    15672: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _elasticsearch_respond, False),
}


def _build_registry() -> dict[int, FaceSpec]:
    """Compose FACE_REGISTRY from the canonical port tables."""
    reg: dict[int, FaceSpec] = {}
    for ext_port, (detected_id, direction, greet_fn, respond_fn, cap) in _FACE_DEFS.items():
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
        2181: 'zookeeper',
        27017: 'mongodb',
        5672: 'amqp',
        9200: 'elasticsearch',
        15672: 'rabbitmq',
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
    """True when the port is an HTTP(S) face that the existing HTTP path owns."""
    if not listen_port:
        return False
    ext = _ports.external_port(listen_port)
    return int(ext) in (80, 443, 8080, 8443, 5000, 7001, 7002, 8888, 9090)
