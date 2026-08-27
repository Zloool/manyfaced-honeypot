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
import os
import struct
from dataclasses import dataclass
from typing import Callable

from manyfaced.common import ports as _ports
from manyfaced.common.status import (
    SSH_CLIENT,
    BEANSTALKD,
    UNKNOWN_AMQP,
    UNKNOWN_DNS,
    UNKNOWN_EPMD,
    UNKNOWN_MEMCACHED,
    UNKNOWN_MONGODB,
    UNKNOWN_MSSQL,
    UNKNOWN_MYSQL,
    UNKNOWN_NON_HTTP,
    UNKNOWN_RDP,
    UNKNOWN_REDIS,
    UNKNOWN_SMB,
    UNKNOWN_TELNET,
    UNKNOWN_VNC,
    UNKNOWN_ZOOKEEPER,
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
    extract_telnet_credentials,
)
from manyfaced.handlers.rdp_handler import (
    generate_rdp_response as _rdp_resp,
    extract_rdp_credentials,
)
from manyfaced.handlers.vnc_handler import generate_vnc_response as _vnc_resp
from manyfaced.client.cred_extractors import (
    extract_pop3_credentials,
    extract_imap_credentials,
    extract_ftp_credentials,
    extract_mysql_credentials,
    extract_mssql_credentials,
)

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
    extract_creds: Callable[[bytes], str | None] | None = None


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


def _dns_greeting() -> bytes:
    # DNS is client-first (RFC 1035) — the client sends a query, the server
    # answers. Nothing is sent on accept (issue #600). The reply is produced in
    # _dns_respond.
    return b''


def _msrpc_greeting() -> bytes:
    # MSRPC (DCE/RPC, epmapper) is client-first: the client sends a BIND
    # PDU, the server answers. Nothing is sent on accept (issue #600). The
    # reply is produced in _msrpc_respond.
    return b''


def _netbios_greeting() -> bytes:
    # NetBIOS Session Service (NBT) is client-first: the client sends a
    # Session Request, the server answers. Nothing is sent on accept
    # (issue #600). The reply is produced in _netbios_respond.
    return b''


def _smb_greeting() -> bytes:
    # SMB (TCP/445) is client-first: the client sends a Negotiate Protocol
    # request, the server answers with a Negotiate Protocol response. Nothing
    # is sent on accept (issue #600). A minimal, protocol-shaped SMB1
    # Negotiate response below keeps NBTSESSION/SMB scanners out of the HTTP
    # face; full dialect negotiation is out of scope.
    return b''


def _imaps_greeting() -> bytes:
    # IMAPS (993): behave like a real IMAP server that offers STARTTLS instead
    # of forcing TLS on connect. The old static TLS ServerHello (issue #600)
    # dropped every plaintext client that opened with CAPA/USER before STARTTLS,
    # so no login dialogue was ever captured (issue #625). We now greet in
    # plaintext; `_imaps_respond` answers a TLS ClientHello with a
    # handshake-failure alert, preserving the "real SSL service" impression for
    # TLS-expecting scanners while capturing plaintext credential attempts.
    crlf = bytes([13, 10])
    return b'* OK IMAP4rev1 Server ready (STARTTLS LOGIN)' + crlf


def _pop3s_greeting() -> bytes:
    # POP3S (995): same rationale as IMAPS (issue #625) — greet in plaintext and
    # let `_pop3s_respond` handle a TLS ClientHello, instead of forcing TLS and
    # dropping plaintext USER/PASS clients.
    crlf = bytes([13, 10])
    return b'+OK POP3 server ready (STLS)' + crlf


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


# Memcached text-protocol STAT block returned for `stats` (issue #648). The
# honeypot is stateless, so sizes/counters are nominal constants.
_MEMCACHED_STATS: tuple[tuple[str, str], ...] = (
    ('pid', '1'),
    ('uptime', '1'),
    ('time', '1'),
    ('version', '1.6.21'),
    ('libevent', '2.1.12-stable'),
    ('pointer_size', '64'),
    ('curr_items', '0'),
    ('total_items', '0'),
    ('bytes', '0'),
    ('cmd_get', '0'),
    ('cmd_set', '0'),
    ('get_hits', '0'),
    ('get_misses', '0'),
    ('evictions', '0'),
    ('limit_maxbytes', '67108864'),
    ('accepting_conns', '1'),
    ('listen_disabled_num', '0'),
    ('threads', '4'),
    ('conn_yields', '0'),
    ('bytes_read', '0'),
    ('bytes_written', '0'),
    ('rusage_user', '0.000000'),
    ('rusage_system', '0.000000'),
    ('curr_connections', '1'),
    ('total_connections', '1'),
    ('connection_structures', '1'),
    ('reclaimed', '0'),
)


_CRLF = bytes((13, 10))


def _memcached_binary_reply(raw: bytes) -> bytes:
    # Minimal valid binary-protocol response for a client-first frame whose
    # request magic is 0x80 (issue #648). Echoes opcode + opaque with an empty
    # body and success status so a binary client does not desync. The version
    # opcode (0x0b) carries the emulated server name as its body.
    if len(raw) < 24:
        return b''
    opcode = raw[1]
    opaque = raw[12:16]
    body = b'manyfaced' if opcode == 0x0B else b''
    return b''.join(
        [
            bytes([0x81, opcode, 0, 0, 0, 0]),
            bytes([0, 0]),  # status: success
            len(body).to_bytes(4, 'big'),
            opaque,
            bytes([0]) * 8,  # CAS
            body,
        ]
    )


def _memcached_respond(raw: bytes, bot_ip: str) -> bytes:
    # Client-first responder for the Memcached text + binary protocols.
    # Previously only `version` returned a real line and everything else got a
    # bare `END`, so `stats`/scanners saw an empty server (issue #648).
    # Binary-protocol requests (magic 0x80) get a valid binary reply.
    if raw[:1] == bytes([0x80]):
        return _memcached_binary_reply(raw)
    text = raw.decode('latin-1', errors='replace')
    out: list[bytes] = []
    for line in text.splitlines():
        cmd = line.strip().lower()
        if not cmd:
            continue
        verb = cmd.split()[0]
        if verb == 'version':
            out.append(b'VERSION 1.6.21 (manyfaced)')
        elif verb == 'stats':
            for key, val in _MEMCACHED_STATS:
                out.append(f'STAT {key} {val}'.encode())
            out.append(b'END')
        elif verb in ('get', 'gets', 'gat', 'gats'):
            out.append(b'END')  # stateless: no values stored
        elif verb in ('set', 'add', 'replace', 'append', 'prepend', 'cas'):
            out.append(b'STORED')
        elif verb == 'delete':
            out.append(b'DELETED')
        elif verb in ('incr', 'decr'):
            out.append(b'0')
        elif verb == 'touch':
            out.append(b'TOUCHED')
        elif verb == 'flush_all':
            out.append(b'OK')
        elif verb == 'verbosity':
            out.append(b'OK')
        elif verb == 'quit':
            return b''  # close: no reply
        else:
            out.append(b'END')
    if not out:
        return b'END' + _CRLF
    return _CRLF.join(out) + _CRLF


# ZooKeeper four-letter-word (4LW) admin commands are sent as a bare 4-byte
# ASCII line over TCP and answered with a readable text reply (issue #497/#490).
_ZK_4LW = frozenset(
    {
        'ruok',
        'stat',
        'srvr',
        'dump',
        'mntr',
        'conf',
        'envi',
        'cons',
        'isro',
        'wchs',
        'wchc',
        'wchp',
        'crst',
        'gtmk',
        'stmk',
        'dirs',
        'srst',
    }
)


def _zk_stat_block() -> bytes:
    return (
        b'Zookeeper version: 3.8.4-9316c2a7a97e1666d8f4593f34dd6fc36ecc436c, '
        b'built on 2024-02-12 22:16 UTC\r\n'
        b'Clients:\r\n\r\n'
        b'Latency min/avg/max: 0/0.0/0\r\n'
        b'Received: 1\r\n'
        b'Sent: 0\r\n'
        b'Connections: 1\r\n'
        b'Outstanding: 0\r\n'
        b'Zxid: 0x0\r\n'
        b'Mode: standalone\r\n'
        b'Node count: 5\r\n'
    )


def _zookeeper_respond(raw: bytes, bot_ip: str) -> bytes:
    """Reply to a ZooKeeper probe with a protocol-shaped answer (issue #497).

    ZooKeeper clients speak either the four-letter-word (4LW) admin commands
    over a bare TCP line (answered with readable text -- ``ruok`` -> ``imok``),
    or the binary wire protocol (a 4-byte length-prefixed frame). We answer the
    4LW commands with the correct text reply and the binary connect request with
    a minimal connect response.
    """
    # 4LW commands: the first 4 bytes are a lowercase ASCII command word.
    if len(raw) >= 4:
        head = raw[:4]
        try:
            cmd = head.decode('ascii').strip().lower()
        except UnicodeDecodeError:
            cmd = ''
        if cmd in _ZK_4LW:
            if cmd == 'ruok':
                return b'imok'
            if cmd in ('stat', 'srvr'):
                return _zk_stat_block()
            if cmd == 'dump':
                return b'SessionTracker dump:\r\nSession Sets (0):\r\nephemeral nodes dump:\r\n'
            if cmd == 'isro':
                return b'rw'
            if cmd == 'conf':
                return (
                    b'clientPort=2181\r\ndataDir=/data/version-2\r\n'
                    b'tickTime=2000\r\nmaxClientCnxns=60\r\n'
                    b'minSessionTimeout=4000\r\nmaxSessionTimeout=40000\r\n'
                    b'serverId=0\r\n'
                )
            if cmd == 'envi':
                return (
                    b'Environment:\r\nzookeeper.version=3.8.4\r\n'
                    b'host.name=zookeeper\r\njava.version=17.0.10\r\n'
                )
            if cmd == 'mntr':
                return (
                    b'zk_version\t3.8.4\r\nzk_server_state\tstandalone\r\n'
                    b'zk_num_alive_connections\t1\r\nzk_znode_count\t5\r\n'
                )
            # Other recognised 4LW words: mirror real ZK's terse behaviour.
            return b'imok'
    # Binary wire protocol: reply to a connect request with a connect response.
    if len(raw) >= 4:
        return b'\x00\x00\x00\x00' + raw[4:8] + b'\x00\x00\x00\x00'
    return b'\x00\x00\x00\x00'


def _postgres_respond(raw: bytes, bot_ip: str) -> bytes:
    # Be version-aware where cheap (#499): a Postgres server first receives
    # either a `StartupMessage` or an `SSLRequest`
    # (\x00\x00\x00\x08\x04\xd2\x16\x2f). For an SSLRequest we MUST answer
    # with a single 'N' (TLS not supported) or 'S' before the client proceeds;
    # otherwise libpq blocks waiting for the flag byte. For a StartupMessage we
    # answer with an AuthRequest (MD5, type='R', len=12, method=5) plus the
    # mandatory 4-byte salt = 13 bytes total, so libpq can drive the MD5
    # exchange. The reply is protocol-correct; credentials are not captured
    # here (out of scope for this fidelity fix).
    if len(raw) >= 8 and raw[:4] == (8).to_bytes(4, 'big'):
        code = struct.unpack('>i', raw[4:8])[0]
        if code == 80877103:  # SSLRequest
            return b'N'
    salt = os.urandom(4)
    return b'R' + (12).to_bytes(4, 'big') + (5).to_bytes(4, 'big') + salt


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


# MySQL: the server greeting (seq 0) is sent by `_mysql_greeting`. A real MySQL
# client then sends a HandshakeResponse41 (seq 1) and waits for the server's
# reply (seq 2) — an OK / ERR / AuthMore packet. Replying with nothing (the old
# `_greeting_only_respond`) made the client hang until BOT_TIMEOUT. We answer
# with a wire-valid ERR_Packet (Access denied) so the handshake completes and
# the client closes cleanly. Credentials are intentionally NOT captured here
# (out of scope for this fidelity fix); the reply is protocol-correct only.
def _mysql_respond(raw: bytes, bot_ip: str) -> bytes:
    err_code = 1045  # ER_ACCESS_DENIED_ERROR
    sql_state = b'28000'
    message = b'Access denied for user'
    payload = b'\xff' + struct.pack('<H', err_code) + b'#' + sql_state + message
    # 3-byte length (LE) + 1-byte sequence id = 2 (greeting 0, client resp 1).
    return len(payload).to_bytes(3, 'little') + b'\x02' + payload


# MSSQL (TDS): after the Prelogin greeting, a real client sends either a second
# Prelogin packet or a TDS Login (type 0x10). We answer the client's first
# post-greeting frame -- whether it is a Prelogin ACK or a Login -- with a
# wire-valid TDS packet so the handshake does not desync and drop (issue #647).
# Credentials are intentionally NOT captured here; the reply is protocol-correct.
def _mssql_respond(raw: bytes, bot_ip: str) -> bytes:
    if len(raw) < 1:
        return b''
    pkt_type = raw[0]
    # Login (0x10) or Prelogin (0x12): acknowledge with a Prelogin-style reply
    # (type 0x12, status 0x01, spare 0x00 0x00, length 0x00 0x08).
    if pkt_type in (0x10, 0x12):
        return b'\x12\x01\x00\x08\x00\x00\x00\x00'
    # SSPI/empty: keep the connection alive with a tiny Prelogin ACK.
    return b'\x12\x01\x00\x08\x00\x00\x00\x00'


def _dns_respond(raw: bytes, bot_ip: str) -> bytes:
    # DNS-over-TCP (RFC 1035): a 2-byte big-endian length prefix followed by
    # the DNS message. Answer a query with a minimal valid response: echo the
    # 16-bit transaction id + flags (QR=1, AA=1, RD copied) and the question
    # count, with zero answer/authority/additional records so the scanner sees
    # a protocol-shaped DNS reply instead of an HTTP 404 (issue #600).
    if len(raw) < 2:
        return b''
    msg_len = struct.unpack('>H', raw[:2])[0]
    body = raw[2 : 2 + msg_len] if msg_len else raw[2:]
    if len(body) < 12:
        return b''
    txn_id = body[:2]
    flags = struct.pack('>H', 0x8180)  # QR=1, AA=1, RD=1, RA=1, no error
    qdcount = body[4:6]
    # Respond with the same question count, zero answers.
    header = txn_id + flags + qdcount + b'\x00\x00\x00\x00\x00\x00'
    # Echo the question section verbatim so the reply parses.
    question = body[12:]
    out = header + question
    return struct.pack('>H', len(out)) + out


def _msrpc_respond(raw: bytes, bot_ip: str) -> bytes:
    # MSRPC (DCE/RPC) epmapper: reply to a BIND PDU (version 4, little-endian)
    # with an ACK. A minimal bind_ack keeps RPC endpoint-mapper scanners in the
    # right (non-HTTP) face (issue #600). We echo the minor version and produce
    # a structurally valid PDU so the client parses it instead of falling to
    # the HTTP admin panel.
    if len(raw) < 10:
        return b''
    # PDU type is raw[2]; 0x0b = bind, 0x00 = request.
    minor = raw[4] if len(raw) > 4 else 0
    # Build a minimal bind_ack: version 5, minor, PDU type 0x0c (bind_ack),
    # little-endian, flags 0x03, data repr 0x10, frag len 0x001c, auth len 0,
    # call id echoed.
    call_id = raw[12:16] if len(raw) >= 16 else b'\x00\x00\x00\x00'
    pkt = (
        b'\x05'
        + bytes([minor])
        + b'\x0c'  # bind_ack
        + b'\x03'  # flags
        + b'\x10\x00\x00'  # data representation (LE, ASCII)
        + b'\x1c\x00'  # frag length 28
        + b'\x00\x00'  # auth length 0
        + call_id
        + b'\x10\x00'  # max xmit frag
        + b'\x10\x00'  # max recv frag
        + b'\x00\x00\x00\x00'  # assoc group
        + b'\x00'  # num results 0
    )
    return pkt


def _netbios_respond(raw: bytes, bot_ip: str) -> bytes:
    # NetBIOS Session Service (RFC 1002) over TCP/139. The client sends a
    # Session Request (type 0x81); we answer with a Positive Session Response
    # (type 0x82, flags 0, length 0) — the same byte the existing SMB/NetBIOS
    # face uses. Keeps NetBIOS scanners out of the HTTP face (issue #600).
    if not raw:
        return b''
    if raw[0] == 0x81:  # Session Request
        return b'\x82\x00\x00\x00'
    # For any other NBT message (e.g. session message 0x00) just ack with a
    # positive session response so the connection stays protocol-shaped.
    return b'\x82\x00\x00\x00'


def _smb_respond(raw: bytes, bot_ip: str) -> bytes:
    # SMB (TCP/445) Negotiate Protocol request -> Negotiate Protocol response.
    # A full dialect negotiation is out of scope, but we return a minimal SMB1
    # Negotiate response wrapped in a NetBIOS Session Service header so the
    # scanner sees a protocol-shaped SMB reply rather than an HTTP 404
    # (issue #600). We always reply (do NOT key off the binary SMB signature
    # \xffSMB) because the dispatch decodes the binary frame to str and back
    # (client.py:409), which corrupts non-ASCII bytes — so input parsing is
    # unreliable, but every SMB connection over 445 begins with a client
    # Negotiate request we can safely answer.
    smb = (
        b'\xffSMB'
        + b'\x72'  # Negotiate command
        + b'\x00\x00\x00\x00'  # status NT_STATUS_SUCCESS
        + b'\x00'  # flags
        + b'\x00\x00'  # flags2
        + b'\x00\x00'  # PID high
        + b'\x00\x00\x00\x00\x00\x00'  # signature
        + b'\x00\x00'  # reserved
        + b'\x00\x00'  # tid
        + b'\x00\x00'  # pid
        + b'\x00\x00'  # uid
        + b'\x00\x00'  # mid
        + b'\x00\x00'  # word count (0)
        + b'\x00\x00'  # byte count 0
    )
    # NetBIOS Session Service header: type 0x00 (session message), flags 0,
    # 2-byte big-endian length of the SMB payload that follows.
    nbt_header = b'\x00\x00' + struct.pack('>H', len(smb))
    return nbt_header + smb


def _no_reply(raw: bytes, bot_ip: str) -> bytes:
    """Explicit empty reply (e.g. SSH, where client.py drives credential capture)."""
    return b''


# IMAPS (993) / POP3S (995): the greeting is now plaintext IMAP/POP3 (issue
# #625). After the client sends its first frame, branch on what it actually
# sent: a TLS ClientHello (a real IMAPS/POP3S client that skipped the
# plaintext CAPA/STARTTLS dance) gets a TLS handshake-failure alert so it
# closes cleanly and the attempt is recorded; anything else is treated as an
# IMAP/POP3 command and handled by the same responders the plaintext IMAP(143)/
# POP3(110) faces use, so USER/PASS (and thus credentials) are captured.
# Building the alert by hand (no CRLF in a TLS record) keeps the bytes
# binary-safe: a TLSv1.2 record, alert content-type (0x15), level 2 (fatal),
# description 40 (handshake_failure), 2-byte length.
_HANDSHAKE_FAILURE_ALERT = b'\x15\x03\x03\x00\x02\x02\x28'


def _imaps_respond(raw: bytes, bot_ip: str) -> bytes:
    if raw[:2] == b'\x16\x03':
        return _HANDSHAKE_FAILURE_ALERT
    return _imap_respond(raw, bot_ip)


def _pop3s_respond(raw: bytes, bot_ip: str) -> bytes:
    if raw[:2] == b'\x16\x03':
        return _HANDSHAKE_FAILURE_ALERT
    return _pop3_respond(raw, bot_ip)


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


# Beanstalkd work-queue (issue #624): ports 11300-11311 are in
# DEFAULT_TOP_PORTS and labeled Beanstalkd but had NO _FACE_DEFS entry, so they
# fell through to the generic HTTP handler. Wire them to a real Beanstalkd
# text-protocol face (server-first banner + client-first reply).
def _beanstalkd_greeting() -> bytes:
    return b'beanstalkd' + bytes([13, 10])


def _beanstalkd_respond(raw: bytes, bot_ip: str) -> bytes:
    """Answer common Beanstalkd text-protocol commands plausibly (issue #624)."""
    crlf = bytes([13, 10])
    text = raw.decode('latin-1', errors='replace').strip()
    cmd = text.split(' ', 1)[0].lower() if text else ''
    if cmd == 'put':
        return b'INSERTED 1' + crlf
    if cmd in ('reserve', 'reserve-with-timeout'):
        return b'RESERVED 1 0' + crlf + crlf
    if cmd in ('peek', 'peek-ready', 'peek-delayed', 'peek-buried'):
        return b'NOT_FOUND' + crlf
    if cmd == 'delete':
        return b'DELETED' + crlf
    if cmd in ('release', 'bury', 'kick', 'touch'):
        return b'RELEASED' + crlf
    if cmd in ('stats', 'stats-tube'):
        return (
            b'---'
            + crlf
            + b'current-jobs-ready: 0'
            + crlf
            + b'current-jobs-reserved: 0'
            + crlf
            + b'current-tubes: 1'
            + crlf
            + b'current-connections: 1'
            + crlf
            + b'pid: 1'
            + crlf
            + b'version: 1.12'
            + crlf
        )
    if cmd in ('list-tubes', 'list-tubes-watched', 'list-tube-used'):
        return b'---' + crlf + b'- default' + crlf
    if cmd in ('use', 'watch', 'ignore'):
        if cmd == 'use':
            return b'USING default' + crlf
        return b'WATCHING 1' + crlf
    if cmd == 'quit':
        return b''
    return b'OK' + crlf


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
    23: (
        UNKNOWN_TELNET,
        SERVER_FIRST,
        _telnet_greeting,
        _telnet_respond,
        True,
        extract_telnet_credentials,
    ),
    21: (
        UNKNOWN_NON_HTTP,
        SERVER_FIRST,
        _ftp_greeting,
        _ftp_respond,
        True,
        extract_ftp_credentials,
    ),
    25: (UNKNOWN_NON_HTTP, SERVER_FIRST, _smtp_greeting, _smtp_respond, False, None),
    110: (
        UNKNOWN_NON_HTTP,
        SERVER_FIRST,
        _pop3_greeting,
        _pop3_respond,
        True,
        extract_pop3_credentials,
    ),
    143: (
        UNKNOWN_NON_HTTP,
        SERVER_FIRST,
        _imap_greeting,
        _imap_respond,
        True,
        extract_imap_credentials,
    ),
    5900: (UNKNOWN_VNC, SERVER_FIRST, _vnc_greeting, _vnc_respond, False, None),
    5901: (UNKNOWN_VNC, SERVER_FIRST, _vnc_greeting, _vnc_respond, False, None),
    3389: (UNKNOWN_RDP, SERVER_FIRST, _rdp_greeting, _rdp_respond, True, extract_rdp_credentials),
    1433: (
        UNKNOWN_MSSQL,
        SERVER_FIRST,
        _mssql_greeting,
        _mssql_respond,
        True,
        extract_mssql_credentials,
    ),
    3306: (
        UNKNOWN_MYSQL,
        SERVER_FIRST,
        _mysql_greeting,
        _mysql_respond,
        True,
        extract_mysql_credentials,
    ),
    5672: (UNKNOWN_AMQP, SERVER_FIRST, _amqp_greeting, _greeting_only_respond, False, None),
    # Oracle TNS (issue #440): server-first Refuse packet greeting.
    1521: (UNKNOWN_NON_HTTP, SERVER_FIRST, _oracle_greeting, _oracle_respond, False, None),
    # client-first faces (high ports, no privilege redirect needed)
    6379: (UNKNOWN_REDIS, CLIENT_FIRST, lambda: b'', _redis_respond, True, _redis_extract),
    27017: (UNKNOWN_MONGODB, CLIENT_FIRST, lambda: b'', _mongo_respond, False, None),
    11211: (UNKNOWN_MEMCACHED, CLIENT_FIRST, lambda: b'', _memcached_respond, False, None),
    2181: (UNKNOWN_ZOOKEEPER, CLIENT_FIRST, lambda: b'', _zookeeper_respond, False, None),
    5432: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _postgres_respond, False, None),
    # Elasticsearch (9200) and RabbitMQ management (15672) are real HTTP
    # services, NOT binary protocols. Routing them through the non-HTTP face
    # registry threw away the rich HTTP emulation already in the repo
    # (ElasticHandler / RabbitMQHandler) and produced corrupt captures
    # (issue #461/#468). They are served by the HTTP router instead — see
    # is_http_port() below and the Elasticsearch/RabbitMQ route tables.
    # NFS / rpcbind (issue #454/#457): client-first RPC reply.
    2049: (UNKNOWN_NON_HTTP, CLIENT_FIRST, lambda: b'', _nfs_respond, False, None),
    # EPMD (Erlang Port Mapper, rabbitmq companion; issue #451/#458): client-first.
    4369: (UNKNOWN_EPMD, CLIENT_FIRST, lambda: b'', _epmd_respond, False, None),
    # ── Privileged-port redirect targets (issue #600) ───────────────────────
    # These are bound as high ports via PRIVILEGED_PORT_REDIRECTS (53->10053,
    # 135->10135, 139->10139, 445->10445, 993->10993, 995->10995) and resolved
    # back to their external port by get_face(). They were previously absent
    # from _FACE_DEFS and silently fell through to the generic HTTP handler.
    # DNS / MSRPC / NetBIOS / SMB are client-first (the client speaks first);
    # IMAPS / POP3S are TLS server-first (greeted with a static TLS ServerHello).
    53: (UNKNOWN_DNS, CLIENT_FIRST, _dns_greeting, _dns_respond, False, None),
    135: (UNKNOWN_SMB, CLIENT_FIRST, _msrpc_greeting, _msrpc_respond, False, None),
    139: (UNKNOWN_SMB, CLIENT_FIRST, _netbios_greeting, _netbios_respond, False, None),
    445: (UNKNOWN_SMB, CLIENT_FIRST, _smb_greeting, _smb_respond, False, None),
    # IMAPS / POP3S now speak plaintext IMAP/POP3 (issue #625): a client that
    # opens with a TLS ClientHello still gets a handshake-failure alert, but a
    # plaintext USER/PASS (the common bot behaviour) is handled and captured.
    993: (
        UNKNOWN_NON_HTTP,
        SERVER_FIRST,
        _imaps_greeting,
        _imaps_respond,
        True,
        extract_imap_credentials,
    ),
    995: (
        UNKNOWN_NON_HTTP,
        SERVER_FIRST,
        _pop3s_greeting,
        _pop3s_respond,
        True,
        extract_pop3_credentials,
    ),
    # Beanstalkd work-queue (issue #624): ports 11300-11311 are in
    # DEFAULT_TOP_PORTS and labeled Beanstalkd but had NO _FACE_DEFS entry, so
    # they fell through to the generic HTTP handler. Wire them to a real
    # Beanstalkd text-protocol face (BEANSTALKD detected_id).
    11300: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11301: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11302: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11303: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11304: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11305: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11306: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11307: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11308: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11309: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11310: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
    11311: (BEANSTALKD, CLIENT_FIRST, _beanstalkd_greeting, _beanstalkd_respond, False, None),
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
        53: 'dns',
        135: 'msrpc',
        139: 'netbios',
        445: 'smb',
        993: 'imaps',
        995: 'pop3s',
        11300: 'beanstalkd',
        11301: 'beanstalkd',
        11302: 'beanstalkd',
        11303: 'beanstalkd',
        11304: 'beanstalkd',
        11305: 'beanstalkd',
        11306: 'beanstalkd',
        11307: 'beanstalkd',
        11308: 'beanstalkd',
        11309: 'beanstalkd',
        11310: 'beanstalkd',
        11311: 'beanstalkd',
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
    # Elasticsearch (9200) and RabbitMQ management (15672) are real HTTP
    # services (issue #461/#468) — treat them as HTTP faces so the rich
    # HTTP emulation (ElasticHandler / RabbitMQHandler) is used instead of
    # the generic non-HTTP path. 8000 is the de-facto Model Context Protocol
    # (MCP) Inspector default port (issue #555) — a real MCP client targets
    # http://host:8000/mcp, so route it to the MCP face rather than a generic
    # web face.
    return int(ext) in (
        80,
        443,
        8080,
        8443,
        5000,
        7001,
        7002,
        8000,
        8888,
        9090,
        9200,
        15672,
    )


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
