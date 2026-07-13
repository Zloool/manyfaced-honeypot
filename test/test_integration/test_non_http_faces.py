"""Regression tests for the non-HTTP face registry + dispatch (issue #377).

These run WITHOUT touching the network: each face is exercised against an
in-memory socket pair so the test is fast and CI-machine-time friendly. They
prove the core contract from the #377 RFC:

* server-first faces send their greeting BEFORE the client speaks;
* client-first faces read the client frame and reply with a protocol-correct,
  non-empty response that actually reaches the client socket;
* the capture (BearStorage) is built with the right detected_id + raw bytes.
"""

from __future__ import annotations

import socket
import threading
import time
from types import SimpleNamespace

import pytest

from manyfaced.client.client import _handle_non_http_connection
from manyfaced.common import faces as face_module
from manyfaced.common.faces import FACE_REGISTRY, FaceSpec, get_face, is_http_port
from manyfaced.handlers.http_handler import set_enrich_args

# CRLF as a bytes constant built without backslash escapes (keeps the test
# source free of literal control chars that confuse editors/diff).
CRLF = bytes([13, 10])


# ---------------------------------------------------------------------------
# Registry structure
# ---------------------------------------------------------------------------


def test_registry_covers_expected_faces():
    names = {spec.name for spec in FACE_REGISTRY.values()}
    for expected in {
        'ssh',
        'telnet',
        'ftp',
        'smtp',
        'pop3',
        'imap',
        'vnc',
        'rdp',
        'mysql',
        'mssql',
        'amqp',
        'oracle',
        'redis',
        'mongodb',
        'memcached',
        'zookeeper',
        'postgres',
        'nfs',
        'epmd',
    }:
        assert expected in names, f'missing face in registry: {expected}'


def test_top_ports_without_faces_are_not_http():
    # The non-HTTP protocol ports this cluster is responsible for must each
    # resolve to a FaceSpec (so they are dispatched to the right face, not the
    # HTTP handler) and must NOT be classified as an HTTP port. The HTTP
    # fallthrough must never answer an Oracle/NFS/EPMD/MSSQL/RDP/Postgres probe
    # with an admin panel (issues #440/#454/#460/#487/#492, cluster C4).
    in_scope = {
        1433,
        1521,
        2049,
        3306,
        3389,
        5432,
        5900,
        5901,
        6379,
        11211,
        27017,
        5672,
        4369,
        2181,
    }
    for port in in_scope:
        assert get_face(port) is not None, (
            f'port {port} has no FaceSpec — would fall through to HTTP'
        )
        assert not is_http_port(port), f'port {port} flagged as HTTP but owns a non-HTTP face'


def test_server_first_faces_have_greeting():
    for port, spec in FACE_REGISTRY.items():
        if spec.direction == 'server-first':
            assert spec.greeting, f'server-first face {spec.name} has empty greeting'


def test_get_face_resolves_via_external_port():
    # Bound high port 10022 -> external 22 -> ssh
    spec = get_face(10022)
    assert spec is not None
    assert spec.name == 'ssh'
    # A direct high port (redis) passes through unchanged
    assert get_face(6379).name == 'redis'


# ---------------------------------------------------------------------------
# Socket-pair harness: drive the real respond()/greeting() through a pair so we
# exercise bytes-on-the-wire without binding a port.
# ---------------------------------------------------------------------------


def _server_first_greeting(name):
    spec = next(s for s in FACE_REGISTRY.values() if s.name == name)
    a, b = socket.socketpair()
    try:
        a.settimeout(2)
        greeting = spec.greeting
        a.sendall(greeting)
        got = b.recv(4096)
        return got, greeting
    finally:
        a.close()
        b.close()


def _client_first_reply(name, client_says):
    spec = next(s for s in FACE_REGISTRY.values() if s.name == name)
    a, b = socket.socketpair()
    try:
        b.settimeout(2)
        a.settimeout(2)
        b.sendall(client_says)
        reply = spec.respond(client_says, '127.0.0.1')
        if reply:
            a.sendall(reply)
            return b.recv(4096)
        return b.recv(4096)
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# Server-first: greeting must arrive before the client speaks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'name,needle',
    [
        ('ssh', b'SSH-2.0-'),
        ('telnet', b'login:'),
        ('ftp', b'220 '),
        ('smtp', b'220 '),
        ('pop3', b'+OK'),
        ('imap', b'* OK'),
        ('vnc', b'RFB '),
        ('rdp', b'\x03\x00'),
        ('mysql', b'\x0a'),
        ('mssql', b'\x12'),
        ('amqp', b'AMQP'),
    ],
)
def test_server_first_greeting_emitted_first(name, needle):
    got, greeting = _server_first_greeting(name)
    assert got == greeting, f'{name}: greeting not received before client spoke'
    assert needle in greeting, f'{name}: greeting missing {needle!r}'


# ---------------------------------------------------------------------------
# Client-first: a correct client frame yields a non-empty, protocol-correct reply
# ---------------------------------------------------------------------------


def test_redis_ping_responds_pong():
    ping = b'*1' + CRLF + b'$4' + CRLF + b'PING' + CRLF
    reply = _client_first_reply('redis', ping)
    assert reply.startswith(b'+PONG'), f'redis reply was {reply!r}'


def test_memcached_version_responds():
    reply = _client_first_reply('memcached', b'version' + CRLF)
    assert reply.startswith(b'VERSION'), f'memcached reply was {reply!r}'


def test_postgres_startup_gets_auth_request():
    import struct

    # A real Postgres StartupMessage: int32 length, int32 protocol 196608
    # (0x00030000, protocol 3.0), then NUL-terminated key/value params ending
    # with an empty key.
    params = b'user\x00postgres\x00database\x00postgres\x00\x00'
    body = struct.pack('!I', 196608) + params
    pkt = struct.pack('!I', 4 + len(body)) + body
    reply = _client_first_reply('postgres', pkt)
    # Real libpq MD5 AuthRequest is exactly 13 bytes: 'R' + int32(12) + int32(5)
    # + 4-byte salt. The old reply declared length 12 but sent only 4 body
    # bytes, desyncing libpq (issue #482).
    assert reply[:1] == b'R', f'postgres reply was {reply!r}'
    assert len(reply) == 13, f'postgres AuthRequest wrong length: {len(reply)}'
    assert reply[1:5] == (12).to_bytes(4, 'big'), f'postgres length field wrong: {reply!r}'
    assert reply[5:9] == (5).to_bytes(4, 'big'), f'postgres method field wrong: {reply!r}'


def test_postgres_sslrequest_gets_flag():
    # A Postgres SSLRequest (code 80877103) must be answered with a single
    # 'N' (TLS not supported) flag byte so libpq can proceed (issue #499).
    ssl_req = (8).to_bytes(4, 'big') + (80877103).to_bytes(4, 'big')
    reply = _client_first_reply('postgres', ssl_req)
    assert reply == b'N', f'postgres SSLRequest reply was {reply!r}'


def test_mongodb_hello_responds():
    # The MongoDB face previously emitted a broken 16-byte header (opcode in
    # the length field) and malformed hello JSON (unterminated
    # authMechanisms array). Verify the reply now has a valid header whose
    # declared length matches the bytes on the wire and a valid JSON body
    # (issues #431/#433/#437).
    import json
    import struct

    hello = b'{"hello":1,"client":{}}'
    reply = _client_first_reply('mongodb', hello)
    assert len(reply) > 16, f'mongo reply too short: {reply!r}'
    declared_len = struct.unpack('<I', reply[:4])[0]
    assert declared_len == len(reply), f'mongo header length {declared_len} != actual {len(reply)}'
    # opcode at offset 12 must be OP_REPLY (1)
    assert struct.unpack('<I', reply[12:16])[0] == 1, f'mongo opcode wrong: {reply!r}'
    body = reply[16:].decode('utf-8', errors='replace')
    parsed = json.loads(body)
    assert parsed.get('isWritablePrimary') is True, f'mongo body was {body!r}'
    assert 'ok' in parsed and parsed['ok'] == 1.0


def test_zookeeper_connect_responds():
    req = bytes([0, 0, 0, 0x0B]) + bytes(8)
    reply = _client_first_reply('zookeeper', req)
    assert len(reply) >= 4, f'zookeeper reply was {reply!r}'


# ---------------------------------------------------------------------------
# BearStorage construction for non-HTTP faces
# ---------------------------------------------------------------------------


def test_build_bear_storage_detected_id():
    from manyfaced.handlers.http_handler import _build_bear_storage
    from manyfaced.common.status import UNKNOWN_REDIS

    spec = get_face(6379)
    ping = b'*1' + CRLF + b'$4' + CRLF + b'PING' + CRLF
    bs = _build_bear_storage('1.2.3.4', spec, ping, 6379)
    assert bs.isDetected == UNKNOWN_REDIS
    assert bs.ip == '1.2.3.4'
    assert 'PING' in bs.raw_request
    assert bs.listen_port == 6379


def _make_op_msg_frame(payload: bytes = b'') -> bytes:
    """Build a minimal MongoDB OP_MSG frame recognised by the repo's detector (issue #597).

    The codebase's wire sniffer expects the opcode at **offset 20** (4-byte
    length + 16-byte pad + 4-byte opcode), so we match that layout here. Body =
    flags(4)=0 + payload. ``payload`` carries arbitrary BSON bytes.

    We also guarantee the first byte is NOT one of the redis RESP trigger bytes
    ($ * +) so the frame is classified as mongodb and not redis (detection order
    is redis-before-mongodb in ``_PROTOCOL_SIGNATURES``).
    """
    import struct

    body = b'\x00' + payload  # flags(4) = 0
    msg_len = 20 + 4 + len(body)
    prefix = struct.pack('<I', msg_len)
    # Shift length until its low byte is not a redis trigger ($ = 0x24, * = 0x2a, + = 0x2b).
    while prefix[0] in (0x24, 0x2A, 0x2B):
        body += b'\x00'
        prefix = struct.pack('<I', 20 + 4 + len(body))
    return prefix + b'\x00' * 16 + struct.pack('<I', 2013) + body


def test_op_msg_frame_detected_and_stored_without_utf8_mangling():
    """A synthetic OP_MSG (opcode 2013) probe must be detected as mongo AND the
    binary request_raw must survive the capture/store path WITHOUT the bytes
    being mangled by a UTF-8 decode (issue #597).

    The frame carries non-UTF-8 BSON bytes (0xff 0xfe 0x00) and a UTF-8
    accelerator document; only a binary-safe path keeps them intact.
    """
    from manyfaced.common.protocol import detect_protocol, get_protocol_info
    from manyfaced.common.utils import receive_first_frame
    from manyfaced.handlers.http_handler import _build_bear_storage
    from manyfaced.common.status import UNKNOWN_MONGODB

    # Binary payload with bytes that are invalid UTF-8 (0xff 0xfe) + a valid doc.
    bson_garbage = b'\xff\xfe\x00' + b'{"ismaster":1}'
    frame = _make_op_msg_frame(bson_garbage)

    # 1) Detection: OP_MSG (opcode 2013) is recognised.
    assert detect_protocol(frame) == 'mongodb'
    assert get_protocol_info(frame)['protocol'] == 'mongodb'

    # 2) receive_first_frame preserves raw bytes verbatim (no UTF-8 decode).
    class _Sock:
        def __init__(self, data):
            self._data = data
            self.settimeout = lambda *a, **k: None

        def recv(self, n):
            if self._data:
                out, self._data = self._data[:n], self._data[n:]
                return out
            return b''

    got = receive_first_frame(_Sock(frame), timeout=1.0)
    assert isinstance(got, bytes)
    assert got == frame, 'receive_first_frame must not mangle binary frames'

    # 3) The capture/store path keeps the bytes intact (BearStorage stores the
    #    raw frame; latin-1 decode/encode is lossless for all 256 byte values).
    spec = get_face(27017)
    assert spec.name == 'mongodb'
    bs = _build_bear_storage('9.9.9.9', spec, frame, 27017)
    assert bs.isDetected == UNKNOWN_MONGODB
    # round-trip the stored raw_request through latin-1 and compare to the wire frame
    stored = bs.raw_request.encode('latin-1', errors='replace')
    assert stored == frame, 'binary OP_MSG bytes were mangled in storage'
    assert b'\xff\xfe\x00' in stored, 'non-UTF-8 BSON bytes were lost'


# ---------------------------------------------------------------------------
# Full dispatch: drive _handle_non_http_connection over a real socketpair so we
# prove the reply actually reaches the client (catches the #377 ordering bug
# where a client-first reply was sent only AFTER a blocking credential read,
# causing the client to time out with an empty response).
# ---------------------------------------------------------------------------


def _dispatch(make_spec, client_says, server_port):
    """Run the real dispatch against a real localhost TCP listener (not a
    socketpair — socketpair on this platform misbehaves when the same fd both
    recv()s and then send()s). Returns what the client received."""
    import socket as _sock

    args = SimpleNamespace(server=19999, server_host='127.0.0.1')
    set_enrich_args(args)
    spec = make_spec()

    # Real ephemeral listener -> accept one connection, hand it to the dispatch.
    lsn = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    lsn.bind(('127.0.0.1', 0))
    lsn.listen(1)
    real_port = lsn.getsockname()[1]

    client = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    client.connect(('127.0.0.1', real_port))
    srv_sock, _ = lsn.accept()

    def server_side():
        try:
            _handle_non_http_connection(srv_sock, args, '9.9.9.9', None, server_port, spec)
        finally:
            srv_sock.close()

    t = threading.Thread(target=server_side, daemon=True)
    t.start()
    try:
        if client_says:
            client.settimeout(4)
            client.sendall(client_says)
        client.settimeout(4)
        return client.recv(4096)
    except Exception as e:
        return f'ERR:{e!r}'.encode()
    finally:
        client.close()
        lsn.close()
        t.join(timeout=3)


def test_dispatch_redis_reply_reaches_client():
    # Redis is client-first AND capture_creds=True -- the +PONG must arrive
    # before any credential-capture read, or the client times out.
    ping = b'*1' + CRLF + b'$4' + CRLF + b'PING' + CRLF
    got = _dispatch(lambda: get_face(6379), ping, 6379)
    assert got.startswith(b'+PONG'), f'client got {got!r} (reply not delivered)'


def test_dispatch_memcached_reply_reaches_client():
    got = _dispatch(lambda: get_face(11211), b'version' + CRLF, 11211)
    assert got.startswith(b'VERSION'), f'client got {got!r}'


def test_dispatch_ssh_banner_reaches_client_before_speaking():
    got = _dispatch(lambda: get_face(10022), None, 10022)
    assert got.startswith(b'SSH-2.0-'), f'client got {got!r}'


# ---------------------------------------------------------------------------
# New non-HTTP faces added by cluster C4 (issue #440 Oracle 1521, #454/#457 NFS
# 2049, #451/#458 EPMD 4369, and the double-ownership locks for RDP 3389 and
# Postgres 5432 — #460/#487). Each must answer with a protocol-shaped (non-HTTP)
# response, never an HTTP/Apache admin panel.
# ---------------------------------------------------------------------------


def test_dispatch_oracle_reply_reaches_client():
    # Oracle TNS is server-first: the Refuse/ORA-12514 packet arrives on accept.
    got = _dispatch(lambda: get_face(1521), None, 1521)
    assert got.startswith(b'\x04'), f'oracle greeting not a TNS Refuse: {got!r}'
    assert b'ORA-12514' in got, f'oracle greeting missing ORA-12514: {got!r}'


def test_dispatch_nfs_reply_reaches_client():
    # NFS/rpcbind is client-first: reply to a (minimal) RPC NULL call with a
    # protocol-shaped rpcbind reply, NOT an HTTP 404.
    got = _dispatch(lambda: get_face(2049), b'\x00\x00\x00\x01req', 2049)
    assert got, f'client got nothing from NFS face: {got!r}'
    assert not got.startswith(b'HTTP'), f'NFS face served HTTP: {got!r}'


def test_dispatch_epmd_reply_reaches_client():
    # EPMD NAMES (0x73) -> empty node list; must not be served an HTTP panel.
    got = _dispatch(lambda: get_face(4369), b'\x73', 4369)
    assert got, f'client got nothing from EPMD face: {got!r}'
    assert not got.startswith(b'HTTP'), f'EPMD face served HTTP: {got!r}'


def test_dispatch_rdp_not_http():
    # Double-ownership lock (issue #460): a connection to external 3389 must be
    # answered by the RDP face (TPKT/X.224 Connection-Confirm), never HTTP.
    got = _dispatch(lambda: get_face(3389), None, 3389)
    assert got, f'RDP face sent nothing: {got!r}'
    assert not got.startswith(b'HTTP'), f'RDP 3389 served HTTP (double-ownership!): {got!r}'
    assert got.startswith(b'\x03\x00'), f'RDP greeting not TPKT: {got!r}'


def test_dispatch_postgres_not_http():
    # Double-ownership lock (issue #487): a connection to external 5432 must be
    # answered by the Postgres face (AuthRequest 'R...'), never an HTTP panel.
    got = _dispatch(lambda: get_face(5432), b'\x00\x00\x00\x08startup', 5432)
    assert got, f'Postgres face sent nothing: {got!r}'
    assert not got.startswith(b'HTTP'), f'Postgres 5432 served HTTP (double-ownership!): {got!r}'
    assert got[:1] == b'R', f'Postgres reply not an AuthRequest: {got!r}'


def test_dispatch_mysql_greeting_and_auth_request_reaches_client():
    # MySQL is server-first: the greeting (seq 0) is sent on accept, then the
    # client's HandshakeResponse41 (seq 1) must be answered with an ERR/OK
    # packet (seq 2). The old face replied with nothing and the client hung
    # until BOT_TIMEOUT (issue #438). Assert the full greeting + auth-request
    # PDU arrives and the auth-request is a wire-valid ERR packet.
    import socket as _sock
    import struct

    from manyfaced.handlers.http_handler import set_enrich_args

    args = SimpleNamespace(server=19999, server_host='127.0.0.1')
    set_enrich_args(args)
    spec = get_face(3306)

    lsn = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    lsn.bind(('127.0.0.1', 0))
    lsn.listen(1)
    real_port = lsn.getsockname()[1]

    client = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    client.connect(('127.0.0.1', real_port))
    srv_sock, _ = lsn.accept()

    def server_side():
        try:
            _handle_non_http_connection(srv_sock, args, '9.9.9.9', None, 3306, spec)
        finally:
            srv_sock.close()

    t = threading.Thread(target=server_side, daemon=True)
    t.start()
    try:
        # Minimal HandshakeResponse41-shaped frame so the dispatch loop has
        # something to respond to.
        client_handshake = struct.pack('<I', 0xFFFF_FFFF) + b'root\x00' + b'\x14' + (b'\x00' * 20)
        client.settimeout(4)
        client.sendall(client_handshake)
        # Read until we have both the greeting (0x0a) and the ERR packet (0xff),
        # or until the socket idles — they may arrive in separate segments.
        buf = b''
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and (b'\x0a' not in buf or b'\xff' not in buf):
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        got = buf
    finally:
        client.close()
        lsn.close()
        t.join(timeout=3)

    assert got, f'MySQL face sent nothing: {got!r}'
    # The greeting PDU is `<3-byte len><1-byte seq><payload>`; the protocol
    # version byte (0x0a) is the first payload byte (offset 4).
    assert got[4:5] == b'\x0a', f'MySQL greeting missing: {got!r}'
    # The full PDU must contain the ERR packet the server sends after the
    # client's handshake: an ERR_Packet begins with 0xff.
    assert b'\xff' in got, f'MySQL auth-request (ERR) missing: {got!r}'


def _dispatch_multi(make_spec, client_frames, server_port):
    """Like _dispatch but drives a *sequence* of client frames (issue #382):
    send a frame, read its reply, repeat — proving the client-first exchange
    loop serves multiple commands (redis-py does HELLO → PING → SET)."""
    import socket as _sock

    args = SimpleNamespace(server=19999, server_host='127.0.0.1')
    set_enrich_args(args)
    spec = make_spec()

    lsn = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    lsn.bind(('127.0.0.1', 0))
    lsn.listen(1)
    real_port = lsn.getsockname()[1]

    client = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    client.connect(('127.0.0.1', real_port))
    srv_sock, _ = lsn.accept()

    def server_side():
        try:
            _handle_non_http_connection(srv_sock, args, '9.9.9.9', None, server_port, spec)
        finally:
            srv_sock.close()

    t = threading.Thread(target=server_side, daemon=True)
    t.start()
    replies = []
    try:
        for frame in client_frames:
            client.settimeout(4)
            client.sendall(frame)
            client.settimeout(4)
            replies.append(client.recv(8192))
        return replies
    except Exception as e:
        return replies + [f'ERR:{e!r}'.encode()]
    finally:
        client.close()
        lsn.close()
        t.join(timeout=3)


def test_dispatch_redis_hello_ping_set_sequence():
    """redis-py opens with HELLO 3, then PING, then SET — the exchange loop must
    answer all three (issue #382)."""
    hello = b'*2' + CRLF + b'$5' + CRLF + b'HELLO' + CRLF + b'$1' + CRLF + b'3' + CRLF
    ping = b'*1' + CRLF + b'$4' + CRLF + b'PING' + CRLF
    sett = (
        b'*3'
        + CRLF
        + b'$3'
        + CRLF
        + b'SET'
        + CRLF
        + b'$1'
        + CRLF
        + b'k'
        + CRLF
        + b'$1'
        + CRLF
        + b'v'
        + CRLF
    )
    replies = _dispatch_multi(lambda: get_face(6379), [hello, ping, sett], 6379)
    assert len(replies) == 3, f'expected 3 replies, got {replies!r}'
    assert replies[0].startswith(b'%7'), f'HELLO reply not a RESP3 map: {replies[0]!r}'
    assert replies[1] == b'+PONG' + CRLF, f'PING reply wrong: {replies[1]!r}'
    assert replies[2] == b'+OK' + CRLF, f'SET reply wrong: {replies[2]!r}'


# ---------------------------------------------------------------------------
# Issue #601: client-first silent-capture guard
#
# A client-first connect (redis/memcached/mongo/postgres/epmd/nfs) that sends
# NO frame before idling must NOT be recorded as a normal UNKNOWN_NON_HTTP
# session with empty request_raw + empty bot_profile_data (indistinguishable
# from a real capture). It must be stamped EMPTY_CONNECTION and carry a minimal
# auditable bot_profile_data so the silent loss is visible.
# ---------------------------------------------------------------------------


def _capture_bear_non_http(name, client_says, server_port):
    """Run the real dispatch but intercept the BearStorage instead of sending
    a report to the server (no network/geo). Returns the built BearStorage."""
    import manyfaced.client.client as client_mod
    from manyfaced.handlers.http_handler import _enrich_and_send_bear

    args = SimpleNamespace(server=19999, server_host='127.0.0.1')
    set_enrich_args(args)
    spec = (
        get_face(server_port)
        if name is None
        else next(s for s in FACE_REGISTRY.values() if s.name == name)
    )

    captured: dict[str, object] = {}

    def _intercept(bs, _ip):
        captured['bs'] = bs

    # Patch ONLY the send side so the dispatch runs the real capture logic.
    real_send = client_mod._enrich_and_send_bear
    client_mod._enrich_and_send_bear = _intercept  # type: ignore[assignment]
    try:
        lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsn.bind(('127.0.0.1', 0))
        lsn.listen(1)
        real_port = lsn.getsockname()[1]
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.connect(('127.0.0.1', real_port))
        srv_sock, _ = lsn.accept()

        def server_side():
            try:
                _handle_non_http_connection(srv_sock, args, '9.9.9.9', None, server_port, spec)
            finally:
                srv_sock.close()

        t = threading.Thread(target=server_side, daemon=True)
        t.start()
        try:
            if client_says:
                cli.settimeout(4)
                cli.sendall(client_says)
        finally:
            cli.settimeout(4)
            try:
                cli.recv(8192)
            except Exception:
                pass
            cli.close()
            lsn.close()
            t.join(timeout=3)
    finally:
        client_mod._enrich_and_send_bear = real_send  # type: ignore[assignment]
        # Restore the real implementation we masked above.
        client_mod._enrich_and_send_bear = _enrich_and_send_bear
    return captured.get('bs')


def test_client_first_empty_frame_is_empty_connection():
    # A client-first face (redis 6379) that connects but sends no frame must
    # be recorded as EMPTY_CONNECTION, not a silent empty UNKNOWN_NON_HTTP.
    bs = _capture_bear_non_http('redis', None, 6379)
    assert bs is not None, 'no BearStorage was built'
    from manyfaced.common.status import EMPTY_CONNECTION

    assert bs.isDetected == EMPTY_CONNECTION, (
        f'empty client-first frame should be EMPTY_CONNECTION, got {bs.isDetected}'
    )
    # And it must carry an auditable, non-empty bot_profile_data so analysts
    # can distinguish a no-frame connect from a genuine capture failure.
    assert bs.bot_profile_data is not None, 'bot_profile_data must be populated'
    prof = bs.bot_profile_data['redis']
    assert prof['note'] == 'client-first frame not captured'
    assert prof['captured'] is False


def test_client_first_real_frame_not_empty_connection():
    # A client-first face that DOES send a frame is a normal capture — must NOT
    # be reclassified as EMPTY_CONNECTION.
    ping = b'*1' + CRLF + b'$4' + CRLF + b'PING' + CRLF
    bs = _capture_bear_non_http('redis', ping, 6379)
    assert bs is not None
    from manyfaced.common.status import EMPTY_CONNECTION, UNKNOWN_REDIS

    assert bs.isDetected == UNKNOWN_REDIS, (
        f'real client-first frame must stay UNKNOWN_REDIS, got {bs.isDetected}'
    )
    assert bs.isDetected != EMPTY_CONNECTION
    # bot_profile_data now always carries at least the minimal request_command.
    assert bs.bot_profile_data is not None
    assert bs.bot_profile_data['redis']['captured'] is True


def test_build_bear_storage_always_emits_bot_profile_data():
    # Issue #601 part 2: _build_bear_storage must ALWAYS emit a minimal
    # bot_profile_data (wire request_command + captured flag), even with an
    # empty frame and no reply.
    from manyfaced.handlers.http_handler import _build_bear_storage

    spec = get_face(6379)
    bs = _build_bear_storage('1.2.3.4', spec, b'', 6379, reply=b'')
    assert bs.bot_profile_data is not None, 'bot_profile_data must never be None'
    assert bs.bot_profile_data['redis']['request_command'] == 'REDIS'
    assert bs.bot_profile_data['redis']['captured'] is False
    # With a real frame it carries the dialogue + captured=True.
    ping = b'*1' + CRLF + b'$4' + CRLF + b'PING' + CRLF
    bs2 = _build_bear_storage('1.2.3.4', spec, ping, 6379, reply=b'+PONG' + CRLF)
    assert bs2.bot_profile_data['redis']['captured'] is True
    assert bs2.bot_profile_data['redis']['dialogue']


# ---------------------------------------------------------------------------
# Issue #596: HTTP-on-non-HTTP re-sniff for ALL non-HTTP faces
#
# An HTTP request (GET /) arriving on a non-HTTP port must be reclassified to
# HTTP_ON_NONHTTP_PORT, not the face's UNKNOWN_* sentinel. Previously only the
# SSH branch did this; MySQL 3306 / MSSQL 1433 / etc. fell through to
# UNKNOWN_NON_HTTP. Verify across server-first (mysql) and client-first (redis).
# ---------------------------------------------------------------------------


def test_http_on_3306_is_http_on_nonhttp_port():
    # A GET / pushed at the MySQL port must be flagged HTTP_ON_NONHTTP_PORT.
    from manyfaced.common.status import HTTP_ON_NONHTTP_PORT

    bs = _capture_bear_non_http('mysql', b'GET / HTTP/1.1' + CRLF + b'Host: x' + CRLF + CRLF, 3306)
    assert bs is not None, 'no BearStorage was built for HTTP-on-3306'
    assert bs.isDetected == HTTP_ON_NONHTTP_PORT, (
        f'HTTP on 3306 should be HTTP_ON_NONHTTP_PORT, got {bs.isDetected}'
    )


def test_http_on_mssql_is_http_on_nonhttp_port():
    from manyfaced.common.status import HTTP_ON_NONHTTP_PORT

    bs = _capture_bear_non_http('mssql', b'POST / HTTP/1.1' + CRLF + b'Host: x' + CRLF + CRLF, 1433)
    assert bs is not None
    assert bs.isDetected == HTTP_ON_NONHTTP_PORT, (
        f'HTTP on 1433 should be HTTP_ON_NONHTTP_PORT, got {bs.isDetected}'
    )


def test_http_on_redis_is_http_on_nonhttp_port():
    # Even client-first faces must re-sniff an HTTP frame.
    from manyfaced.common.status import HTTP_ON_NONHTTP_PORT

    bs = _capture_bear_non_http('redis', b'GET / HTTP/1.1' + CRLF + b'Host: x' + CRLF + CRLF, 6379)
    assert bs is not None
    assert bs.isDetected == HTTP_ON_NONHTTP_PORT, (
        f'HTTP on redis port should be HTTP_ON_NONHTTP_PORT, got {bs.isDetected}'
    )


def test_real_http_request_still_http_on_ssh():
    # Regression: the SSH branch keeps its prior HTTP_ON_NONHTTP_PORT behavior.
    from manyfaced.common.status import HTTP_ON_NONHTTP_PORT

    bs = _capture_bear_non_http('ssh', b'GET / HTTP/1.1' + CRLF + b'Host: x' + CRLF + CRLF, 22)
    assert bs is not None
    assert bs.isDetected == HTTP_ON_NONHTTP_PORT, (
        f'HTTP on 22 should remain HTTP_ON_NONHTTP_PORT, got {bs.isDetected}'
    )
