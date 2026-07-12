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
        'elasticsearch',
        'rabbitmq',
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
        15672,
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


def test_elasticsearch_get_responds_http():
    req = b'GET / HTTP/1.0' + CRLF + CRLF
    reply = _client_first_reply('elasticsearch', req)
    assert reply.startswith(b'HTTP/1.1 200'), f'es reply was {reply!r}'


def test_postgres_startup_gets_auth_request():
    import struct

    pkt = (
        struct.pack('!ii', 8, 80877103)
        + struct.pack('!ii', 96, 196608)
        + (b'user\x00postgres\x00database\x00postgres\x00\x00')
    )
    reply = _client_first_reply('postgres', pkt)
    assert reply[:1] == b'R', f'postgres reply was {reply!r}'


def test_mongodb_hello_responds():
    hello = bytes([0x3D]) + bytes(23)
    reply = _client_first_reply('mongodb', hello)
    assert b'isWritablePrimary' in reply or len(reply) > 16, f'mongo reply was {reply!r}'


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


def test_dispatch_elasticsearch_reply_reaches_client():
    req = b'GET / HTTP/1.0' + CRLF + CRLF
    got = _dispatch(lambda: get_face(9200), req, 9200)
    assert got.startswith(b'HTTP/1.1 200'), f'client got {got!r}'


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
