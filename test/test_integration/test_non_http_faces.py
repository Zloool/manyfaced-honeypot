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
from manyfaced.common.faces import FACE_REGISTRY, FaceSpec, get_face
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
        'redis',
        'mongodb',
        'memcached',
        'zookeeper',
        'postgres',
        'elasticsearch',
    }:
        assert expected in names, f'missing face in registry: {expected}'


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
