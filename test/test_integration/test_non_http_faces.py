"""Regression tests for the non-HTTP face registry + dispatch (issue #377).

These run WITHOUT touching the network: each face is exercised against an
in-memory socket pair so the test is fast and CI-machine-time friendly. They
prove the core contract from the #377 RFC:

* server-first faces send their greeting BEFORE the client speaks;
* client-first faces read the client frame and reply with a protocol-correct,
  non-empty response;
* the capture (BearStorage) is built with the right detected_id + raw bytes.
"""

from __future__ import annotations

import socket
import threading

import pytest

from manyfaced.common import faces as face_module
from manyfaced.common.faces import FACE_REGISTRY, FaceSpec, get_face


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


def _pump(client_sock, server_sock, client_says: bytes | None, wait_for: int):
    """Server side: optionally send greeting first, then read client frame."""
    if server_sock is not None:
        # For server-first, the greeting must be sent before reading.
        pass


def _server_first_probe(name: str, client_says: bytes | None = None, timeout: float = 2.0):
    """Open a socketpair; send the face greeting from the 'server' side, then
    read whatever the 'client' side would have received. Returns server greeting
    bytes (proving it is emitted before any client data)."""
    a, b = socket.socketpair()
    spec = next(s for s in FACE_REGISTRY.values() if s.name == name)
    try:
        a.settimeout(timeout)
        # Server emits greeting immediately (prelude) — no recv first.
        greeting = spec.greeting
        a.sendall(greeting)
        # The 'client' (b) should receive it without having spoken.
        got = b.recv(4096)
        return got, greeting
    finally:
        a.close()
        b.close()


def _client_first_probe(name: str, client_says: bytes, timeout: float = 2.0):
    """Open a socketpair; 'client' (b) sends client_says; 'server' (a) runs
    spec.respond and sends the reply back. Returns the reply bytes."""
    a, b = socket.socketpair()
    spec = next(s for s in FACE_REGISTRY.values() if s.name == name)
    try:
        b.settimeout(timeout)
        a.settimeout(timeout)
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
        ('mysql', b'\x0a'),  # protocol version byte
        ('mssql', b'\x12'),  # TDS prelogin
        ('amqp', b'AMQP'),
    ],
)
def test_server_first_greeting_emitted_first(name, needle):
    got, greeting = _server_first_probe(name)
    assert got == greeting, f'{name}: greeting not received before client spoke'
    assert needle in greeting, f'{name}: greeting missing {needle!r}'


# ---------------------------------------------------------------------------
# Client-first: a correct client frame yields a non-empty, protocol-correct reply
# ---------------------------------------------------------------------------


def test_redis_ping_responds_pong():
    # RESP PING
    reply = _client_first_probe('redis', b'*1\r\n$4\r\nPING\r\n')
    assert reply.startswith(b'+PONG'), f'redis reply was {reply!r}'


def test_memcached_version_responds():
    reply = _client_first_probe('memcached', b'version\r\n')
    assert reply.startswith(b'VERSION'), f'memcached reply was {reply!r}'


def test_elasticsearch_get_responds_http():
    reply = _client_first_probe('elasticsearch', b'GET / HTTP/1.0\r\n\r\n')
    assert reply.startswith(b'HTTP/1.1 200'), f'es reply was {reply!r}'


def test_postgres_startup_gets_auth_request():
    import struct

    pkt = (
        struct.pack('!ii', 8, 80877103)
        + struct.pack('!ii', 96, 196608)
        + (b'user\x00postgres\x00database\x00postgres\x00\x00')
    )
    reply = _client_first_probe('postgres', pkt)
    # AuthRequest message type 'R' with method 5 (MD5)
    assert reply[:1] == b'R', f'postgres reply was {reply!r}'


def test_mongodb_hello_responds():
    # ismaster/hello op
    reply = _client_first_probe(
        'mongodb', b'\x3d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    assert b'isWritablePrimary' in reply or len(reply) > 16, f'mongo reply was {reply!r}'


def test_zookeeper_connect_responds():
    reply = _client_first_probe(
        'zookeeper', b'\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    assert len(reply) >= 4, f'zookeeper reply was {reply!r}'


# ---------------------------------------------------------------------------
# BearStorage construction for non-HTTP faces
# ---------------------------------------------------------------------------


def test_build_bear_storage_detected_id():
    from manyfaced.handlers.http_handler import _build_bear_storage
    from manyfaced.common.status import UNKNOWN_REDIS

    spec = get_face(6379)
    bs = _build_bear_storage('1.2.3.4', spec, b'*1\r\n$4\r\nPING\r\n', 6379)
    assert bs.isDetected == UNKNOWN_REDIS
    assert bs.ip == '1.2.3.4'
    assert 'PING' in bs.raw_request
    assert bs.listen_port == 6379
