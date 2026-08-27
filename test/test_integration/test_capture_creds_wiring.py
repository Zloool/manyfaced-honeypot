"""Regression guard for issue #627.

The server-first interactive capture path
(``_capture_credentials`` in ``manyfaced/client/client.py``) must honour a
non-HTTP face's dedicated ``spec.extract_creds`` extractor (FTP / POP3 / IMAP /
MySQL / MSSQL). Previously it only ran the generic ``_parse_plaintext_credentials``
parser, which never invoked the face-specific extractors, so faces with
``capture_creds=True`` captured **zero** credentials despite the extractor
existing. This test proves the wiring now routes the client's auth frame to
``spec.extract_creds``.

It also proves the residual gap closed by the seed-accumulation fix: real
FTP/POP3/IMAP clients send USER then PASS as SEPARATE round-trips, and the USER
frame is consumed by the server to pick its reply. The capture path must seed
that first frame into the extractor so both halves are paired instead of the
username being dropped (issue #627).
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from manyfaced.client.client import _capture_credentials
from manyfaced.client.cred_extractors import (
    extract_ftp_credentials,
    extract_imap_credentials,
    extract_pop3_credentials,
)
from manyfaced.common.faces import FaceSpec


class _FakeSpec:
    """Minimal stand-in carrying only what ``_capture_credentials`` reads."""

    def __init__(self, name: str, extract_creds):
        self.name = name
        self.extract_creds = extract_creds


def _ftp_spec() -> FaceSpec:
    return FaceSpec(
        name='ftp',
        detected_id=4294967292,
        direction='server-first',
        greeting=b'220 FTP ready\r\n',
        respond=None,
        capture_creds=True,
        extract_creds=extract_ftp_credentials,
    )


def _pop3_spec() -> FaceSpec:
    return FaceSpec(
        name='pop3',
        detected_id=4294967292,
        direction='server-first',
        greeting=b'+OK POP3 ready\r\n',
        respond=None,
        capture_creds=True,
        extract_creds=extract_pop3_credentials,
    )


def _make_socket(first_recv: bytes) -> MagicMock:
    """Socket whose first recv returns the auth frame, then closes."""
    sock = MagicMock()
    sock.recv.side_effect = [first_recv, b'']
    return sock


def _build_ssh_userauth_request(username: bytes, password: bytes) -> bytes:
    """Construct a minimal, SSH-spec-compliant USERAUTH_REQUEST binary packet.

    SSH framing is ``[uint32 packet_length][byte padding_length][payload]`` where
    ``packet_length`` counts everything *after* the 4-byte length field (i.e. it
    includes the 1-byte padding_length). The honeypot parser
    (``_parse_ssh_binary_protocol``) walks exactly this layout, so the probe must
    honour it or the last field gets truncated (issue #628 regression guard).
    """

    def _ssh_str(b: bytes) -> bytes:
        return len(b).to_bytes(4, 'big') + b

    message = (
        b'\x32'  # message code USERAUTH_REQUEST
        + _ssh_str(username)
        + _ssh_str(b'ssh-connection')
        + _ssh_str(b'password')
        + b'\x01'  # FALSE (no password change requested)
        + _ssh_str(password)
    )
    pkt_len = 1 + len(message)  # padding_length byte + payload
    return pkt_len.to_bytes(4, 'big') + b'\x00' + message


class TestSshCredentialCapture(unittest.TestCase):
    """Regression guard for issue #628: SSH credential capture.

    SSH uses a bespoke binary protocol parser
    (``manyfaced.client.ssh_creds._capture_ssh_credentials`` /
    ``_parse_ssh_binary_protocol``) reached from ``_capture_credentials`` when
    the greeting starts with ``SSH-``. The brittle ``find(b'\\x32')`` approach was
    replaced by length-prefixed frame walking; these tests prove a real
    USERAUTH_REQUEST yields the captured username/password so the fix cannot
    silently regress.
    """

    def test_parse_userauth_request_yields_user_and_password(self):
        from manyfaced.client.ssh_creds import _parse_ssh_binary_protocol

        frame = _build_ssh_userauth_request(b'root', b'vizxv')
        creds = _parse_ssh_binary_protocol(frame)
        self.assertEqual(creds, 'user=root, pass=vizxv')

    def test_ssh_capture_wired_through_capture_credentials(self):
        frame = _build_ssh_userauth_request(b'admin', b's3cret')
        sock = _make_socket(frame)
        spec = FaceSpec(
            name='ssh',
            detected_id=4294967284,
            direction='server-first',
            greeting=b'SSH-2.0-manyfaced\r\n',
            respond=None,
            capture_creds=True,
            extract_creds=None,
        )
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec)
        self.assertEqual(creds, 'user=admin, pass=s3cret')


class TestCaptureCredsWiring(unittest.TestCase):
    def test_ftp_extractor_is_invoked_on_auth_frame(self):
        # A real FTP client sends USER then PASS on the wire.
        frame = b'USER scanner\r\nPASS hunter2\r\n'
        sock = _make_socket(frame)
        spec = _ftp_spec()
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec)
        # extract_ftp_credentials returns "<user>:<pass>".
        self.assertEqual(creds, 'scanner:hunter2')
        sock.recv.assert_called()

    def test_pop3_extractor_is_invoked_on_auth_frame(self):
        frame = b'USER bob\r\nPASS s3cret\r\n'
        sock = _make_socket(frame)
        spec = _pop3_spec()
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec)
        self.assertEqual(creds, 'bob:s3cret')

    def test_extractor_not_called_when_absent(self):
        # No extractor -> falls through to the interactive parser (no crash),
        # and an empty frame yields no creds rather than raising.
        sock = _make_socket(b'')
        spec = FaceSpec(
            name='ssh',
            detected_id=4294967284,
            direction='server-first',
            greeting=b'SSH-2.0-manyfaced\r\n',
            respond=None,
            capture_creds=True,
            extract_creds=None,
        )
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec)
        self.assertIsNone(creds)

    def test_ftp_user_pass_separate_frames_accumulated(self):
        # Real FTP clients send USER then PASS as SEPARATE round-trips. The
        # USER frame is consumed by the server to choose its 331 reply and must
        # be seeded into capture; otherwise only the post-reply PASS frame is
        # seen and the username is dropped (issue #627 residual gap).
        sock = _make_socket(b'PASS hunter2\r\n')
        spec = _ftp_spec()
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec, seed=b'USER scanner\r\n')
        self.assertEqual(creds, 'scanner:hunter2')

    def test_pop3_user_pass_separate_frames_accumulated(self):
        sock = _make_socket(b'PASS s3cret\r\n')
        spec = _pop3_spec()
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec, seed=b'USER bob\r\n')
        self.assertEqual(creds, 'bob:s3cret')

    def test_imap_user_pass_separate_frames_accumulated(self):
        # IMAP extractor also handles the older USER/PASS style (not just
        # ``a001 LOGIN user pass``), and those can arrive as separate frames.
        sock = _make_socket(b'PASS s3cret\r\n')
        spec = FaceSpec(
            name='imap',
            detected_id=4294967292,
            direction='server-first',
            greeting=b'* OK IMAP ready\r\n',
            respond=None,
            capture_creds=True,
            extract_creds=extract_imap_credentials,
        )
        creds = _capture_credentials(sock, '1.2.3.4', spec.greeting, spec, seed=b'USER bob\r\n')
        self.assertEqual(creds, 'bob:s3cret')


if __name__ == '__main__':
    unittest.main()
