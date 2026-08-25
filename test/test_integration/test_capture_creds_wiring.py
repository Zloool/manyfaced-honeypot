"""Regression guard for issue #627.

The server-first interactive capture path
(``_capture_credentials`` in ``manyfaced/client/client.py``) must honour a
non-HTTP face's dedicated ``spec.extract_creds`` extractor (FTP / POP3 / IMAP /
MySQL / MSSQL). Previously it only ran the generic ``_parse_plaintext_credentials``
parser, which never invoked the face-specific extractors, so faces with
``capture_creds=True`` captured **zero** credentials despite the extractor
existing. This test proves the wiring now routes the client's auth frame to
``spec.extract_creds``.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from manyfaced.client.client import _capture_credentials
from manyfaced.client.cred_extractors import extract_ftp_credentials, extract_pop3_credentials
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


if __name__ == '__main__':
    unittest.main()
