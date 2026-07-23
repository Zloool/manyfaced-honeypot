"""Integration tests for protocol-specific handlers (Redis, MongoDB, Telnet, RDP, VNC).

Tests response generation and credential capture for each protocol handler.
"""

from __future__ import annotations

import json
import random
import struct
import unittest
from datetime import datetime, timezone
from io import BytesIO
from socketserver import BaseRequestHandler, TCPServer
from threading import Thread
from unittest.mock import MagicMock, patch

from manyfaced.common.bearstorage import BearStorage
from manyfaced.handlers.mongodb_handler import (
    extract_mongodb_credentials,
    generate_mongodb_greeting,
    generate_mongodb_response,
)
from manyfaced.handlers.rdp_handler import (
    extract_rdp_credentials,
    generate_rdp_greeting,
    generate_rdp_response,
)
from manyfaced.handlers.redis_handler import (
    extract_redis_credentials,
    generate_redis_greeting,
    generate_redis_response,
)
from manyfaced.handlers.telnet_handler import (
    _strip_iac,
    extract_telnet_credentials,
    generate_auth_failure,
    generate_auth_success,
    generate_password_prompt,
    generate_telnet_greeting,
    generate_telnet_response,
)
from manyfaced.handlers.vnc_handler import (
    extract_vnc_credentials,
    generate_vnc_greeting,
    generate_vnc_response,
)


class TestRedisHandler(unittest.TestCase):
    """Test Redis RESP protocol handler."""

    def test_redis_ping_response(self):
        """PING command should return +PONG response."""
        raw_data = b'*1\r\n$4\r\nPING\r\n'
        response = generate_redis_response(raw_data, '10.0.0.1')
        self.assertIn(b'+PONG', response)

    def test_redis_auth_credential_capture(self):
        """AUTH command should capture username and password and be accepted."""
        raw_data = b'*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$6\r\npassword123\r\n'
        response = generate_redis_response(raw_data, '10.0.0.2')
        creds = extract_redis_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'admin')
        self.assertEqual(creds[1], 'password123')
        self.assertEqual(response, b'+OK\r\n')

    def test_redis_noauth_response(self):
        """Unauthenticated data commands on a honeypot still get a benign reply.

        We no longer hard-fail with -NOAUTH (that broke redis-py sessions);
        GET/SET/etc. now return protocol-valid replies.
        """
        raw_data = b'*1\r\n$4\r\nKEYS\r\n'
        response = generate_redis_response(raw_data, '10.0.0.3')
        self.assertNotIn(b'-NOAUTH', response)

    def test_redis_hello_resp3_reply_is_map(self):
        """HELLO 3 must return a RESP3 map redis-py can parse into a dict (issue #382)."""
        raw = b'*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n'
        resp = generate_redis_response(raw, '10.0.0.5')
        self.assertTrue(resp.startswith(b'%7\r\n'))
        for key in (b'server', b'version', b'proto', b'id', b'mode', b'role', b'modules'):
            self.assertIn(key, resp)

    def test_redis_hello_resp2_reply_is_array(self):
        """HELLO 2 must return a RESP2 flat array of interleaved key/values."""
        raw = b'*2\r\n$5\r\nHELLO\r\n$1\r\n2\r\n'
        resp = generate_redis_response(raw, '10.0.0.6')
        self.assertTrue(resp.startswith(b'*14\r\n'))
        self.assertIn(b'server', resp)

    def test_redis_set_get_replies(self):
        """redis-py .set()/.get() need +OK and a bulk/nil reply (issue #382)."""
        set_r = generate_redis_response(b'*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n', '10.0.0.7')
        self.assertEqual(set_r, b'+OK\r\n')
        get_r = generate_redis_response(b'*2\r\n$3\r\nGET\r\n$1\r\nk\r\n', '10.0.0.7')
        self.assertEqual(get_r, b'$-1\r\n')

    def test_redis_greeting(self):
        """Redis is client-first: no banner is sent on connect (issue #382)."""
        greeting = generate_redis_greeting('10.0.0.4')
        self.assertEqual(greeting, b'')


class TestMongoDBHandler(unittest.TestCase):
    """Test MongoDB Wire Protocol handler."""

    def test_mongodb_ismaster_response(self):
        """ismaster command should return replica set info."""
        raw_data = b'\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80\x04\x00\x00\x7b\x22\x69\x73\x6d\x61\x73\x74\x65\x72\x22\x3a\x74\x72\x75\x65\x2c\x22\x6f\x6b\x22\x3a\x31\x2e\x30\x7d'
        response = generate_mongodb_response(raw_data, '10.0.0.1')
        self.assertGreater(len(response), 0)

    def test_mongodb_auth_credential_capture(self):
        """authenticate command should capture credentials."""
        raw_data = b'\x81\x07\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80\x04\x00\x00\x7b\x22\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x22\x3a\x31\x2c\x22\x75\x73\x65\x72\x22\x3a\x22\x61\x64\x6d\x69\x6e\x22\x2c\x22\x70\x72\x69\x6d\x61\x72\x79\x22\x3a\x22\x6c\x6f\x63\x61\x6c\x22\x2c\x22\x6b\x65\x79\x22\x3a\x22\x61\x64\x6d\x69\x6e\x3a\x70\x61\x73\x73\x77\x6f\x72\x64\x31\x32\x33\x22\x7d'
        response = generate_mongodb_response(raw_data, '10.0.0.2')
        creds = extract_mongodb_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'admin')

    def test_mongodb_saslstart_challenge(self):
        """saslStart command should return authentication challenge."""
        raw_data = b'\x81\x07\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80\x04\x00\x00\x7b\x22\x73\x61\x73\x6c\x53\x74\x61\x72\x74\x22\x3a\x31\x2c\x22\x6d\x65\x63\x68\x61\x6e\x69\x73\x6d\x22\x3a\x22\x53\x43\x52\x41\x4d\x2d\x53\x48\x41\x2d\x31\x22\x7d'
        response = generate_mongodb_response(raw_data, '10.0.0.3')
        self.assertIn(b'"done":false', response)

    def test_mongodb_greeting(self):
        """Greeting should return empty bytes."""
        greeting = generate_mongodb_greeting('10.0.0.4')
        self.assertEqual(greeting, b'')

    def _build_op_msg_request(self, command_doc: dict) -> bytes:
        """Helper: build a well-formed OP_MSG request carrying ``command_doc``.

        The frame is a real on-the-wire OP_MSG (opcode 2013) with a single
        kind-0 body section holding ``command_doc`` as BSON.
        """
        from manyfaced.handlers.mongodb_handler import (
            _bson_encode_doc,
            _build_op_msg,
        )

        # Use a throwaway request id so we don't disturb the shared counter.
        request_id = 0xDEADBEEF
        message_length = 16 + 4 + 1 + len(_bson_encode_doc(command_doc))
        body = struct.pack('<I', 0)  # flagBits (no checksum)
        body += b'\x00' + _bson_encode_doc(command_doc)  # kind 0 body section
        # hand-build the header so we can set a known request id / opcode
        return (
            struct.pack('<I', message_length)
            + struct.pack('<I', request_id)
            + struct.pack('<I', 0)  # responseTo
            + struct.pack('<I', 2013)  # OP_MSG
            + body
        )

    def _decode_op_msg_reply(self, raw: bytes) -> dict:
        """Decode a kind-0 OP_MSG reply body into a python dict (for assertions)."""
        from manyfaced.handlers.mongodb_handler import _bson_decode_doc

        # header(16) + flagBits(4) + sectionKind(1) + BSON doc
        (opcode,) = struct.unpack_from('<I', raw, 12)
        self.assertEqual(opcode, 2013)
        return _bson_decode_doc(raw, 21)[0]

    def test_mongodb_op_msg_hello_reply_is_op_msg(self):
        """A modern driver's OP_MSG hello must get an OP_MSG (2013) reply (#646).

        Regression: the handler used to always answer OP_MSG with a legacy
        OP_REPLY (opcode 1), which makes every 4.2+ driver bail out of the
        handshake immediately.
        """
        from manyfaced.handlers.mongodb_handler import OP_MSG

        raw = self._build_op_msg_request({'hello': 1, 'client': {'driver': {'name': 'pymongo'}}})
        response = generate_mongodb_response(raw, '10.0.0.5')
        # Opcode must be OP_MSG (2013), never the legacy OP_REPLY (1).
        (opcode,) = struct.unpack_from('<I', response, 12)
        self.assertEqual(opcode, OP_MSG)
        self.assertNotEqual(opcode, 1)
        # The reply must be a valid hello-style document that the driver can
        # parse, echoing the request id as responseTo.
        (response_to,) = struct.unpack_from('<I', response, 8)
        self.assertEqual(response_to, 0xDEADBEEF)
        doc = self._decode_op_msg_reply(response)
        self.assertEqual(doc.get('ok'), 1.0)
        self.assertTrue(doc.get('ismaster'))
        self.assertTrue(doc.get('helloOk'))

    def test_mongodb_op_msg_ismaster_alias_reply(self):
        """OP_MSG isMaster (legacy alias) must also get an OP_MSG hello reply (#646)."""
        from manyfaced.handlers.mongodb_handler import OP_MSG

        raw = self._build_op_msg_request({'isMaster': 1})
        response = generate_mongodb_response(raw, '10.0.0.6')
        (opcode,) = struct.unpack_from('<I', response, 12)
        self.assertEqual(opcode, OP_MSG)
        doc = self._decode_op_msg_reply(response)
        self.assertEqual(doc.get('ok'), 1.0)
        self.assertTrue(doc.get('ismaster'))
        # isMaster-style responders must still report the replica set name.
        self.assertEqual(doc.get('setName'), 'honeypot-rs')

    def test_mongodb_op_msg_reply_roundtrips_bson(self):
        """generate_op_msg_reply produces BSON a real driver-style parse can read."""
        from manyfaced.handlers.mongodb_handler import generate_op_msg_reply

        raw = self._build_op_msg_request({'hello': 1})
        reply = generate_op_msg_reply(raw, '10.0.0.7')
        doc = self._decode_op_msg_reply(reply)
        self.assertIn('authMechanisms', doc)
        self.assertIsInstance(doc['authMechanisms'], list)
        self.assertIn('SCRAM-SHA-256', doc['authMechanisms'])


class TestTelnetHandler(unittest.TestCase):
    """Test Telnet protocol handler."""

    def test_telnet_iac_negotiation(self):
        """IAC negotiation should return appropriate responses."""
        raw_data = b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f'
        response = generate_telnet_response(raw_data, '10.0.0.1')
        self.assertGreater(len(response), 0)

    def test_telnet_login_credential_capture(self):
        """Login interaction should capture username and password."""
        raw_data = b'\r\nlogin: admin\r\nPassword: secret123'
        response = generate_telnet_response(raw_data, '10.0.0.2')
        creds = extract_telnet_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'admin')
        self.assertEqual(creds[1], 'secret123')

    def test_telnet_greeting(self):
        """Greeting should return login prompt."""
        greeting = generate_telnet_greeting('10.0.0.3')
        self.assertIn(b'login:', greeting)

    def test_password_prompt(self):
        """Password prompt should be generated correctly."""
        prompt = generate_password_prompt()
        self.assertEqual(prompt, b'\r\nPassword: ')

    def test_telnet_greeting_uses_do_echo(self):
        """Greeting must start with IAC DO ECHO, not IAC WILL ECHO (#467)."""
        greeting = generate_telnet_greeting('127.0.0.1')
        self.assertIn(b'\xff\xfd\x03', greeting)  # IAC DO ECHO
        self.assertNotIn(b'\xff\xfb\x03', greeting)  # must NOT be IAC WILL ECHO

    def test_telnet_negotiation_accepts_echo(self):
        """Client DO ECHO -> server answers WILL ECHO; client WILL ECHO -> DO ECHO (#467)."""
        from manyfaced.handlers.telnet_handler import (
            DO,
            IAC,
            WILL,
            _handle_telnet_negotiation,
        )

        # Client asks server to DO ECHO (rfc854 correct client behaviour).
        resp = _handle_telnet_negotiation(IAC + DO + b'\x03', '127.0.0.1')
        self.assertEqual(resp, IAC + WILL + b'\x03')
        # Client offers WILL ECHO (server asks it to echo).
        resp2 = _handle_telnet_negotiation(IAC + WILL + b'\x03', '127.0.0.1')
        self.assertEqual(resp2, IAC + DO + b'\x03')

    def test_telnet_mirai_frame_emits_password_prompt(self):
        """A Mirai-style IAC+username frame must yield a Password: prompt.

        Regression for issue #598: the old handler short-circuited any frame
        containing 0xff to negotiation-only reflexive ACKs, dropping the
        embedded username and never emitting a Password: prompt.
        """
        # Typical Mirai first auth frame: IAC negotiation + the typed username.
        raw_data = (
            b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f'  # IAC WILL BIN/WILL ECHO/DO NAWS
            b'root\x0d\x0a'
        )
        response = generate_telnet_response(raw_data, '10.0.0.99')
        # Must NOT be negotiation-only -- it has to ask for the password.
        self.assertIn(b'Password: ', response)
        # The username must be reflected back in the server log/state path
        # (i.e. the frame was parsed, not discarded).
        creds = extract_telnet_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'root')

    def test_telnet_strip_iac_keeps_username(self):
        """_strip_iac must remove IAC bytes but preserve the typed username."""
        raw_data = b'\xff\xfb\x01\xff\xfb\x03root\x0d\x0a'
        self.assertEqual(_strip_iac(raw_data), b'root\x0d\x0a')

    def test_telnet_full_credentials_frame_succeeds_auth(self):
        """A frame carrying both username and password gets an auth-success.

        The dialogue must look complete (a shell prompt), not a failure +
        re-prompt, so extract_telnet_credentials has the full login:/Password:
        exchange to parse (issue #626).
        """
        raw_data = b'\xff\xfb\x01\x0d\x0alogin: admin\x0d\x0aPassword: secret123'
        response = generate_telnet_response(raw_data, '10.0.0.100')
        self.assertIn(generate_auth_success().split(b'\x0d\x0a')[0], response)
        # Successful auth yields a shell prompt, not a fresh login prompt: the
        # response must end with the shell prompt rather than 'login: '.
        self.assertTrue(response.endswith(b'$ '))

    def test_telnet_root_pass_login_emits_auth_success_and_parses(self):
        """Full 'root'/'pass' exchange yields an auth-success frame and parses.

        End-to-end regression for issue #626: a complete login: root / Password:
        pass exchange must produce a believable auth-success shell prompt, and
        the raw exchange fed back to extract_telnet_credentials must parse to
        ('root', 'pass') so the captured login is surfaced.
        """
        # A realistic Mirai-style frame: IAC negotiation + the typed username,
        # followed by the password frame. extract_telnet_credentials operates on
        # the whole accumulated raw exchange the CORE hands us.
        username_frame = b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1froot\x0d\x0a'
        password_frame = b'\xff\xfb\x01\x0d\x0aPassword: pass\x0d\x0a'
        raw_exchange = username_frame + password_frame

        # Server first asks for the password (username seen, no password yet).
        first = generate_telnet_response(username_frame, '10.0.0.101')
        self.assertIn(b'Password: ', first)

        # After the password arrives the dialogue completes with auth-success.
        response = generate_telnet_response(raw_exchange, '10.0.0.101')
        self.assertIn(b'$ ', response)  # shell prompt == auth success
        # Sanity-check the success frame shape without over-coupling to the
        # random banner choice.
        self.assertTrue(response.endswith(b'$ '))

        # The full exchange must be parseable into the captured credentials.
        creds = extract_telnet_credentials(raw_exchange)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'root')
        self.assertEqual(creds[1], 'pass')


class TestRDPHandler(unittest.TestCase):
    """Test RDP protocol handler."""

    def test_rdp_initial_response(self):
        """Initial response should return TPKT/X.224 connection confirm."""
        raw_data = b''
        response = generate_rdp_response(raw_data, '10.0.0.1')
        self.assertGreater(len(response), 0)

    def test_rdp_nla_challenge(self):
        """NLA challenge should be generated for authentication data."""
        # Use realistic NLA/TSRequest format with username and password
        raw_data = (
            b'\x03\x00\x00\x1f\x0e\xe0\x00\x00\x18\x00\x01\xc1\x00\x00\x00'
            + b'<TSRequest><Credentials><userName>admin</userName><password>secret123</password></Credentials></TSRequest>'
        )
        response = generate_rdp_response(raw_data, '10.0.0.2')
        creds = extract_rdp_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'admin')

    def test_rdp_greeting(self):
        """Greeting should return TPKT/X.224 response."""
        greeting = generate_rdp_greeting('10.0.0.3')
        self.assertGreater(len(greeting), 0)

    def test_rdp_tpkt_length_matches_actual_bytes(self):
        """Every RDP generator's TPKT length field must equal the actual bytes.

        Regression for #470: the TPKT length was hard-coded (31 / 47) and did
        not match the on-the-wire byte count, so real RDP clients desync.
        """
        for name, gen in (
            ('initial', generate_rdp_greeting('127.0.0.1')),
            (
                'nla',
                generate_rdp_response(
                    b'\x03\x00\x00\x1f\x0e\xe0' + b'<TSRequest>nla</TSRequest>', '127.0.0.1'
                ),
            ),
            (
                'connection_confirm',
                generate_rdp_response(b'\x03\x00\x00\x1f' + b'\x00' * 17, '127.0.0.1'),
            ),
        ):
            frame = gen
            # TPKT version + reserved = 2 bytes; length is the next 2 bytes (big-endian),
            # counting the bytes AFTER the 4-byte TPKT header (x224 + payload).
            self.assertEqual(frame[:2], b'\x03\x00', f'{name}: not a TPKT header')
            tpkt_len = struct.unpack('!H', frame[2:4])[0]
            self.assertEqual(
                tpkt_len,
                len(frame) - 4,
                f'{name}: TPKT length {tpkt_len} != actual {len(frame) - 4}',
            )

    def test_rdp_nla_challenge_has_tpkt_framing(self):
        """NLA challenge must be wrapped in a TPKT + X.224 envelope (#470)."""
        raw = b'\x03\x00\x00\x1f' + b'<TSRequest>nla-token</TSRequest>'
        resp = generate_rdp_response(raw, '127.0.0.1')
        # Must start with a TPKT header, not bare ASN.1 SEQUENCE (0x30).
        self.assertEqual(resp[:2], b'\x03\x00')
        self.assertNotEqual(resp[4:5], b'\x30')


class TestVNCHandler(unittest.TestCase):
    """Test VNC protocol handler."""

    def test_vnc_version_string(self):
        """Version string should be returned for an empty / unknown frame."""
        raw_data = b''
        response = generate_vnc_response(raw_data, '10.0.0.1')
        self.assertGreater(len(response), 0)

    def test_vnc_auth_response_yields_result_and_serverinit(self):
        """A 16-byte auth response should return SecurityResult(OK) + ServerInit (#651)."""
        raw_data = bytes([random.randint(0, 255) for _ in range(16)])
        response = generate_vnc_response(raw_data, '10.0.0.2')
        # 4-byte SecurityResult == OK (0), followed by a non-empty ServerInit.
        self.assertEqual(response[0:4], bytes(4))
        self.assertGreater(len(response), 4)

    def test_vnc_credential_capture(self):
        """VNC auth attempt should capture credentials."""
        raw_data = bytes([random.randint(0, 255) for _ in range(16)])
        creds = extract_vnc_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'vnc-authenticated')
        self.assertEqual(creds[1], raw_data.hex())

    def test_vnc_greeting(self):
        """Greeting should return version string."""
        greeting = generate_vnc_greeting('10.0.0.3')
        self.assertIn(b'RFB', greeting)

    def test_vnc_version_negotiation_sends_security_types(self):
        """Client version must be answered with the security-types list (#651)."""
        greeting = generate_vnc_greeting('127.0.0.1')
        self.assertEqual(greeting, b'RFB 003.008\n')
        # On the client's version string, the server's NEXT message is the
        # security-types list (count byte + VNC Auth), NOT a version echo.
        reply = generate_vnc_response(b'RFB 003.003\n', '127.0.0.1')
        self.assertNotIn(b'RFB', reply)
        self.assertEqual(reply, bytes([1, 2]))  # one type: VNC Auth (2)

    def test_vnc_security_selection_yields_challenge(self):
        """Selecting a security type must return a 16-byte auth challenge (#651)."""
        # RFB 3.7+ client sends a single type byte (2 = VNC Auth).
        resp = generate_vnc_response(bytes([2]), '127.0.0.1')
        self.assertEqual(len(resp), 16)

    def test_vnc_full_handshake_captures_credentials(self):
        """Drive the whole handshake and assert a credential-capable exchange (#651).

        greeting -> client version -> security-types -> selection -> challenge
        -> client DES response (captured) -> SecurityResult(OK) + ServerInit.
        """
        greeting = generate_vnc_greeting('10.0.0.9')
        self.assertEqual(greeting, b'RFB 003.008\n')

        # Client version -> server security-types list.
        sec_types = generate_vnc_response(b'RFB 003.008\n', '10.0.0.9')
        self.assertEqual(sec_types[0], 1)  # count = 1
        self.assertIn(2, sec_types[1:])  # offers VNC Auth (type 2)

        # Client selects VNC Auth (2) -> server 16-byte challenge.
        challenge = generate_vnc_response(bytes([2]), '10.0.0.9')
        self.assertEqual(len(challenge), 16)

        # Client sends 16-byte DES response -> credentials captured.
        des_response = bytes([random.randint(0, 255) for _ in range(16)])
        creds = extract_vnc_credentials(des_response)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'vnc-authenticated')

        # Server replies SecurityResult(OK) + a non-empty ServerInit.
        final = generate_vnc_response(des_response, '10.0.0.9')
        self.assertEqual(final[0:4], bytes(4))  # SecurityResult OK
        server_init = final[4:]
        self.assertGreater(len(server_init), 0)
        width, height = struct.unpack('>HH', server_init[0:4])
        self.assertEqual((width, height), (1024, 768))

    def test_vnc_http_probe_returns_http_shaped_reply(self):
        """An HTTP probe on the VNC port must return an HTTP-shaped reply (#652)."""
        crlf = bytes([13, 10])
        for method in (
            b'GET / HTTP/1.1' + crlf + crlf,
            b'POST / HTTP/1.1' + crlf,
            b'HEAD / HTTP/1.0' + crlf,
        ):
            resp = generate_vnc_response(method, '10.0.0.7')
            self.assertTrue(resp.startswith(b'HTTP/1.1'), f'no HTTP reply for {method!r}')
            self.assertNotIn(b'RFB', resp)

    def test_vnc_masscan_probe_recognized(self):
        """The masscan MGLNDD_<ip>_<port> probe must be recognised (#652)."""
        resp = generate_vnc_response(b'MGLNDD_1.2.3.4_5900' + bytes([13, 10]), '10.0.0.8')
        self.assertIn(b'RFB', resp)


class TestProtocolHandlerIntegration(unittest.TestCase):
    """Integration tests for protocol handlers with HTTPHandler routing."""

    def test_redis_routing(self):
        """Redis probe should be routed to Redis handler."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: PLC0415

        raw_data = b'*1\r\n$4\r\nPING\r\n'
        protocol_info = {
            'protocol': 'redis',
            'raw': raw_data,
            'version': 'redis_test',
            'client': 'test-redis-bot',
        }

        # Create a mock HTTPHandler with minimal args
        mock_args = MagicMock()
        mock_update_event = MagicMock()
        handler = HTTPHandler(mock_args, mock_update_event)

        response, bear_storage = handler._handle_non_http_probe('10.0.0.1', 'redis', protocol_info)
        self.assertIn(b'+PONG', response)

    def test_mongodb_routing(self):
        """MongoDB probe should be routed to MongoDB handler."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: PLC0415

        raw_data = (
            b'\x81\x07\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80\x04\x00\x00'
        )
        protocol_info = {
            'protocol': 'mongodb',
            'raw': raw_data,
            'version': 'mongodb_test',
            'client': 'test-mongodb-bot',
        }

        mock_args = MagicMock()
        mock_update_event = MagicMock()
        handler = HTTPHandler(mock_args, mock_update_event)

        response, bear_storage = handler._handle_non_http_probe(
            '10.0.0.2', 'mongodb', protocol_info
        )
        self.assertGreater(len(response), 0)

    def test_telnet_routing(self):
        """Telnet probe should be routed to Telnet handler."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: PLC0415

        raw_data = b'\xff\xfb\x01\xff\xfb\x03'
        protocol_info = {
            'protocol': 'telnet',
            'raw': raw_data,
            'version': 'telnet_test',
            'client': 'test-telnet-bot',
        }

        mock_args = MagicMock()
        mock_update_event = MagicMock()
        handler = HTTPHandler(mock_args, mock_update_event)

        response, bear_storage = handler._handle_non_http_probe('10.0.0.3', 'telnet', protocol_info)
        self.assertGreater(len(response), 0)

    def test_rdp_routing(self):
        """RDP probe should be routed to RDP handler."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: PLC0415

        raw_data = b'\x03\x00\x00\x1f\x0e\xe0\x00\x00\x18\x00\x01\xc1\x00\x00\x00'
        protocol_info = {
            'protocol': 'rdp',
            'raw': raw_data,
            'version': 'rdp_test',
            'client': 'test-rdp-bot',
        }

        mock_args = MagicMock()
        mock_update_event = MagicMock()
        handler = HTTPHandler(mock_args, mock_update_event)

        response, bear_storage = handler._handle_non_http_probe('10.0.0.4', 'rdp', protocol_info)
        self.assertGreater(len(response), 0)

    def test_vnc_routing(self):
        """VNC probe should be routed to VNC handler."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: PLC0415

        raw_data = b'RFB 003.008\n'
        protocol_info = {
            'protocol': 'vnc',
            'raw': raw_data,
            'version': 'vnc_test',
            'client': 'test-vnc-bot',
        }

        mock_args = MagicMock()
        mock_update_event = MagicMock()
        handler = HTTPHandler(mock_args, mock_update_event)

        response, bear_storage = handler._handle_non_http_probe('10.0.0.5', 'vnc', protocol_info)
        self.assertGreater(len(response), 0)


if __name__ == '__main__':
    unittest.main()
