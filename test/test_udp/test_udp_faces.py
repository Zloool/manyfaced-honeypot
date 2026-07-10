"""Tests for the UDP transport + SIP/SNMP faces (issue #388/#389/#390).

Validates that:
- protocol detection classifies SIP and SNMP UDP payloads
- the UDP face registry resolves SIP (5060) and SNMP (161)
- _sip_respond / _snmp_respond return plausible, parseable replies
- a full UDP datagram round-trip (recvfrom -> respond -> sendto) records a capture
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common import faces as _faces
from manyfaced.common import ports as _ports
from manyfaced.common import status as _status
from manyfaced.common.protocol import detect_protocol


class TestUdpDetection(unittest.TestCase):
    def test_sip_detected(self):
        sip = b'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4\r\n'
        self.assertEqual(detect_protocol(sip), 'sip')

    def test_snmp_detected(self):
        snmp = (
            b'\x30\x26\x02\x01\x00\x04\x06public'
            b'\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00'
            b'\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
        )
        self.assertEqual(detect_protocol(snmp), 'snmp')

    def test_tcp_detection_unaffected(self):
        self.assertEqual(detect_protocol(b'GET / HTTP/1.1\r\n'), 'http')
        self.assertEqual(detect_protocol(b'SSH-2.0-OpenSSH'), 'ssh')


class TestUdpRegistry(unittest.TestCase):
    def test_sip_face_resolves(self):
        spec = _faces.get_udp_face(5060)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.name, 'sip')
        self.assertEqual(spec.detected_id, _status.UNKNOWN_SIP)
        self.assertTrue(spec.capture_creds)

    def test_snmp_face_resolves(self):
        spec = _faces.get_udp_face(161)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.name, 'snmp')
        self.assertEqual(spec.detected_id, _status.UNKNOWN_SNMP)

    def test_bound_high_port_resolves_via_redirect(self):
        # 161 is privileged; in prod it redirects to 10161. The resolver must
        # map the bound port back to the external 161 face.
        spec = _faces.get_udp_face(10161)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.name, 'snmp')

    def test_non_udp_port_is_none(self):
        self.assertIsNone(_faces.get_udp_face(99999))


class TestUdpResponses(unittest.TestCase):
    def test_sip_register_401(self):
        raw = b'REGISTER sip:manyfaced SIP/2.0\r\n'
        out = _faces._sip_respond(raw, '1.2.3.4')
        self.assertTrue(out.startswith(b'SIP/2.0 401'))
        self.assertIn(b'WWW-Authenticate', out)

    def test_sip_options_200(self):
        raw = b'OPTIONS sip:manyfaced SIP/2.0\r\n'
        out = _faces._sip_respond(raw, '1.2.3.4')
        self.assertTrue(out.startswith(b'SIP/2.0 200'))

    def test_snmp_public_sysdescr(self):
        snmp = (
            b'\x30\x26\x02\x01\x00\x04\x06public'
            b'\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00'
            b'\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
        )
        out = _faces._snmp_respond(snmp, '1.2.3.4')
        self.assertTrue(out.startswith(b'\x30'))
        # response carries the sysDescr string we injected
        self.assertIn(b'Manyfaced Router', out)

    def test_snmp_wrong_community_silent(self):
        snmp = (
            b'\x30\x26\x02\x01\x00\x04\x03private'
            b'\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00'
            b'\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
        )
        out = _faces._snmp_respond(snmp, '1.2.3.4')
        self.assertEqual(out, b'')


class TestUdpDatagramRoundTrip(unittest.TestCase):
    """Exercise _handle_udp_datagram with a fake socket + stubbed enrichment."""

    def _run(self, data: bytes, listen_port: int, spec_name: str):
        # Stub the enrichment so no real DB/geo happens in the test.
        import manyfaced.client.client as _client

        sent = {}

        class _FakeSock:
            def settimeout(self, *_a):
                pass

            def recvfrom(self, _n):
                raise TimeoutError  # not used directly here

            def sendto(self, payload, addr):
                sent['payload'] = payload
                sent['addr'] = addr

        bs_capture = {}

        def _fake_build(bot_ip, spec, raw, lp):
            from manyfaced.common.bearstorage import BearStorage
            from datetime import datetime, timezone

            class _P:
                command = spec.name.upper()
                path = '/'
                version = ''
                headers = {}
                user_agent = spec.name

            b = BearStorage(
                bot_ip,
                raw.decode('latin-1', 'replace'),
                str(datetime.now(timezone.utc)),
                _P(),
                spec.detected_id,
                'test',
            )
            b.listen_port = lp
            return b

        def _fake_enrich(bs, bot_ip):
            bs_capture['bs'] = bs

        import manyfaced.handlers.http_handler as _hh

        orig_build = _hh._build_bear_storage
        orig_enrich = _hh._enrich_and_send_bear
        _hh._build_bear_storage = _fake_build
        _hh._enrich_and_send_bear = _fake_enrich
        try:
            sock = _FakeSock()
            args = MagicMock()
            args.verbose = False
            _client._handle_udp_datagram(sock, data, ('9.9.9.9', 5050), args, listen_port)
        finally:
            _hh._build_bear_storage = orig_build
            _hh._enrich_and_send_bear = orig_enrich
        return sent, bs_capture

    def test_sip_roundtrip(self):
        sent, cap = self._run(b'REGISTER sip:manyfaced SIP/2.0\r\n', 5060, 'sip')
        self.assertIn('payload', sent)
        self.assertTrue(sent['payload'].startswith(b'SIP/2.0 401'))
        self.assertIn('bs', cap)
        self.assertEqual(cap['bs'].isDetected, _status.UNKNOWN_SIP)

    def test_snmp_roundtrip(self):
        snmp = (
            b'\x30\x26\x02\x01\x00\x04\x06public'
            b'\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00'
            b'\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
        )
        sent, cap = self._run(snmp, 161, 'snmp')
        self.assertIn('payload', sent)
        self.assertIn(b'Manyfaced Router', sent['payload'])
        self.assertEqual(cap['bs'].isDetected, _status.UNKNOWN_SNMP)


if __name__ == '__main__':
    unittest.main()
