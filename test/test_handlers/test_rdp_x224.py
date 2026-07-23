"""Decode-based tests for RDP X.224/TPKT Connection-Confirm and NLA DT framing.

Regression coverage for issue #594: the X.224 TPDU header byte order was
inverted (the LI slot carried 0xE0 and the 0xD0 CC code sat in the
source-reference slot), so a real RDP client read the TPKT length fine but then
misread the inflated LI and waited for phantom bytes, desyncing/aborting.

See https://github.com/Zloool/manyfaced-honeypot/issues/594
"""

import os
import sys
import struct
import unittest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers.rdp_handler import (
    _generate_initial_response,
    _generate_connection_confirm,
    _generate_nla_challenge,
    generate_rdp_response,
    rdp_probe_signal,
)
from manyfaced.common.status import EMPTY_CONNECTION


def _parse_tpkt_x224(payload: bytes) -> 'tuple[int, int, int, int, bytes]':
    """Parse a TPKT+X.224 frame.

    Returns (tpkt_len, x224_len, li, code, x224_body).
    """
    self_version = payload[0]
    self_reserved = payload[1]
    tpkt_len = struct.unpack('!H', payload[2:4])[0]
    assert self_version == 0x03, f'TPKT version must be 3, got {self_version:#04x}'
    assert self_reserved == 0x00, f'TPKT reserved must be 0, got {self_reserved:#04x}'
    x224 = payload[4:]
    x224_len = len(x224)
    li = x224[0]
    code = x224[1]
    return tpkt_len, x224_len, li, code, x224


class TestRdpX224ConnectionConfirm(unittest.TestCase):
    """The X.224 TPDU header must be correctly ordered for a real client."""

    def test_initial_response_tpkt_length_matches_payload(self):
        payload = _generate_initial_response()
        tpkt_len, x224_len, li, code, _ = _parse_tpkt_x224(payload)
        # TPKT length field excludes the 4-byte TPKT header -> it equals x224_len.
        self.assertEqual(
            tpkt_len,
            x224_len,
            msg='TPKT length must equal the X.224 payload length',
        )

    def test_initial_response_x224_header_ordering(self):
        payload = _generate_initial_response()
        tpkt_len, x224_len, li, code, x224 = _parse_tpkt_x224(payload)
        # octet 0 is the Length Indicator, counting the *header* octets after it.
        # The standalone CC_TPDU has no user data, so LI == 6 (code + dst + src + opts).
        self.assertEqual(li, 0x06, msg='LI must be 0x06 for a 7-octet CC TPDU')
        # octet 1 is the CC code 0xD0 (high nibble 0xD), NOT the inverted 0xE0.
        self.assertEqual(code, 0xD0, msg='TPDU code must be 0xD0 (Connection-Confirm)')
        # The full X.224 TPDU must be a valid 7-octet CC header (LI 6 + 6 octets).
        self.assertEqual(x224_len, 1 + li)
        self.assertEqual(x224, b'\x06\xd0\x00\x00\x00\x00\x00')

    def test_connection_confirm_tpkt_length_matches_payload(self):
        payload = _generate_connection_confirm()
        tpkt_len, x224_len, li, code, _ = _parse_tpkt_x224(payload)
        # TPKT length covers the X.224 header AND the RDP_NEG_RSP user data.
        self.assertEqual(tpkt_len, x224_len, msg='TPKT length must cover x224 + neg rsp')

    def test_connection_confirm_x224_header_ordering(self):
        payload = _generate_connection_confirm()
        tpkt_len, x224_len, li, code, x224 = _parse_tpkt_x224(payload)
        # LI counts every octet after itself: 6 CC header octets + the 8-byte
        # RDP Negotiation Response user data (issue #630).
        self.assertEqual(li, 6 + 8, msg='LI must cover CC header + RDP_NEG_RSP')
        self.assertEqual(code, 0xD0, msg='TPDU code must be 0xD0 (Connection-Confirm)')
        self.assertEqual(x224_len, 1 + li)
        # The fixed header is correctly ordered: LI, CC code, dst, src, options.
        self.assertEqual(x224[:7], b'\x0e\xd0\x00\x00\x00\x01\x00')

    def test_connection_confirm_carries_rdp_neg_rsp(self):
        """The CC user data must be a valid RDP Negotiation Response (#630)."""
        payload = _generate_connection_confirm()
        _, _, li, _, x224 = _parse_tpkt_x224(payload)
        neg = x224[7 : 1 + li]
        self.assertEqual(len(neg), 8, msg='RDP_NEG_RSP must be exactly 8 octets')
        self.assertEqual(neg[0], 0x02, msg='type must be RDP_NEG_RSP (0x02)')
        self.assertEqual(struct.unpack('<H', neg[2:4])[0], 8, msg='length field must be 8')
        selected = struct.unpack('<I', neg[4:8])[0]
        self.assertEqual(selected, 0x00000000, msg='selectedProtocol must be PROTOCOL_RDP')

    def test_nla_challenge_dt_header_ordering(self):
        payload = _generate_nla_challenge()
        tpkt_len, x224_len, li, code, x224 = _parse_tpkt_x224(payload)
        # TPKT length must cover the whole X.224+TSRequest payload.
        self.assertEqual(tpkt_len, x224_len, msg='TPKT length must cover x224')
        # For a Data TPDU the LI counts the octets after it: the 0xF0 code octet
        # plus the TSRequest user data. So LI == x224_len - 1.
        self.assertEqual(li, x224_len - 1, msg='DT LI must count code + user data')
        # octet 1 is the DT code 0xF0, NOT the inverted 0xF0 in the LI slot.
        self.assertEqual(code, 0xF0, msg='TPDU code must be 0xF0 (Data TPDU)')
        self.assertEqual(x224[0], len(x224) - 1)


class TestRdpX224HandshakeFidelity(unittest.TestCase):
    """Issue #630: a minimal X.224 CR must yield a valid CC + RDP_NEG_RSP."""

    # Minimal client X.224 Connection-Request with an RDP Negotiation Request
    # asking for TLS (PROTOCOL_SSL). TPKT(4) + CR header(7) + cookie-less
    # RDP_NEG_REQ(8). LI = 6 + 8 = 14; TPKT length = 4 + 15 = 19.
    CR_WITH_NEG_REQ = (
        b'\x03\x00\x00\x13'  # TPKT: version 3, len 19
        + b'\x0e\xe0\x00\x00\x00\x00\x00'  # X.224 CR: LI=14, code 0xE0
        + b'\x01\x00\x08\x00\x01\x00\x00\x00'  # RDP_NEG_REQ: TLS requested
    )

    def test_minimal_cr_yields_connection_confirm_with_neg_rsp(self):
        resp = generate_rdp_response(self.CR_WITH_NEG_REQ, '10.0.0.9')
        tpkt_len, x224_len, li, code, x224 = _parse_tpkt_x224(resp)
        self.assertEqual(tpkt_len, x224_len, msg='TPKT length must match payload')
        self.assertEqual(code, 0xD0, msg='must answer CR with Connection-Confirm')
        self.assertEqual(li, x224_len - 1, msg='LI must count all trailing octets')
        # The CC must carry an 8-octet RDP Negotiation Response (type 0x02).
        neg = x224[7:]
        self.assertEqual(len(neg), 8)
        self.assertEqual(neg[0], 0x02, msg='type must be RDP_NEG_RSP')
        self.assertEqual(struct.unpack('<H', neg[2:4])[0], 8)

    def test_cr_without_neg_req_still_gets_cc_with_neg_rsp(self):
        # Bare CR (no negotiation request): LI=6, TPKT len=11.
        raw = b'\x03\x00\x00\x0b' + b'\x06\xe0\x00\x00\x00\x00\x00'
        resp = generate_rdp_response(raw, '10.0.0.9')
        _, _, li, code, x224 = _parse_tpkt_x224(resp)
        self.assertEqual(code, 0xD0)
        self.assertEqual(x224[7], 0x02, msg='CC must still carry RDP_NEG_RSP')


class TestRdpEmptyRawSignal(unittest.TestCase):
    """Issue #630: empty/whitespace-only raw must signal EMPTY_CONNECTION."""

    def test_empty_raw_signals_empty_connection(self):
        self.assertEqual(rdp_probe_signal(b''), EMPTY_CONNECTION)

    def test_whitespace_only_raw_signals_empty_connection(self):
        self.assertEqual(rdp_probe_signal(b'  \r\n\t '), EMPTY_CONNECTION)

    def test_real_frame_is_not_flagged(self):
        self.assertIsNone(rdp_probe_signal(b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'))

    def test_empty_raw_still_gets_a_wire_response(self):
        # The honeypot must still answer a payloadless probe with a valid CC
        # so slow clients that connect-then-pause see a live RDP endpoint.
        resp = generate_rdp_response(b'', '10.0.0.9')
        self.assertEqual(resp[:2], b'\x03\x00')


if __name__ == '__main__':
    unittest.main()
