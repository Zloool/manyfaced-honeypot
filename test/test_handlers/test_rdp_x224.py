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
)


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
        # TPKT length covers the X.224 header AND the trailing MCS user data.
        self.assertEqual(tpkt_len, x224_len, msg='TPKT length must cover x224 + MCS')

    def test_connection_confirm_x224_header_ordering(self):
        payload = _generate_connection_confirm()
        tpkt_len, x224_len, li, code, x224 = _parse_tpkt_x224(payload)
        # LI counts only the CC TPDU header octets after it (6), not the MCS data.
        self.assertEqual(li, 0x06, msg='LI must be 0x06 for the CC TPDU header')
        self.assertEqual(code, 0xD0, msg='TPDU code must be 0xD0 (Connection-Confirm)')
        # LI being 6 means exactly 6 octets follow it (x224_len == 7) BEFORE user data.
        self.assertEqual(len(x224[: 1 + li]), 7)
        # The header itself is correctly ordered: LI, CC code, dst, src, options.
        self.assertEqual(x224[:7], b'\x06\xd0\x00\x00\x00\x01\x00')

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


if __name__ == '__main__':
    unittest.main()
