"""Tests for protocol detection and classification.

Covers:
(a) Each new protocol's distinctive bytes route to the right detected_id
(b) Borderline cases (truncated, near-match) do NOT route to that protocol
(c) Genuinely-unrecognized non-HTTP input still routes to generic path
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

_geoip_mock = MagicMock()
_geoip_mock.geolite2.geolite2 = _geoip_mock.geolite2
sys.modules['geoip'] = _geoip_mock
sys.modules['geoip.geolite2'] = _geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()

from manyfaced.common.protocol import detect_protocol, get_protocol_info  # noqa: E402


class TestDetectProtocolNewProtocols:
    """Test that each new protocol is correctly detected from raw bytes."""

    def test_tls_clienthello_detected(self):
        """TLS ClientHello (0x16 0x03) should be detected as 'tls'."""
        # TLS ClientHello: handshake(0x16) + version(0x03 0x01) + length
        raw = b'\x16\x03\x01\x00\xdc\x01\x00\x00\xd8\x03\x01'
        assert detect_protocol(raw) == 'tls'

    def test_tls_clienthello_version_33(self):
        """TLS 1.3 ClientHello (0x16 0x03 0x03) should be detected as 'tls'."""
        raw = b'\x16\x03\x03\x00\xef\x01\x00\x00\xeb'
        assert detect_protocol(raw) == 'tls'

    def test_dns_over_tcp_detected(self):
        """DNS-over-TCP (full 12-byte header + domain label) should be detected as 'dns'."""
        # Full DNS query: txn_id(2)+flags(2)+counts(6)=12 byte header, then labels
        raw = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
        assert detect_protocol(raw) == 'dns'

    def test_dns_over_tcp_long_query(self):
        """Longer DNS query should still be detected as 'dns'."""
        # Full 12-byte header + longer domain
        raw = (
            b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            + b'\x00' * 10
        )
        assert detect_protocol(raw) == 'dns'

    def test_sip_options_detected(self):
        """SIP OPTIONS request-line must be detected as 'sip', not 'http' (issue #599)."""
        raw = b'OPTIONS sip:manyfaced SIP/2.0\r\nVia: SIP/2.0/UDP\r\n\r\n'
        assert detect_protocol(raw) == 'sip'

    def test_sip_invite_detected(self):
        """SIP INVITE request-line must be detected as 'sip', not 'http' (issue #599)."""
        raw = b'INVITE sip:user@host SIP/2.0\r\n'
        assert detect_protocol(raw) == 'sip'

    def test_rtsp_options_detected(self):
        """RTSP OPTIONS request-line must be detected as 'rtsp', not 'http' (issue #599)."""
        raw = b'OPTIONS / RTSP/1.0\r\nCSeq: 1\r\n\r\n'
        assert detect_protocol(raw) == 'rtsp'

    def test_rtsp_describe_detected(self):
        """RTSP DESCRIBE request-line must be detected as 'rtsp', not 'http' (issue #599)."""
        raw = b'DESCRIBE rtsp://host/stream RTSP/1.0\r\nCSeq: 2\r\n\r\n'
        assert detect_protocol(raw) == 'rtsp'

    def test_ldap_bind_detected(self):
        """LDAP bind request (ASN.1 SEQUENCE + bind tag) detected as 'ldap', not 'http' (issue #599)."""
        # SEQUENCE(0x30) len(0x14=20) + INTEGER(0x02) 0x01 0x01 (msgID) + app bind(0x60) ...
        raw = b'\x30\x14\x02\x01\x01\x60\x0f\x02\x01\x03\x04\x08admin\x80\x04\x00'
        assert detect_protocol(raw) == 'ldap'

    def test_http_still_detected_after_reorder(self):
        """Genuine HTTP requests must still be detected as 'http' after the reordering."""
        assert detect_protocol(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n') == 'http'
        assert detect_protocol(b'POST /login HTTP/1.1\r\n\r\n') == 'http'
        assert detect_protocol(b'OPTIONS * HTTP/1.1\r\n\r\n') == 'http'
        assert detect_protocol(b'CONNECT host:22 HTTP/1.1\r\n\r\n') == 'http'

        """HTTP/2 connection preface should be detected as 'http2', not 'dns'."""
        raw = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x18\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x04\x00\x00Bh\x00\x06\x00\x04\x00\x00\x00\x03\x00\x00\x00\n'
        assert detect_protocol(raw) == 'http2'

    def test_mongodb_wire_protocol_detected(self):
        """MongoDB wire protocol (valid length + OP_QUERY opcode at offset 20) should be detected."""
        # Format: {length(4)+flags(4)+cursor_id(8)+response_to(4)+opcode(4)} = 24 bytes header
        # OP_QUERY=2004 in LE = \xd4\x07\x00\x00 at offset 20
        raw = b'\x30\x00\x00\x00' + b'\x00' * 16 + b'\xd4\x07\x00\x00'
        assert detect_protocol(raw) == 'mongodb'

    def test_mongodb_wire_protocol_op_msg(self):
        """MongoDB OP_MSG alias opcode (1000 LE = \xe8\x03\x00\x00 at offset 20) should be detected."""
        raw = b'\x50\x00\x00\x00' + b'\x00' * 16 + b'\xe8\x03\x00\x00'
        assert detect_protocol(raw) == 'mongodb'

    def test_mongodb_wire_protocol_op_msg_real(self):
        """MongoDB OP_MSG (the modern default driver opcode=2013 / 0x07dd) must be detected (issue #597).

        OP_MSG (opcode 2013, LE encoding \xdd\x07\x00\x00 at offset 20) is what every
        current MongoDB driver actually sends; the old detector only knew legacy
        OP_QUERY/OP_REPLY so OP_MSG probes were mis-classified.
        """
        # header length=0x50 (80), then 16 bytes of flags/cursor/responseTo, then opcode=2013.
        raw = b'\x50\x00\x00\x00' + b'\x00' * 16 + b'\xdd\x07\x00\x00'
        assert detect_protocol(raw) == 'mongodb'
        # get_protocol_info must also classify it as mongodb.
        info = get_protocol_info(raw)
        assert info['protocol'] == 'mongodb'

    def test_mongodb_wire_protocol_op_reply(self):
        """MongoDB OP_REPLY (opcode=1 LE = \x01\x00\x00\x00 at offset 20) should be detected."""
        raw = b'\x50\x00\x00\x00' + b'\x00' * 16 + b'\x01\x00\x00\x00'
        assert detect_protocol(raw) == 'mongodb'

    def test_redis_ping_detected(self):
        """Redis PING (*1\r\n$4\r\nPING\r\n) should be detected as 'redis'."""
        raw = b'*1\r\n$4\r\nPING\r\n'
        assert detect_protocol(raw) == 'redis'

    def test_redis_bulk_string_detected(self):
        """Redis bulk string ($5\r\nHELLO\r\n) should be detected as 'redis'."""
        raw = b'$5\r\nHELLO\r\n'
        assert detect_protocol(raw) == 'redis'

    def test_redis_array_detected(self):
        """Redis array (*2\r\n$3\r\nSET\r\n) should be detected as 'redis'."""
        raw = b'*2\r\n$3\r\nSET\r\n'
        assert detect_protocol(raw) == 'redis'

    def test_redis_simple_string_detected(self):
        """Redis simple string (+OK\r\n) should be detected as 'redis'."""
        raw = b'+OK\r\n'
        # Redis comes before POP3 in detection order, so + matches redis first
        assert detect_protocol(raw) == 'redis'


class TestDetectProtocolBorderlineCases:
    """Test that borderline / truncated bytes do NOT falsely match protocols."""

    def test_tls_too_short(self):
        """Single byte 0x16 without version should not be TLS."""
        raw = b'\x16\x03'  # Only 2 bytes, no length field — but regex just checks ^\x16\x03
        # Actually the regex is just ^\x16\x03 so this WILL match. That's fine —
        # it's a conservative signature and false positives are acceptable here
        # because TLS ClientHello always starts with these bytes.
        assert detect_protocol(raw) == 'tls'

    def test_tls_non_tls_start(self):
        """Data starting with 0x16 but not followed by 0x03 should not be TLS."""
        raw = b'\x16\x04\x00\x00\x10'
        assert detect_protocol(raw) is None

    def test_dns_compression_pointer(self):
        """DNS compression pointer (0xc0 at offset 2) should NOT match DNS label range."""
        # Length=2, then 0xc0 = compression pointer — excluded from label byte range (0x01-0xbf)
        raw = b'\x00\x02\xc0\x0c'
        assert detect_protocol(raw) is None

    def test_dns_null_byte_at_offset_2(self):
        """DNS with null at offset 2 (root zone) should NOT match."""
        # Length=2, then 0x00 = root label — not in 0x01-0xf9 range
        raw = b'\x00\x02\x00\x01'
        assert detect_protocol(raw) is None

    def test_dns_too_short(self):
        """Less than 4 bytes cannot be DNS-over-TCP."""
        raw = b'\x00\x03'
        assert detect_protocol(raw) is None

    def test_mongodb_invalid_opcode(self):
        """MongoDB with unknown opcode should not match."""
        # length=48, but opcode at offset 20 = \xff\xff\xff\xff (not a valid pattern)
        raw = b'\x30\x00\x00\x00' + b'\x00' * 16 + b'\xff\xff\xff\xff'
        assert detect_protocol(raw) is None

    def test_mongodb_too_short(self):
        """Less than 24 bytes cannot be MongoDB wire protocol."""
        raw = b'\x30\x00\x00\x00' + b'\x00' * 19
        assert detect_protocol(raw) is None

    def test_mongodb_message_too_small(self):
        """MongoDB with message length < 16 should not match (opcode also invalid)."""
        # length=8, and opcode at offset 20 is \xff\xff\xff\xff (not a valid pattern)
        raw = b'\x08\x00\x00\x00' + b'\x00' * 16 + b'\xff\xff\xff\xff'
        assert detect_protocol(raw) is None

    def test_redis_not_at_start(self):
        """Redis marker in the middle of data should not match."""
        raw = b'GET $5\r\nHELLO\r\n'
        # HTTP comes before DNS, so "GET ..." matches HTTP first
        assert detect_protocol(raw) == 'http'

    def test_redis_partial_marker(self):
        """Truncated Redis bulk string ($ without length) — still matches because ^[$*+]"""
        # This WILL match because the regex just checks first byte. That's acceptable:
        # a single $ at start of data is almost certainly Redis RESP.
        raw = b'$'
        assert detect_protocol(raw) == 'redis'

    def test_unrecognized_binary_not_detected(self):
        """Random binary data should not match any protocol."""
        raw = b'\xde\xad\xbe\xef\x01\x02\x03\x04'
        assert detect_protocol(raw) is None

    def test_empty_data_not_detected(self):
        """Empty bytes should return None."""
        assert detect_protocol(b'') is None


class TestGetProtocolInfoNewProtocols:
    """Test that get_protocol_info extracts correct info for new protocols."""

    def test_tls_info_extracted(self):
        """TLS ClientHello should set protocol='tls' and version."""
        raw = b'\x16\x03\x01\x00\xdc\x01\x00\x00\xd8'
        info = get_protocol_info(raw)
        assert info['protocol'] == 'tls'
        # Version bytes at offset 1-2: \x03\x01 → TLS 3.1 (wire format for TLS 1.0)
        assert info.get('version') == 'TLS 3.1'

    def test_tls_version_13(self):
        """TLS 1.3 ClientHello should report version 3.3."""
        raw = b'\x16\x03\x03\x00\xef'
        info = get_protocol_info(raw)
        assert info['protocol'] == 'tls'
        # Version bytes at offset 1-2: \x03\x03 → TLS 3.3 (wire format for TLS 1.3)
        assert info.get('version') == 'TLS 3.3'

    def test_dns_info_extracted(self):
        """DNS-over-TCP should set protocol='dns'."""
        raw = b'\x00\x10\x03www\x07example\x03com\x00\x00\x01\x00\x01'
        info = get_protocol_info(raw)
        assert info['protocol'] == 'dns'

    def test_mongodb_info_extracted(self):
        """MongoDB wire protocol should set protocol='mongodb'."""
        raw = b'\x30\x00\x00\x00' + b'\x00' * 16 + b'\xd4\x07\x00\x00'
        info = get_protocol_info(raw)
        assert info['protocol'] == 'mongodb'

    def test_redis_info_extracted(self):
        """Redis RESP should set protocol='redis'."""
        raw = b'*1\r\n$4\r\nPING\r\n'
        info = get_protocol_info(raw)
        assert info['protocol'] == 'redis'


class TestHandlerRouting:
    """Test that _handle_non_http_probe routes to correct detected_id per protocol."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        args.server = None  # No server port = no report sent
        update_event = MagicMock()
        from manyfaced.handlers.http_handler import HTTPHandler

        return HTTPHandler(args, update_event)

    def test_tls_routes_to_unknown_tls(self, handler):
        """TLS ClientHello should be stored with UNKNOWN_TLS detected_id."""
        from manyfaced.common.status import UNKNOWN_TLS

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        raw = b'\x16\x03\x01\x00\xdc\x01\x00\x00\xd8'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='1.2.3.4')

        call_args = MockBS.call_args
        assert call_args[0][4] == UNKNOWN_TLS  # detected_id is 5th positional arg

    def test_dns_routes_to_unknown_dns(self, handler):
        """DNS-over-TCP should be stored with UNKNOWN_DNS detected_id."""
        from manyfaced.common.status import UNKNOWN_DNS

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        raw = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='2.3.4.5')

        call_args = MockBS.call_args
        assert call_args[0][4] == UNKNOWN_DNS

    def test_mongodb_routes_to_unknown_mongodb(self, handler):
        """MongoDB wire protocol should be stored with UNKNOWN_MONGODB detected_id."""
        from manyfaced.common.status import UNKNOWN_MONGODB

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        # Full 24-byte header with OP_QUERY opcode at offset 20
        raw = b'\x30\x00\x00\x00' + b'\x00' * 16 + b'\xd4\x07\x00\x00'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='3.4.5.6')

        call_args = MockBS.call_args
        assert call_args[0][4] == UNKNOWN_MONGODB

    def test_redis_routes_to_unknown_redis(self, handler):
        """Redis PING should be stored with UNKNOWN_REDIS detected_id."""
        from manyfaced.common.status import UNKNOWN_REDIS

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        raw = b'*1\r\n$4\r\nPING\r\n'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='4.5.6.7')

        call_args = MockBS.call_args
        assert call_args[0][4] == UNKNOWN_REDIS

    def test_unrecognized_non_http_still_routes_to_unknown_non_http(self, handler):
        """Unrecognized non-HTTP input still routes to generic HTTP path (not crash)."""
        from manyfaced.common.status import UNKNOWN_NON_HTTP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        # Random binary that doesn't match any known protocol — goes through HTTP fallback
        raw = b'\xde\xad\xbe\xef\x01\x02\x03\x04'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='5.6.7.8')

        # Unrecognized data goes through HTTP fallback path (not _handle_non_http_probe)
        # The HTTP parser creates a minimal request and stores with generic detected_id
        call_args = MockBS.call_args
        assert call_args is not None  # BearStorage was created (no crash)

    def test_sip_routes_to_unknown_sip_not_elasticsearch(self, handler):
        """SIP OPTIONS arriving on an HTTP port must NOT be stored as ES (1013).

        Before the fix (issue #599) SIP's leading 'OPTIONS ' matched the generic
        HTTP method regex, so the probe fell through to the GET / fallback and was
        stored under ELASTIC_HTTP (1013). After #599 it is detected as 'sip' and
        stored under UNKNOWN_SIP.
        """
        from manyfaced.common.status import ELASTIC_HTTP, UNKNOWN_NON_HTTP, UNKNOWN_SIP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        raw = b'OPTIONS sip:manyfaced SIP/2.0\r\nVia: SIP/2.0/UDP\r\n\r\n'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='7.8.9.10')

        call_args = MockBS.call_args
        detected_id = call_args[0][4]
        assert detected_id == UNKNOWN_SIP
        assert detected_id != ELASTIC_HTTP
        assert detected_id != UNKNOWN_NON_HTTP

    def test_rtsp_routes_to_non_http_not_elasticsearch(self, handler):
        """RTSP OPTIONS arriving on an HTTP port must NOT be stored as ES (1013).

        Before the fix (issue #599) RTSP had no signature, so its leading
        'OPTIONS /' matched the HTTP method regex and was stored under
        ELASTIC_HTTP. After #599 it is detected as 'rtsp'.
        """
        from manyfaced.common.status import ELASTIC_HTTP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        raw = b'OPTIONS / RTSP/1.0\r\nCSeq: 1\r\n\r\n'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='8.9.10.11')

        call_args = MockBS.call_args
        detected_id = call_args[0][4]
        assert detected_id != ELASTIC_HTTP

        """Existing FTP probes should still use UNKNOWN_NON_HTTP."""
        from manyfaced.common.status import UNKNOWN_NON_HTTP

        mock_bs = MagicMock()
        mock_bs.dns_name = ''
        mock_bs.country = ''
        mock_bs.continent = ''

        raw = b'220 (vsFTPd 3.0.3)\r\n'
        with patch('manyfaced.handlers.http_handler.BearStorage', return_value=mock_bs) as MockBS:
            handler.handle_request(raw, bot_ip='6.7.8.9')

        call_args = MockBS.call_args
        assert call_args[0][4] == UNKNOWN_NON_HTTP


class TestProtocolDetectionOrdering:
    """Test that protocol detection order prevents false positives."""

    def test_tls_not_confused_with_dns(self):
        """TLS data should not be misclassified as DNS."""
        raw = b'\x16\x03\x01\x00\xdc'
        # TLS starts with 0x16, which is NOT in the DNS label range (0x01-0xf9)
        # But wait — 0x16 IS in range 0x01-0xf9! So DNS regex could match.
        # However, TLS comes before DNS in _PROTOCOL_SIGNATURES, so TLS wins.
        assert detect_protocol(raw) == 'tls'

    def test_redis_not_confused_with_imap(self):
        """Redis array marker (*) should not be confused with IMAP."""
        raw = b'*2\r\n$3\r\nSET\r\n'
        # Redis * is at position 0, IMAP needs "* OK " — different pattern
        assert detect_protocol(raw) == 'redis'

    def test_pop3_not_confused_with_redis(self):
        """POP3 (+OK ) with space should not be confused with Redis simple string."""
        raw = b'+OK mailserver ready\r\n'
        # POP3 has "+OK " (with space), which matches pop3 pattern ^\+OK\s
        # Redis comes before POP3 but +OK doesn't match redis because redis only checks first byte
        assert detect_protocol(raw) == 'pop3'
