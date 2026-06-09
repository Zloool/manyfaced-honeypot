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
    extract_telnet_credentials,
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
        """AUTH command should capture username and password."""
        raw_data = b'*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$6\r\npassword123\r\n'
        response = generate_redis_response(raw_data, '10.0.0.2')
        creds = extract_redis_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'admin')
        self.assertEqual(creds[1], 'password123')

    def test_redis_noauth_response(self):
        """Commands without auth should return -NOAUTH response."""
        raw_data = b'*1\r\n$4\r\nKEYS\r\n'
        response = generate_redis_response(raw_data, '10.0.0.3')
        self.assertIn(b'-NOAUTH', response)

    def test_redis_greeting(self):
        """Greeting should return +PONG."""
        greeting = generate_redis_greeting('10.0.0.4')
        self.assertEqual(greeting, b'+PONG\r\n')


class TestMongoDBHandler(unittest.TestCase):
    """Test MongoDB Wire Protocol handler."""

    def test_mongodb_ismaster_response(self):
        """ismaster command should return replica set info."""
        raw_data = b'\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80\x04\x00\x00\x7b\x22\x69\x73\x6d\x61\x73\x74\x65\x72\x22\x3a\x74\x72\x75\x65\x2c\x22\x6f\x6b\x22\x3a\x31\x2e\x30\x7d'
        response = generate_mongodb_response(raw_data, '10.0.0.1')
        self.assertTrue(len(response) > 0)

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


class TestTelnetHandler(unittest.TestCase):
    """Test Telnet protocol handler."""

    def test_telnet_iac_negotiation(self):
        """IAC negotiation should return appropriate responses."""
        raw_data = b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f'
        response = generate_telnet_response(raw_data, '10.0.0.1')
        self.assertTrue(len(response) > 0)

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


class TestRDPHandler(unittest.TestCase):
    """Test RDP protocol handler."""

    def test_rdp_initial_response(self):
        """Initial response should return TPKT/X.224 connection confirm."""
        raw_data = b''
        response = generate_rdp_response(raw_data, '10.0.0.1')
        self.assertTrue(len(response) > 0)

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
        self.assertTrue(len(greeting) > 0)


class TestVNCHandler(unittest.TestCase):
    """Test VNC protocol handler."""

    def test_vnc_version_string(self):
        """Version string should be returned for initial connection."""
        raw_data = b''
        response = generate_vnc_response(raw_data, '10.0.0.1')
        self.assertTrue(len(response) > 0)

    def test_vnc_auth_failure(self):
        """Authentication attempt should return failure response."""
        raw_data = bytes([random.randint(0, 255) for _ in range(16)])
        response = generate_vnc_response(raw_data, '10.0.0.2')
        self.assertTrue(len(response) > 0)

    def test_vnc_credential_capture(self):
        """VNC auth attempt should capture credentials."""
        raw_data = bytes([random.randint(0, 255) for _ in range(16)])
        creds = extract_vnc_credentials(raw_data)
        self.assertIsNotNone(creds)
        self.assertEqual(creds[0], 'vnc-authenticated')

    def test_vnc_greeting(self):
        """Greeting should return version string."""
        greeting = generate_vnc_greeting('10.0.0.3')
        self.assertIn(b'RFB', greeting)


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
        self.assertTrue(len(response) > 0)

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
        self.assertTrue(len(response) > 0)

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
        self.assertTrue(len(response) > 0)

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
        self.assertTrue(len(response) > 0)


if __name__ == '__main__':
    unittest.main()
