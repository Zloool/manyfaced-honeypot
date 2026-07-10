"""Tests for the Fortinet FortiGate/FortiManager honeypot face."""

from __future__ import annotations

import unittest

from manyfaced.handlers.fortinet_handler import FortinetHandler, DETECTED_ID
from manyfaced.handlers.routes import routes_fortinet


BOT_IP = '203.0.113.45'


def _post_logincheck(username: str = 'admin', password: str = 'P@ssw0rd!') -> str:
    """Build a realistic FortiGate /remote/logincheck POST request."""
    body = f'username={username}&password={password}&realm=&ajax=1'
    return (
        'POST /remote/logincheck HTTP/1.1\r\n'
        'Host: vpn.example.com\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: {len(body)}\r\n'
        'Connection: close\r\n'
        '\r\n'
        f'{body}'
    )


class TestFortinetHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = FortinetHandler()

    def test_login_page_returns_bytes(self) -> None:
        resp, flag = self.handler.generate_response(
            '/remote/login', 'GET /remote/login HTTP/1.1\r\nHost: x\r\n\r\n', BOT_IP
        )
        self.assertIsInstance(resp, bytes)
        self.assertIn(DETECTED_ID, (flag,))  # flag == DETECTED_ID
        self.assertEqual(flag, DETECTED_ID)
        # Login page should mention FortiGate / Fortinet.
        self.assertIn(b'FortiGate', resp)
        self.assertIn(b'Fortinet', resp)

    def test_logincheck_captures_credentials(self) -> None:
        raw = _post_logincheck('alice', 's3cr3t')
        resp, flag = self.handler.generate_response('/remote/logincheck', raw, BOT_IP)

        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)
        # FortiGate returns '1' on success.
        self.assertIn(b'1', resp)

        # Credentials must be captured in the bot profile.
        profile = self.handler.get_profile(BOT_IP)
        self.assertIsNotNone(profile)
        captured = profile.captured_credentials
        self.assertTrue(any(c.get('username') == 'alice' for c in captured))
        self.assertTrue(any(c.get('password') == 's3cr3t' for c in captured))

    def test_logout_response(self) -> None:
        resp, flag = self.handler.generate_response(
            '/remote/logout', 'GET /remote/logout HTTP/1.1\r\nHost: x\r\n\r\n', BOT_IP
        )
        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)

    def test_api_v2_json(self) -> None:
        resp, flag = self.handler.generate_response(
            '/api/v2/cmdb/system/status',
            'GET /api/v2/cmdb/system/status HTTP/1.1\r\nHost: x\r\n\r\n',
            BOT_IP,
        )
        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)
        self.assertIn(b'application/json', resp)

    def test_jsonrpc_response(self) -> None:
        raw = (
            'POST /jsonrpc HTTP/1.1\r\n'
            'Host: fmg.example.com\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: 63\r\n'
            'Connection: close\r\n'
            '\r\n'
            '{"method":"get","params":[],"id":1,"session":""}'
        )
        resp, flag = self.handler.generate_response('/jsonrpc', raw, BOT_IP)
        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)
        self.assertIn(b'application/json', resp)

    def test_routes_registered(self) -> None:
        self.assertGreaterEqual(len(routes_fortinet.ROUTES), 1)
        names = {r.name for r in routes_fortinet.ROUTES}
        self.assertIn('fortinet_sslvpn_login', names)
        self.assertIn('fortinet_fmgr_jsonrpc', names)
        for r in routes_fortinet.ROUTES:
            self.assertEqual(r.detected_id, DETECTED_ID)


if __name__ == '__main__':
    unittest.main()
