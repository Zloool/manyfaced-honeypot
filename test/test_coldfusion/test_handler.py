"""Tests for the Adobe ColdFusion honeypot face (CVE-2026-48282)."""

from __future__ import annotations

import unittest

from manyfaced.handlers.coldfusion_handler import ColdFusionHandler
from manyfaced.handlers.routes.routes_coldfusion import ROUTES


class TestColdFusionHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = ColdFusionHandler()
        self.bot_ip = '203.0.113.45'

    def test_admin_login_page_returns_bytes(self) -> None:
        raw = (
            'GET /cfide/administrator/ HTTP/1.1\r\n'
            'Host: victim.example.com\r\n'
            'User-Agent: Mozilla/5.0\r\n'
            '\r\n'
        )
        resp, detected = self.handler.generate_response('/cfide/administrator/', raw, self.bot_ip)
        self.assertIsInstance(resp, bytes)
        self.assertGreater(len(resp), 0)
        self.assertIn(b'ColdFusion', resp)
        self.assertEqual(detected, 1042)

    def test_post_credentials_captured(self) -> None:
        raw = (
            'POST /CFIDE/administrator/enter.cfm HTTP/1.1\r\n'
            'Host: victim.example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            'Content-Length: 47\r\n'
            '\r\n'
            'adminUserId=admin&cfadminPassword=S3cret123!'
        )
        resp, detected = self.handler.generate_response(
            '/CFIDE/administrator/enter.cfm', raw, self.bot_ip
        )
        self.assertIsInstance(resp, bytes)
        self.assertEqual(detected, 1042)

        profile = self.handler.get_profile(self.bot_ip)
        self.assertIsNotNone(profile)
        self.assertTrue(len(profile.captured_credentials) > 0)
        creds = profile.captured_credentials[0]
        self.assertEqual(creds.get('username'), 'admin')
        self.assertEqual(creds.get('password'), 'S3cret123!')

    def test_routes_registered(self) -> None:
        self.assertGreaterEqual(len(ROUTES), 1)
        from manyfaced.handlers.router import Route

        for route in ROUTES:
            self.assertIsInstance(route, Route)
            self.assertEqual(route.detected_id, 1042)


if __name__ == '__main__':
    unittest.main()
