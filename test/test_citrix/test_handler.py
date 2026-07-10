"""Tests for the Citrix NetScaler Gateway honeypot face."""

import os
import sys
import unittest

_CRLF = chr(13) + chr(10)  # CRLF without backslash escapes (ASCII-safe)

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers.citrix_handler import CitrixHandler  # noqa: E402
from manyfaced.handlers.routes import routes_citrix  # noqa: E402


class TestCitrixHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = CitrixHandler()
        self.bot_ip = '203.0.113.45'

    def test_generate_response_vpn_index_returns_bytes(self) -> None:
        """GET /vpn/index.html should return realistic NetScaler login HTML as bytes."""
        resp, detected = self.handler.generate_response(
            '/vpn/index.html',
            'GET /vpn/index.html HTTP/1.1' + _CRLF + 'Host: vpn.example.com' + _CRLF + _CRLF,
            self.bot_ip,
        )
        self.assertIsInstance(resp, bytes)
        self.assertGreater(len(resp), 0)
        self.assertIn('NetScaler'.encode('utf-8'), resp)
        self.assertIn('Citrix'.encode('utf-8'), resp)
        self.assertEqual(detected, 1044)

    def test_post_cgi_login_captures_credentials(self) -> None:
        """POST /cgi/login with creds should be captured in the bot profile."""
        raw = (
            'POST /cgi/login HTTP/1.1'
            + _CRLF
            + 'Host: vpn.example.com'
            + _CRLF
            + 'Content-Type: application/x-www-form-urlencoded'
            + _CRLF
            + 'Content-Length: 35'
            + _CRLF
            + _CRLF
            + 'login=administrator&password=Passw0rd!'
        )
        resp, detected = self.handler.generate_response('/cgi/login', raw, self.bot_ip, headers={})
        self.assertIsInstance(resp, bytes)
        self.assertEqual(detected, 1044)

        profile = self.handler.get_profile(self.bot_ip)
        self.assertIsNotNone(profile)
        self.assertTrue(len(profile.captured_credentials) >= 1)
        captured = profile.captured_credentials[0]
        self.assertEqual(captured.get('username'), 'administrator')
        self.assertEqual(captured.get('password'), 'Passw0rd!')

    def test_routes_registered(self) -> None:
        """The citrix route table must define at least one route."""
        self.assertGreaterEqual(len(routes_citrix.ROUTES), 1)

    def test_cve_2026_3055_probe_returns_200(self) -> None:
        """CVE-2026-3055 out-of-bounds-read probe paths return HTTP 200."""
        resp, detected = self.handler.generate_response(
            '/pcidss/',
            'GET /pcidss/ HTTP/1.1' + _CRLF + 'Host: vpn.example.com' + _CRLF + _CRLF,
            self.bot_ip,
        )
        self.assertIsInstance(resp, bytes)
        self.assertTrue(resp.startswith(b'HTTP/1.1 200'))
        self.assertEqual(detected, 1044)


if __name__ == '__main__':
    unittest.main()
