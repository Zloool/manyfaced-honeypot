"""Tests for the Nginx handler (issue #294)."""

import unittest
from unittest.mock import MagicMock

# Issue #294 constant. status.py exposes the canonical Nginx face id as
# NGINX_PROBE_HTTP (=1029); alias it here to keep the test self-contained
# without editing the shared status.py.
from manyfaced.common.status import NGINX_PROBE_HTTP as NGINX_HTTP
from manyfaced.handlers.nginx_handler import NginxHandler


class TestNginxHandler(unittest.TestCase):
    """Test Nginx responses (issue #294)."""

    def setUp(self):
        self.handler = NginxHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, NGINX_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/',
            'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'nginx', response.lower())
        self.assertEqual(detected, NGINX_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)

    def test_welcome_page_index(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/index.html',
            'GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'welcome to nginx', response.lower())
        self.assertEqual(detected, NGINX_HTTP)

    def test_status_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/nginx_status',
            'GET /nginx_status HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Active connections', response)


if __name__ == '__main__':
    unittest.main()
