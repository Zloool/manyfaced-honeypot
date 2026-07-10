"""Joomla handler tests (issue #391 / CVE-2026-48908, CVE-2026-56290)."""

import os
import sys
import unittest

# Ensure the project root is in sys.path for imports.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers.joomla_handler import JoomlaHandler
from manyfaced.handlers.routes.routes_joomla import ROUTES


class TestJoomlaHandler(unittest.TestCase):
    """Test Joomla responses and route table."""

    def setUp(self):
        self.handler = JoomlaHandler()

    def test_admin_login_page(self):
        response, detected = self.handler.generate_response(
            '/administrator/',
            'GET /administrator/ HTTP/1.1\r\nHost: x\r\n\r\n',
            '10.0.0.5',
        )
        self.assertIsInstance(response, bytes)
        self.assertGreater(len(response), 0)
        self.assertIn(b'HTTP/1.1 200', response)
        self.assertIn(b'Joomla', response)
        self.assertEqual(detected, 1040)

    def test_front_page(self):
        response, detected = self.handler.generate_response(
            '/',
            'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
            '10.0.0.6',
        )
        self.assertIn(b'HTTP/1.1 200', response)
        self.assertIn(b'Joomla', response)
        self.assertEqual(detected, 1040)

    def test_upload_post_with_credentials(self):
        raw = (
            'POST /index.php?option=com_sppagebuilder&task=media.upload HTTP/1.1\r\n'
            'Host: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=Pr3ttyL0ngPa$$w0rd'
        )
        response, detected = self.handler.generate_response(
            '/index.php?option=com_sppagebuilder&task=media.upload',
            raw,
            '10.0.0.7',
        )
        self.assertIsInstance(response, bytes)
        self.assertGreater(len(response), 0)
        # Successful credential capture returns 302 (or 200) to encourage probing.
        self.assertTrue(
            response.startswith(b'HTTP/1.1 302') or response.startswith(b'HTTP/1.1 200'),
            msg=f'unexpected status line: {response[:20]!r}',
        )
        self.assertEqual(detected, 1040)
        profile = self.handler.get_profile('10.0.0.7')
        self.assertIsNotNone(profile)
        self.assertTrue(len(profile.captured_credentials) >= 1)

    def test_routes_loaded(self):
        self.assertGreaterEqual(len(ROUTES), 1)


if __name__ == '__main__':
    unittest.main()
