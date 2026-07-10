"""Splunk handler tests (issue #397 / CVE-2026-20253)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.handlers.splunk_handler import SplunkHandler, DETECTED_ID
from manyfaced.handlers.routes import routes_splunk


class TestSplunkHandler(unittest.TestCase):
    """Test Splunk Enterprise responses."""

    def setUp(self):
        self.handler = SplunkHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, DETECTED_ID)

    def test_login_page_returns_bytes(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/en-US/account/login',
            'GET /en-US/account/login HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIsInstance(response, bytes)
        self.assertIn(b'Splunk', response)
        self.assertEqual(detected, DETECTED_ID)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/services/auth/login',
            'POST /services/auth/login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret123',
            '1.2.3.4',
        )
        # Credentials should have been captured on the bot profile.
        profile.capture_credentials.assert_called_once()
        args, _kwargs = profile.capture_credentials.call_args
        creds = args[0]
        self.assertEqual(creds.get('username'), 'admin')
        self.assertIn(b'sessionKey', response)
        self.assertEqual(detected, DETECTED_ID)

    def test_search_jobs_returns_sid(self):
        response, detected = self.handler.generate_response(
            '/services/search/jobs',
            'POST /services/search/jobs HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'search=index%3Dmain',
            '1.2.3.4',
        )
        self.assertIn(b'sid', response)
        self.assertEqual(detected, DETECTED_ID)

    def test_cve_2026_20253_probe_captured(self):
        response, detected = self.handler.generate_response(
            '/servicesNS/admin/search/../../../etc/passwd',
            'GET /servicesNS/admin/search/../../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'captured_probe', response)
        self.assertEqual(detected, DETECTED_ID)

    def test_routes_loaded(self):
        self.assertGreaterEqual(len(routes_splunk.ROUTES), 1)


if __name__ == '__main__':
    unittest.main()
