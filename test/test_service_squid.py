"""Squid cache-manager handler tests (issue #289)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import SQUID_HTTP
from manyfaced.handlers import SquidHandler


class TestSquidHandler(unittest.TestCase):
    """Test Squid cachemgr responses."""

    def setUp(self):
        self.handler = SquidHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, SQUID_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/squid-internal-mgr/',
            'GET /squid-internal-mgr/ HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Squid', response)
        self.assertEqual(detected, SQUID_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/cachemgr.cgi',
            'POST /cachemgr.cgi HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)
        self.assertEqual(detected, SQUID_HTTP)


if __name__ == '__main__':
    unittest.main()
