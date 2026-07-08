"""HNAP handler tests (issue #288)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import HNAP_HTTP
from manyfaced.handlers import HNAPHandler


class TestHnapHandler(unittest.TestCase):
    """Test HNAP responses."""

    def setUp(self):
        self.handler = HNAPHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, HNAP_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/HNAP1',
            'GET /HNAP1 HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'HNAP', response)
        self.assertEqual(detected, HNAP_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)
        self.assertEqual(detected, HNAP_HTTP)


if __name__ == '__main__':
    unittest.main()
