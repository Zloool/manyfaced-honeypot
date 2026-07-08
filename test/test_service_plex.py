"""Plex handler tests (issue #284)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import PLEX_HTTP
from manyfaced.handlers import PlexHandler


class TestPlexHandler(unittest.TestCase):
    """Test Plex Media Server honeypot responses."""

    def setUp(self):
        self.handler = PlexHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, PLEX_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/web',
            'GET /web HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Plex', response)
        self.assertEqual(detected, PLEX_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/myplex/account',
            'POST /myplex/account HTTP/1.1\r\nHost: x\r\n\r\nuser=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
