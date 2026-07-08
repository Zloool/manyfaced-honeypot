"""Next.js handler tests."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import NEXTJS_HTTP
from manyfaced.handlers import NextjsHandler


class TestNextjsHandler(unittest.TestCase):
    """Test Next.js honeypot responses."""

    def setUp(self):
        self.handler = NextjsHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, NEXTJS_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/',
            'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Next.js', response)
        self.assertEqual(detected, NEXTJS_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)
        self.assertEqual(detected, NEXTJS_HTTP)


if __name__ == '__main__':
    unittest.main()
