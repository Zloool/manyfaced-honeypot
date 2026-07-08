"""ThinkPHP handler tests (issue #287)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import THINKPHP_HTTP
from manyfaced.handlers import ThinkPHPHandler


class TestThinkPHPHandler(unittest.TestCase):
    """Test ThinkPHP responses."""

    def setUp(self):
        self.handler = ThinkPHPHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, THINKPHP_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/index.php',
            'GET /index.php HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'ThinkPHP', response)
        self.assertEqual(detected, THINKPHP_HTTP)

    def test_rce_probe_returns_exception_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        probe = (
            'GET /index.php?s=/index/think\\app/invokefunction'
            '&function=call_user_func_array&vars[0]=md5&vars[1][]=hello '
            'HTTP/1.1\r\nHost: x\r\n\r\n'
        )
        response, detected = self.handler.generate_response(
            '/index.php', probe, '1.2.3.4'
        )
        self.assertIn(b'ThinkPHP', response)
        self.assertIn(b'invokefunction', response)
        self.assertEqual(detected, THINKPHP_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
