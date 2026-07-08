"""Redis Admin handler tests (issue #297)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import REDIS_ADMIN_HTTP
from manyfaced.handlers import RedisAdminHandler


class TestRedisAdminHandler(unittest.TestCase):
    """Test Redis Admin responses."""

    def setUp(self):
        self.handler = RedisAdminHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, REDIS_ADMIN_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/redis-commander',
            'GET /redis-commander HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Redis', response)
        self.assertEqual(detected, REDIS_ADMIN_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
