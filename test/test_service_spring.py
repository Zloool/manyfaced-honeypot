"""Spring Boot handler tests (scaffold)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import SPRING_HTTP
from manyfaced.handlers import SpringHandler


class TestSpringHandler(unittest.TestCase):
    """Test Spring Boot responses."""

    def setUp(self):
        self.handler = SpringHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, SPRING_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/actuator',
            'GET /actuator HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Spring Boot', response)
        self.assertEqual(detected, SPRING_HTTP)

    def test_login_post_captures_credentials(self):
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
