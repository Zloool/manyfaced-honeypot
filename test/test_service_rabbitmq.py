"""RabbitMQ handler tests (scaffold)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import RABBITMQ_HTTP
from manyfaced.handlers import RabbitMQHandler


class TestRabbitMQHandler(unittest.TestCase):
    """Test RabbitMQ responses."""

    def setUp(self):
        self.handler = RabbitMQHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, RABBITMQ_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/api/overview',
            'GET /api/overview HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'RabbitMQ', response)
        self.assertEqual(detected, RABBITMQ_HTTP)

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
