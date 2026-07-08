"""IoT / generic router web admin handler tests (issue #284)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import IOT_HTTP
from manyfaced.handlers.iot_handler import IoTHandler


class TestIotHandler(unittest.TestCase):
    """Test IoT Router responses."""

    def setUp(self):
        self.handler = IoTHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, IOT_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/admin',
            'GET /admin HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertTrue(b'Router' in response or b'IoT' in response)
        self.assertEqual(detected, IOT_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _detected = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
