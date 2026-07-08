"""Laravel handler tests (issue #286)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import LARAVEL_HTTP
from manyfaced.handlers import LaravelHandler


class TestLaravelHandler(unittest.TestCase):
    """Test Laravel responses."""

    def setUp(self):
        self.handler = LaravelHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, LARAVEL_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/_ignition',
            'GET /_ignition HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Laravel', response)
        self.assertEqual(detected, LARAVEL_HTTP)

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

    def test_ignition_execute_solution(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        raw = (
            'POST /_ignition/execute-solution HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/json\r\n\r\n'
            '{"solution":"fake"}'
        )
        response, detected = self.handler.generate_response(
            '/_ignition/execute-solution', raw, '1.2.3.4'
        )
        self.assertIn(b'Laravel', response)
        self.assertEqual(detected, LARAVEL_HTTP)

    def test_env_disclosure_path_encoded(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        raw = 'GET /laravel/%2eenv HTTP/1.1\r\nHost: example.com\r\n\r\n'
        response, detected = self.handler.generate_response(
            '/laravel/%2eenv', raw, '1.2.3.4'
        )
        self.assertIn(b'APP_KEY', response)
        self.assertEqual(detected, LARAVEL_HTTP)

    def test_storage_logs_disclosure(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        raw = 'GET /storage/logs/laravel%2e.log HTTP/1.1\r\nHost: x\r\n\r\n'
        response, detected = self.handler.generate_response(
            '/storage/logs/laravel%2e.log', raw, '1.2.3.4'
        )
        self.assertIn(b'Laravel', response)
        self.assertEqual(detected, LARAVEL_HTTP)


if __name__ == '__main__':
    unittest.main()
