"""Tests for the Env / config disclosure HTTP handler (issue #272)."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers.env_disc_handler import EnvDiscHandler
from manyfaced.common.status import ENV_DISC_HTTP


class TestEnvDiscHandler(unittest.TestCase):
    """Test EnvDiscHandler responses."""

    def setUp(self):
        self.handler = EnvDiscHandler()

    def _profile(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        return profile

    def test_detected_id(self):
        """Handler reports the correct detected ID constant."""
        self.assertEqual(self.handler.DETECTED_ID, ENV_DISC_HTTP)
        self.assertEqual(self.handler.domain, 'env_disc')
        self.assertEqual(self.handler.VERSION, '1.0')

    def test_main_page(self):
        """GET /.env returns a fake .env disclosure marked honeypot."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/.env',
            'GET /.env HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertTrue(
            b'DB_PASSWORD' in response or b'APP_KEY' in response or b'=' in response
        )
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_config_dot_env_disclosure(self):
        """/.env returns a fake .env dump with HONEYPOT marker."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/.env',
            'GET /.env HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'HONEYPOT', response)
        self.assertIn(b'DB_PASSWORD', response)
        self.assertIn(b'APP_KEY', response)
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_config_env_path(self):
        """/config.env returns a fake .env dump too."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/config.env',
            'GET /config.env HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'APP_KEY', response)
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_env_example_path(self):
        """/.env.example returns a fake .env dump."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/.env.example',
            'GET /.env.example HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'APP_KEY', response)
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_configuration_html_page(self):
        """/configuration returns an HTML config page (not an .env dump)."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/configuration',
            'GET /configuration HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Environment Configuration', response)
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_env_prefix_encoded_probe(self):
        """/env/%2eenv (decoded to /env/.env) returns a fake .env dump."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/env/%2eenv',
            'GET /env/%2eenv HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'DB_PASSWORD', response)
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_api_prefix_probe(self):
        """/api/.env returns a fake .env dump under the /api/ prefix."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/api/.env',
            'GET /api/.env HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'APP_KEY', response)
        self.assertEqual(detected, ENV_DISC_HTTP)

    def test_login_post(self):
        """Credential-bearing POST on an env path returns b'Error'."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/env/login',
            'POST /env/login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret123',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)
        self.assertEqual(detected, ENV_DISC_HTTP)


if __name__ == '__main__':
    unittest.main()
