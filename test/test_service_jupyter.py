"""Jupyter handler tests (issue #288)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import JUPYTER_HTTP
from manyfaced.handlers import JupyterHandler


class TestJupyterHandler(unittest.TestCase):
    """Test Jupyter responses."""

    def setUp(self):
        self.handler = JupyterHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, JUPYTER_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/jupyter',
            'GET /jupyter HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Jupyter', response)
        self.assertEqual(detected, JUPYTER_HTTP)

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
