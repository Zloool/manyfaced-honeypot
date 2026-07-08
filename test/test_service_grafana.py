"""Grafana handler tests (issue #289)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import GRAFANA_HTTP
from manyfaced.handlers import GrafanaHandler


class TestGrafanaHandler(unittest.TestCase):
    """Test Grafana responses."""

    def setUp(self):
        self.handler = GrafanaHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, GRAFANA_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/grafana',
            'GET /grafana HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Grafana', response)
        self.assertEqual(detected, GRAFANA_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
