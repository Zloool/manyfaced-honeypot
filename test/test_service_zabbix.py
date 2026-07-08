"""Zabbix handler tests (issue #282)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import ZABBIX_HTTP
from manyfaced.handlers import ZabbixHandler


class TestZabbixHandler(unittest.TestCase):
    """Test Zabbix responses."""

    def setUp(self):
        self.handler = ZabbixHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, ZABBIX_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/zabbix.php',
            'GET /zabbix.php HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Zabbix', response)
        self.assertEqual(detected, ZABBIX_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/zabbix.php',
            'POST /zabbix.php HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'name=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
