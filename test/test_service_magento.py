"""Magento handler tests (issue #293)."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common.status import MAGENTO_HTTP
from manyfaced.handlers import MagentoHandler


class TestMagentoHandler(unittest.TestCase):
    """Test Magento responses."""

    def setUp(self):
        self.handler = MagentoHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, MAGENTO_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/admin',
            'GET /admin HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Magento', response)
        self.assertEqual(detected, MAGENTO_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/admin',
            'POST /admin HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nlogin[username]=admin&login[password]=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
