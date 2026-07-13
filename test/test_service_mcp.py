"""MCP handler tests (scaffold)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import MCP_HTTP
from manyfaced.handlers import MCPHandler


class TestMCPHandler(unittest.TestCase):
    """Test MCP responses."""

    def setUp(self):
        self.handler = MCPHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, MCP_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/mcp',
            'GET /mcp HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'MCP', response)
        self.assertEqual(detected, MCP_HTTP)

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
        # /login is not an MCP endpoint; the handler returns a JSON-RPC
        # 'Method not found' error (no login/credential flow in MCP).
        self.assertIn(b'"error"', response)
        self.assertIn(b'Method not found', response)
