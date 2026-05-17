"""Tests for GenericHandler (monster page) and HTTPRequest parsing."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common.httphandler import HTTPRequest
from manyfaced.handlers import GenericHandler


class TestGenericHandler(unittest.TestCase):
    """Test GenericHandler (monster page) responses."""

    def setUp(self):
        self.handler = GenericHandler()

    def test_monster_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/random-path',
            'GET /random-path HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Server Administration Panel', response)
        self.assertIn(b'WordPress', response)
        self.assertIn(b'phpMyAdmin', response)
        self.assertIn(b'Jenkins', response)

    def test_traversal_error(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/../../etc/passwd',
            'GET /../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'403', response)
        self.assertIn(b'Forbidden', response)


class TestHTTPRequest(unittest.TestCase):
    """Test HTTPRequest parsing."""

    def test_parse_get(self):
        req = HTTPRequest('GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n')
        self.assertEqual(req.command, 'GET')
        self.assertEqual(req.path, '/wp-login.php')
        self.assertEqual(req.request_version, 'HTTP/1.1')

    def test_parse_post(self):
        req = HTTPRequest(
            'POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\nlog=admin&pwd=test'
        )
        self.assertEqual(req.command, 'POST')
        self.assertEqual(req.path, '/wp-login.php')

    def test_parse_with_query_string(self):
        req = HTTPRequest('GET /search?q=test&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n')
        self.assertEqual(req.path, '/search?q=test&lang=en')


if __name__ == '__main__':
    unittest.main()
