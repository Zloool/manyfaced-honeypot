"""Elasticsearch handler tests (issue #281)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import ELASTIC_HTTP
from manyfaced.handlers.elastic_handler import ElasticHandler


class TestElasticHandler(unittest.TestCase):
    """Test Elastic responses."""

    def setUp(self):
        self.handler = ElasticHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, ELASTIC_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/_cluster/health',
            'GET /_cluster/health HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertTrue(
            b'elasticsearch' in response or b'cluster' in response,
            f'expected elasticsearch/cluster in response, got: {response[:200]!r}',
        )
        self.assertEqual(detected, ELASTIC_HTTP)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/kibana/login',
            'POST /kibana/login HTTP/1.1\r\nHost: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)

    def test_response_uses_real_crlf(self):
        """Regression for #593: headers must use real CRLF, not literal backslash-r-n."""
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/_cluster/health',
            'GET /_cluster/health HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        # Real CRLF present, literal backslash-escape sequence absent.
        self.assertIn(b'\r\n', response)
        self.assertNotIn(b'\\r\\n', response)
        # Header block terminates with a blank line (CRLFCRLF).
        self.assertIn(b'\r\n\r\n', response)
        # Status line ends with real CRLF.
        self.assertTrue(response.startswith(b'HTTP/1.1 200 OK\r\n'))


if __name__ == '__main__':
    unittest.main()
