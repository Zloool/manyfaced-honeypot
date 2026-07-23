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


class TestElasticManagementPaths(unittest.TestCase):
    """ES management/recon paths must return ES JSON + ELASTIC_HTTP (#644)."""

    MANAGEMENT_PATHS = [
        '/_all/_mapping',
        '/_aliases',
        '/_stats',
        '/_status',
        '/_cluster/state',
        '/_nodes/stats',
        '/_bulk',
        '/_search',
        '/_cat/indices',
        '/_cat/health',
        '/_cat/nodes',
    ]

    def test_router_classifies_elastic_and_returns_es_json(self):
        import json

        from manyfaced.handlers.routes import router

        for path in self.MANAGEMENT_PATHS:
            with self.subTest(path=path):
                result = router.dispatch(
                    path,
                    f'GET {path} HTTP/1.1\r\nHost: x\r\n\r\n',
                    '1.2.3.4',
                    {},
                )
                self.assertIsNotNone(result, f'{path} fell through the router')
                assert result is not None
                response, detected = result[0], result[1]
                self.assertEqual(
                    detected,
                    ELASTIC_HTTP,
                    f'{path} classified {detected}, expected ELASTIC_HTTP',
                )
                if isinstance(response, str):
                    response = response.encode()
                self.assertTrue(response.startswith(b'HTTP/1.1 200'))
                body = response.split(b'\r\n\r\n', 1)[1]
                json.loads(body)  # must be valid ES-shaped JSON

    def test_handler_returns_elastic_id_for_management_paths(self):
        handler = ElasticHandler()
        handler.bot_profiles = {'1.2.3.4': MagicMock()}
        for path in self.MANAGEMENT_PATHS:
            with self.subTest(path=path):
                response, detected = handler.generate_response(
                    path,
                    f'GET {path} HTTP/1.1\r\nHost: x\r\n\r\n',
                    '1.2.3.4',
                )
                self.assertEqual(detected, ELASTIC_HTTP)
                self.assertTrue(response.startswith(b'HTTP/1.1 200 OK\r\n'))


if __name__ == '__main__':
    unittest.main()
