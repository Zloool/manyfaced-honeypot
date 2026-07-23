"""Elasticsearch handler tests (issue #281)."""

import json
import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import ELASTIC_HTTP
from manyfaced.handlers.elastic_handler import ElasticHandler

CRLF = chr(13) + chr(10)


class TestElasticHandler(unittest.TestCase):
    """Test Elastic responses."""

    def setUp(self):
        self.handler = ElasticHandler()

    def _request(self, path):
        return 'GET ' + path + ' HTTP/1.1' + CRLF + 'Host: x' + CRLF + CRLF

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, ELASTIC_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/_cluster/health',
            self._request('/_cluster/health'),
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
        raw = (
            'POST /kibana/login HTTP/1.1'
            + CRLF
            + 'Host: example.com'
            + CRLF
            + 'Content-Type: application/x-www-form-urlencoded'
            + CRLF
            + CRLF
            + 'username=admin&password=secret'
        )
        response, _ = self.handler.generate_response('/kibana/login', raw, '1.2.3.4')
        self.assertIn(b'Error', response)

    def test_response_uses_real_crlf(self):
        """Regression for #593: headers must use real CRLF."""
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/_cluster/health',
            self._request('/_cluster/health'),
            '1.2.3.4',
        )
        self.assertIn(b'\r\n', response)
        self.assertNotIn(b'\\r\\n', response)
        self.assertIn(b'\r\n\r\n', response)
        self.assertTrue(response.startswith(b'HTTP/1.1 200 OK\r\n'))

    def test_issue_644_elasticsearch_paths_classified(self):
        """Issue #644: bare ES REST endpoints must be ELASTIC_HTTP + valid JSON."""
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        paths = [
            '/_all/_mapping',
            '/_aliases',
            '/_stats',
            '/_status',
        ]
        sep = chr(13) + chr(10) + chr(13) + chr(10)
        for path in paths:
            response, detected = self.handler.generate_response(
                path,
                self._request(path),
                '1.2.3.4',
            )
            self.assertEqual(
                detected,
                ELASTIC_HTTP,
                f'{path} should be classified ELASTIC_HTTP, got {detected}',
            )
            body = response.split(sep.encode('latin-1'), 1)[1]
            self.assertTrue(
                body.strip().startswith(b'{') or body.strip().startswith(b'['),
                f'{path} body is not JSON: {body[:120]!r}',
            )
            json.loads(body.decode('iso-8859-1'))


if __name__ == '__main__':
    unittest.main()
