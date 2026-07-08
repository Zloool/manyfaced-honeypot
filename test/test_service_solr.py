"""Apache Solr handler tests (issue #279)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import SOLR_HTTP
from manyfaced.handlers import SolrHandler


class TestSolrHandler(unittest.TestCase):
    """Test Apache Solr responses."""

    def setUp(self):
        self.handler = SolrHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, SOLR_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/solr',
            'GET /solr HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Solr', response)
        self.assertEqual(detected, SOLR_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/solr/admin/authentication',
            'POST /solr/admin/authentication HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
