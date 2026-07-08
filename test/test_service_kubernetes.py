"""Kubernetes handler tests (issue #274)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import KUBERNETES_HTTP
from manyfaced.handlers import KubernetesHandler


class TestKubernetesHandler(unittest.TestCase):
    """Test Kubernetes responses."""

    def setUp(self):
        self.handler = KubernetesHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, KUBERNETES_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/api/v1',
            'GET /api/v1 HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertTrue(
            b'kube' in response.lower() or b'kubernetes' in response.lower()
        )
        self.assertEqual(detected, KUBERNETES_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/dashboard',
            'POST /dashboard HTTP/1.1\r\nHost: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
