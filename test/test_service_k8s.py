"""Kubernetes handler tests (issue #274)."""

import os
import sys
import unittest
from unittest.mock import MagicMock

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common.status import KUBERNETES_HTTP
from manyfaced.handlers import KubernetesHandler
from manyfaced.handlers.router import Router
from manyfaced.handlers.routes import ROUTES, router


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
        self.assertTrue(b'kube' in response.lower() or b'kubernetes' in response.lower())
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


class TestKubernetesRoutePrecedence(unittest.TestCase):
    """Regression guard for issue #592: k8s /api/v1* must win over Next.js.

    The generic Next.js ``PathPrefix('/api/')`` used to sit before the
    Kubernetes route table and reverse-shadow every core kube-apiserver path
    (``/api/v1``, ``/api/v1/namespaces/<ns>/secrets``, ``/api/v1/targets``,
    ``/apis``). These tests pin the correct dispatch so the bug cannot
    silently return.
    """

    def _dispatch(self, path: str):
        r = Router(ROUTES)
        result = r.dispatch(
            path,
            f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
            {},
        )
        assert result is not None, f'No route matched for path: {path}'
        return result[1]

    def test_api_v1_classifies_kubernetes(self):
        self.assertEqual(self._dispatch('/api/v1'), KUBERNETES_HTTP)
        self.assertIn('k8s', router.explain('/api/v1').lower())

    def test_api_v1_nested_namespaces_secrets_kubernetes(self):
        path = '/api/v1/namespaces/kube-system/secrets'
        self.assertEqual(self._dispatch(path), KUBERNETES_HTTP)

    def test_api_v1_targets_kubernetes(self):
        self.assertEqual(self._dispatch('/api/v1/targets'), KUBERNETES_HTTP)

    def test_api_v1_namespaces_kubernetes(self):
        self.assertEqual(self._dispatch('/api/v1/namespaces'), KUBERNETES_HTTP)

    def test_apis_classifies_kubernetes(self):
        self.assertEqual(self._dispatch('/apis'), KUBERNETES_HTTP)
        self.assertEqual(self._dispatch('/apis/apps/v1'), KUBERNETES_HTTP)

    def test_explain_points_at_kubernetes(self):
        self.assertIn('k8s', router.explain('/api/v1').lower())
        self.assertIn('k8s', router.explain('/api/v1/namespaces/kube-system/secrets').lower())
        self.assertIn('k8s', router.explain('/apis').lower())


if __name__ == '__main__':
    unittest.main()
