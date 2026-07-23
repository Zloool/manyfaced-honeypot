"""RabbitMQ handler tests (issue #285 / #643)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import RABBITMQ_HTTP
from manyfaced.handlers.rabbitmq_handler import RabbitMQHandler


class TestRabbitMQHandler(unittest.TestCase):
    """Test RabbitMQ responses."""

    def setUp(self):
        self.handler = RabbitMQHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, RABBITMQ_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/api/overview',
            'GET /api/overview HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertTrue(b'rabbitmq' in response or b'RabbitMQ' in response)
        self.assertEqual(detected, RABBITMQ_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/login',
            'POST /login HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)

    def test_rabbitmq_owns_root_and_cli(self):
        """RabbitMQ's own management surface (/, /cli) is classified RABBITMQ_HTTP."""
        from manyfaced.handlers.router import Router
        from manyfaced.handlers.routes import ROUTES

        router = Router(ROUTES)
        for path in ('/', '/cli', '/rabbitmq/.env'):
            result = router.dispatch(
                path, 'GET ' + path + ' HTTP/1.1\r\nHost: x\r\n\r\n', '1.2.3.4'
            )
            assert result is not None, path
            _body, detected = result
            self.assertEqual(detected, RABBITMQ_HTTP, f'{path} -> {detected}')


class TestRabbitMQRouting(unittest.TestCase):
    """Router-level classification for 15672 management paths (issue #643)."""

    @staticmethod
    def _make_request(path: str) -> str:
        return 'GET ' + path + ' HTTP/1.1\r\nHost: x\r\n\r\n'

    def test_management_paths_classify_as_rabbitmq(self):
        from manyfaced.handlers.router import Router
        from manyfaced.handlers.routes import ROUTES

        router = Router(ROUTES)
        # RabbitMQ owns its own management surface; ES-style probe paths and
        # /api/* belong to Elastic (issue #644 / PR #670) and are not claimed here.
        paths = [
            '/',
            '/cli',
            '/rabbitmq/.env',
        ]
        for path in paths:
            result = router.dispatch(path, self._make_request(path), '1.2.3.4')
            assert result is not None, path
            _body, detected = result
            self.assertEqual(detected, RABBITMQ_HTTP, f'{path} -> {detected}')

    def test_es_probe_paths_classify_as_elastic(self):
        from manyfaced.common.status import ELASTIC_HTTP
        from manyfaced.handlers.router import Router
        from manyfaced.handlers.routes import ROUTES

        router = Router(ROUTES)
        for path in ('/_cluster/state', '/_nodes/stats', '/_search', '/_cat/indices'):
            result = router.dispatch(path, self._make_request(path), '1.2.3.4')
            assert result is not None, path
            _body, detected = result
            self.assertEqual(detected, ELASTIC_HTTP, f'{path} -> {detected}')


if __name__ == '__main__':
    unittest.main()
