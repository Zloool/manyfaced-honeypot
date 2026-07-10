"""Tests for the Langflow honeypot handler and route table."""

import unittest

from manyfaced.handlers.langflow_handler import LangflowHandler
from manyfaced.handlers.routes import routes_langflow


BOT_IP = '203.0.113.42'


class TestLangflowHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = LangflowHandler()

    def test_login_returns_http_response(self) -> None:
        raw = 'GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n'
        resp, detected = self.handler.generate_response('/login', raw, BOT_IP)
        self.assertIsInstance(resp, bytes)
        text = resp.decode('iso-8859-1')
        self.assertTrue('200' in text or 'HTTP' in text)
        self.assertIn('Content-Length', text)

    def test_root_serves_login_page(self) -> None:
        raw = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        resp, detected = self.handler.generate_response('/', raw, BOT_IP)
        text = resp.decode('iso-8859-1')
        self.assertIn('Langflow', text)
        self.assertEqual(detected, 1041)

    def test_api_run_returns_json(self) -> None:
        raw = 'POST /api/v1/run HTTP/1.1\r\nHost: example.com\r\n\r\n'
        resp, detected = self.handler.generate_response('/api/v1/run', raw, BOT_IP)
        text = resp.decode('iso-8859-1')
        self.assertIn('"outputs"', text)
        self.assertIn('application/json', text)

    def test_api_flows_returns_json(self) -> None:
        raw = 'GET /api/v1/flows HTTP/1.1\r\nHost: example.com\r\n\r\n'
        resp, detected = self.handler.generate_response('/api/v1/flows', raw, BOT_IP)
        self.assertIn('200', resp.decode('iso-8859-1'))

    def test_api_validate_returns_200(self) -> None:
        raw = 'GET /api/v1/validate HTTP/1.1\r\nHost: example.com\r\n\r\n'
        resp, detected = self.handler.generate_response('/api/v1/validate', raw, BOT_IP)
        self.assertIn('200', resp.decode('iso-8859-1'))

    def test_upload_endpoint_captures(self) -> None:
        raw = (
            'POST /api/v1/upload HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=langflow123'
        )
        resp, detected = self.handler.generate_response('/api/v1/upload', raw, BOT_IP)
        self.assertIn('200', resp.decode('iso-8859-1'))
        profile = self.handler.get_profile(BOT_IP)
        self.assertIsNotNone(profile)
        self.assertTrue(len(profile.captured_credentials) >= 1)
        captured = profile.captured_credentials[0]
        self.assertEqual(captured.get('username'), 'admin')
        self.assertEqual(captured.get('password'), 'langflow123')

    def test_login_post_captures_credentials(self) -> None:
        raw = (
            'POST /login HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secretpass'
        )
        resp, detected = self.handler.generate_response('/login', raw, BOT_IP)
        text = resp.decode('iso-8859-1')
        self.assertTrue('200' in text or 'HTTP' in text)
        profile = self.handler.get_profile(BOT_IP)
        self.assertIsNotNone(profile)
        self.assertTrue(len(profile.captured_credentials) >= 1)
        captured = profile.captured_credentials[0]
        self.assertEqual(captured.get('username'), 'admin')
        self.assertEqual(captured.get('password'), 'secretpass')


class TestLangflowRoutes(unittest.TestCase):
    def test_routes_present(self) -> None:
        self.assertGreaterEqual(len(routes_langflow.ROUTES), 1)

    def test_route_names_and_ids(self) -> None:
        names = {r.name for r in routes_langflow.ROUTES}
        self.assertIn('langflow_login', names)
        self.assertIn('langflow_api_run', names)
        for r in routes_langflow.ROUTES:
            self.assertEqual(r.detected_id, 1041)


if __name__ == '__main__':
    unittest.main()
