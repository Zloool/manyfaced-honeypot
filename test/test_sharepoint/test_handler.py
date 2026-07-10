"""SharePoint handler tests (issue #396 / CVE-2026-45659)."""

import unittest

from manyfaced.handlers.sharepoint_handler import SharePointHandler
from manyfaced.handlers.routes import routes_sharepoint


class TestSharePointHandler(unittest.TestCase):
    """Test SharePoint responses and credential capture."""

    def setUp(self):
        self.handler = SharePointHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, 1045)
        self.assertEqual(self.handler.domain, 'sharepoint')

    def test_start_page_returns_bytes(self):
        response, detected = self.handler.generate_response(
            '/_layouts/15/start.aspx',
            'GET /_layouts/15/start.aspx HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIsInstance(response, bytes)
        self.assertIn(b'SharePoint', response)
        self.assertEqual(detected, 1045)

    def test_api_returns_json(self):
        response, _ = self.handler.generate_response(
            '/_api/web',
            'GET /_api/web HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'{"d":{}}', response)
        self.assertIn(b'application/json', response)

    def test_cve_probe_captured(self):
        response, _ = self.handler.generate_response(
            '/_layouts/15/cve-2026-45659/deserialize.aspx',
            'POST /_layouts/15/cve-2026-45659/deserialize.aspx HTTP/1.1\r\nHost: x\r\n\r\n',
            '9.9.9.9',
        )
        self.assertIn(b'SharePoint', response)

    def test_login_post_captures_credentials(self):
        raw = (
            'POST /login HTTP/1.1\r\n'
            'Host: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'username=admin&password=secret123'
        )
        response, detected = self.handler.generate_response('/login', raw, '5.6.7.8')
        self.assertIn(b'SharePoint', response)
        self.assertEqual(detected, 1045)

        profile = self.handler.get_profile('5.6.7.8')
        self.assertIsNotNone(profile)
        self.assertTrue(len(profile.captured_credentials) >= 1)
        captured = profile.captured_credentials[0]
        self.assertEqual(captured.get('username'), 'admin')
        self.assertEqual(captured.get('password'), 'secret123')

    def test_routes_registered(self):
        self.assertGreaterEqual(len(routes_sharepoint.ROUTES), 1)
        names = [r.name for r in routes_sharepoint.ROUTES]
        self.assertIn('sharepoint_layouts', names)
        self.assertIn('sharepoint_api', names)


if __name__ == '__main__':
    unittest.main()
