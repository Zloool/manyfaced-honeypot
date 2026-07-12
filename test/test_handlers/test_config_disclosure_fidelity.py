"""Regression tests for config-disclosure body fidelity (issues #476, #478).

These assert that every router-routed path yields a TYPE-CORRECT disclosure
body (instead of the old wp-config.php fallback), and that POST bodies are
inspected and captured as IOC signals (never widening credential capture).
"""

import os
import sys
import unittest

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Must import the handler before building the per-route map below.
import manyfaced.handlers.routes.routes_config_disclosure as rcd  # noqa: E402
from manyfaced.handlers.config_disclosure_handler import (  # noqa: E402
    ConfigDisclosureHandler,
)


HEADERS_URLENCODED = {'Content-Type': 'application/x-www-form-urlencoded'}


class TestConfigDisclosureBodyFidelity(unittest.TestCase):
    """Every routed config path must serve a type-correct body (#476)."""

    def setUp(self):
        self.handler = ConfigDisclosureHandler()

    def _get(self, path: str) -> bytes:
        response, _ = self.handler.generate_response(
            path,
            f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        # Body is after the first blank line.
        return response.split(b'\r\n\r\n', 1)[1]

    def test_git_index_body(self):
        body = self._get('/.git/index')
        self.assertIn(b'DIRC', body)
        self.assertNotIn(b'<?php', body)

    def test_git_head_body(self):
        body = self._get('/.git/HEAD')
        self.assertIn(b'ref: refs/heads/', body)
        self.assertNotIn(b'<?php', body)

    def test_git_config_body(self):
        body = self._get('/.git/config')
        self.assertIn(b'[remote', body)
        self.assertNotIn(b'<?php', body)

    def test_gemfile_body(self):
        body = self._get('/Gemfile')
        self.assertIn(b'rubygems.org', body)
        self.assertNotIn(b'<?php', body)

    def test_gemfile_lock_body(self):
        body = self._get('/Gemfile.lock')
        self.assertIn(b'BUNDLED WITH', body)
        self.assertNotIn(b'<?php', body)

    def test_postgresql_conf_body(self):
        body = self._get('/postgresql.conf')
        self.assertIn(b'listen_addresses', body)
        self.assertNotIn(b'<?php', body)

    def test_redis_conf_body(self):
        body = self._get('/redis.conf')
        self.assertIn(b'requirepass', body)
        self.assertNotIn(b'<?php', body)

    def test_env_body(self):
        body = self._get('/.env')
        self.assertIn(b'DB_', body)
        self.assertNotIn(b'<?php', body)

    def test_db_php_body(self):
        body = self._get('/db.php')
        self.assertIn(b'<?php', body)
        self.assertIn(b'DB_', body)

    def test_appsettings_json_body(self):
        body = self._get('/appsettings.json')
        self.assertIn(b'ConnectionStrings', body)
        self.assertNotIn(b'<?php', body)

    def test_test_php_body(self):
        body = self._get('/test.php')
        self.assertIn(b'<?php', body)

    def test_no_route_serves_wpconfig_fallback(self):
        """No router-routed path may fall through to the wp-config.php body."""
        # Signature substring unique to the real fake wp-config.php body.
        wpconfig_sig = b'GenerateWP.com'
        for route in rcd.ROUTES:
            path = route.matcher._path if hasattr(route.matcher, '_path') else None
            prefix = route.matcher._prefix if hasattr(route.matcher, '_prefix') else None
            if path is not None:
                sample = path
            elif prefix is not None:
                sample = prefix.rstrip('/') or '/sql/x'
            else:  # pragma: no cover
                continue
            with self.subTest(route=route.name, path=sample):
                body = self._get(sample)
                # Only the wp-config* routes should serve the wp-config body.
                if not route.name.startswith('config_wp_config'):
                    self.assertNotIn(wpconfig_sig, body)


class TestConfigDisclosurePostInspection(unittest.TestCase):
    """POST bodies must be inspected and captured as IOC signals (#478)."""

    def setUp(self):
        self.handler = ConfigDisclosureHandler()

    def test_post_body_captured_as_ioc(self):
        raw = (
            'POST /.env HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            '\r\n'
            '0x%5B%5D=DTAB'
        )
        self.handler.generate_response('/.env', raw, '1.2.3.4', headers=HEADERS_URLENCODED)

        profile = self.handler.bot_profiles['1.2.3.4']
        post_records = [
            r for r in profile.request_history if r.get('vector') == 'config_disclosure_post'
        ]
        self.assertEqual(len(post_records), 1)
        self.assertEqual(post_records[0]['method'], 'POST')
        self.assertIn('0x[]=DTAB', post_records[0]['post_body'])

    def test_post_body_decoded_for_urlencoded(self):
        raw = (
            'POST /wp-config.php HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            '\r\n'
            'payload%5B%5D=probe123'
        )
        self.handler.generate_response('/wp-config.php', raw, '9.9.9.9', headers=HEADERS_URLENCODED)

        profile = self.handler.bot_profiles['9.9.9.9']
        post_records = [
            r for r in profile.request_history if r.get('vector') == 'config_disclosure_post'
        ]
        self.assertEqual(len(post_records), 1)
        self.assertIn('probe123', post_records[0]['post_body'])


if __name__ == '__main__':
    unittest.main()
