"""Tests for high-entropy fingerprint-probe deflection (issue #324)."""

import os
import sys
import unittest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common import status as _status
from manyfaced.handlers.fingerprint import (
    HighEntropyPath,
    NotFoundHandler,
    build_apache_404,
    is_random_probe,
)
from manyfaced.handlers.router import Router
from manyfaced.handlers.routes import ROUTES


def _make_request(path: str, host: str = '68.183.114.1:4369') -> str:
    return f'GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n'


class TestIsRandomProbe(unittest.TestCase):
    """Pure classifier: high-entropy single-segment tokens -> True."""

    def test_log_sample_is_probe(self):
        self.assertTrue(is_random_probe('/3cwja4nt2qs1a4v'))

    def test_hex_base64_looking(self):
        self.assertTrue(is_random_probe('/xZ92kLmQ'))

    def test_multi_segment_not_probe(self):
        # /api/v2/users/1234 must still route/bait, never 404.
        self.assertFalse(is_random_probe('/api/v2/users/1234'))

    def test_dict_word_not_probe(self):
        for p in (
            '/wp-login.php',
            '/.env',
            '/actuator/health',
            '/index.php',
            '/assets/app.a1b2c3d4.js',
            '/backup',
            '/admin',
        ):
            self.assertFalse(is_random_probe(p), msg=p)

    def test_short_token_not_probe(self):
        # too short to be a fingerprint token
        self.assertFalse(is_random_probe('/abc'))

    def test_english_looking_not_probe(self):
        # dictionary structure (vowels + common bigrams) -> keep as bait
        self.assertFalse(is_random_probe('/administratorpage'))

    def test_extension_not_probe(self):
        self.assertFalse(is_random_probe('/3cwja4nt2qs1a4v.js'))


class TestApache404Shape(unittest.TestCase):
    """404 byte details must match a real Apache response."""

    def test_no_php_header_and_iso_charset(self):
        body = build_apache_404('68.183.114.1', 4369)
        text = body.decode('iso-8859-1')
        self.assertNotIn('X-Powered-By', text)
        self.assertIn('charset=iso-8859-1', text)
        self.assertIn('Apache/2.4.57 (Ubuntu)', text)
        self.assertIn('Server at 68.183.114.1 Port 4369', text)
        self.assertTrue(text.startswith('HTTP/1.1 404 Not Found'))

    def test_deterministic_per_host_port(self):
        # Identical (host,port) -> identical body (only Date header varies).
        b1 = build_apache_404('h.example', 80)
        b2 = build_apache_404('h.example', 80)

        # Strip the Date header line before comparing.
        def strip(b):
            return b'\r\n'.join(ln for ln in b.split(b'\r\n') if not ln.startswith(b'Date:'))

        self.assertEqual(strip(b1), strip(b2))


class TestDispatchRouting(unittest.TestCase):
    """Random probes + missing favicon route to the 404 handler, not bait."""

    def setUp(self):
        self.router = Router(ROUTES)

    def test_random_probe_404(self):
        result = self.router.dispatch(
            '/3cwja4nt2qs1a4v', _make_request('/3cwja4nt2qs1a4v'), '1.2.3.4'
        )
        assert result is not None
        body, detected = result
        self.assertEqual(detected, _status.FINGERPRINT_PROBE)
        self.assertIn(b'404 Not Found', body)
        self.assertNotIn(b'X-Powered-By', body)

    def test_favicon_404(self):
        # A missing /favicon.ico should 404, not draw a 200 monster page.
        result = self.router.dispatch('/favicon.ico', _make_request('/favicon.ico'), '1.2.3.4')
        assert result is not None
        body, detected = result
        self.assertEqual(detected, _status.FINGERPRINT_PROBE)
        self.assertIn(b'404 Not Found', body)

    def test_dict_path_still_baits(self):
        # Real service paths must still hit their handlers / the monster page.
        for path in ('/wp-login.php', '/.env', '/actuator/health', '/admin'):
            result = self.router.dispatch(path, _make_request(path), '1.2.3.4')
            assert result is not None, path
            body, _ = result
            self.assertNotIn(b'404 Not Found', body, msg=path)

    def test_high_entropy_matcher_class(self):
        m = HighEntropyPath()
        self.assertTrue(m.match('/3cwja4nt2qs1a4v'))
        self.assertFalse(m.match('/wp-login.php'))


if __name__ == '__main__':
    import unittest

    unittest.main()
