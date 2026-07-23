"""Tests for the Fortinet FortiGate/FortiManager honeypot face."""

from __future__ import annotations

import unittest

from manyfaced.handlers.fortinet_handler import FortinetHandler, DETECTED_ID
from manyfaced.handlers.routes import routes_fortinet


BOT_IP = '203.0.113.45'


def _post_logincheck(username: str = 'admin', password: str = 'P@ssw0rd!') -> str:
    """Build a realistic FortiGate /remote/logincheck POST request."""
    body = f'username={username}&password={password}&realm=&ajax=1'
    return (
        'POST /remote/logincheck HTTP/1.1\r\n'
        'Host: vpn.example.com\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: {len(body)}\r\n'
        'Connection: close\r\n'
        '\r\n'
        f'{body}'
    )


class TestFortinetHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = FortinetHandler()

    def test_login_page_returns_bytes(self) -> None:
        resp, flag = self.handler.generate_response(
            '/remote/login', 'GET /remote/login HTTP/1.1\r\nHost: x\r\n\r\n', BOT_IP
        )
        self.assertIsInstance(resp, bytes)
        self.assertIn(DETECTED_ID, (flag,))  # flag == DETECTED_ID
        self.assertEqual(flag, DETECTED_ID)
        # Login page should mention FortiGate / Fortinet.
        self.assertIn(b'FortiGate', resp)
        self.assertIn(b'Fortinet', resp)

    def test_logincheck_captures_credentials(self) -> None:
        raw = _post_logincheck('alice', 's3cr3t')
        resp, flag = self.handler.generate_response('/remote/logincheck', raw, BOT_IP)

        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)
        # FortiGate returns '1' on success.
        self.assertIn(b'1', resp)

        # Credentials must be captured in the bot profile.
        profile = self.handler.get_profile(BOT_IP)
        self.assertIsNotNone(profile)
        captured = profile.captured_credentials
        self.assertTrue(any(c.get('username') == 'alice' for c in captured))
        self.assertTrue(any(c.get('password') == 's3cr3t' for c in captured))

    def test_logout_response(self) -> None:
        resp, flag = self.handler.generate_response(
            '/remote/logout', 'GET /remote/logout HTTP/1.1\r\nHost: x\r\n\r\n', BOT_IP
        )
        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)

    def test_api_v2_json(self) -> None:
        resp, flag = self.handler.generate_response(
            '/api/v2/cmdb/system/status',
            'GET /api/v2/cmdb/system/status HTTP/1.1\r\nHost: x\r\n\r\n',
            BOT_IP,
        )
        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)
        self.assertIn(b'application/json', resp)

    def test_jsonrpc_response(self) -> None:
        raw = (
            'POST /jsonrpc HTTP/1.1\r\n'
            'Host: fmg.example.com\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: 63\r\n'
            'Connection: close\r\n'
            '\r\n'
            '{"method":"get","params":[],"id":1,"session":""}'
        )
        resp, flag = self.handler.generate_response('/jsonrpc', raw, BOT_IP)
        self.assertIsInstance(resp, bytes)
        self.assertEqual(flag, DETECTED_ID)
        self.assertIn(b'application/json', resp)

    def test_fake_svpn_cookie_format_and_determinism(self) -> None:
        """The fake SSL-VPN cookie must be a 48-hex-char, deterministic value.

        Regression test for issue #658: the cookie must remain the same length
        and format from the client's perspective (48 hex chars) and be stable
        across calls so a session's cookie is consistent. It must NOT be a raw
        sha256 of a secret (the old weak-hash construction).
        """
        c1 = self.handler._fake_svpn_cookie('admin')
        c2 = self.handler._fake_svpn_cookie('admin')
        c_other = self.handler._fake_svpn_cookie('root')

        # Deterministic: same username -> same cookie.
        self.assertEqual(c1, c2)
        # Different usernames produce different cookies.
        self.assertNotEqual(c1, c_other)
        # Same length/format as the original fake cookie (48 hex chars).
        self.assertEqual(len(c1), 48)
        self.assertRegex(c1, r'^[0-9a-f]{48}$')

    def test_fake_svpn_cookie_is_keyed_hmac_not_plain_sha256(self) -> None:
        """Cookie must be HMAC-SHA256 keyed with the decoy secret, not sha256(raw).

        Guards against a regression to the weak ``hashlib.sha256(raw)``
        construction that triggered the py/weak-sensitive-data-hashing alert.
        """
        import hashlib
        import hmac

        username = 'operator'
        cookie = self.handler._fake_svpn_cookie(username)
        raw = f'{username}:{self.handler.SERIAL}:{self.handler.VERSION}'.encode('utf-8')

        # Direct sha256 of the raw input must NOT be the cookie (weak form).
        self.assertNotEqual(hashlib.sha256(raw).hexdigest()[:48], cookie)
        # The cookie must equal the keyed HMAC-SHA256 over raw (strong form).
        expected = hmac.new(self.handler._FAKE_SVPN_COOKIE_SECRET, raw, 'sha256').hexdigest()[:48]
        self.assertEqual(cookie, expected)

    def test_routes_registered(self) -> None:
        self.assertGreaterEqual(len(routes_fortinet.ROUTES), 1)
        names = {r.name for r in routes_fortinet.ROUTES}
        self.assertIn('fortinet_sslvpn_login', names)
        self.assertIn('fortinet_fmgr_jsonrpc', names)
        for r in routes_fortinet.ROUTES:
            self.assertEqual(r.detected_id, DETECTED_ID)


if __name__ == '__main__':
    unittest.main()
