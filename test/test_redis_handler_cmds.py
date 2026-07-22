"""Redis handler command tests (issue #650).

Covers the AUTH success/failure round-trip and the newly recognised RESP
commands (SUBSCRIBE / PUBLISH / LPUSH / EXPIRE / EVAL / CLUSTER) that the
prod recon flagged as returning nothing/garbage.

This is intentionally a standalone module so it can be added without colliding
with the shared ``TestRedisHandler`` suite in ``test_protocol_handlers``.
"""

import unittest

from manyfaced.handlers.redis_handler import (
    REDIS_AUTH_PASSWORD,
    extract_redis_credentials,
    generate_redis_response,
)

_REDIS_MOD = __import__('manyfaced.handlers.redis_handler', fromlist=['REDIS_AUTH_PASSWORD'])


class TestRedisAuth(unittest.TestCase):
    """AUTH round-trip: accept-any by default, reject-wrong when trapped (#650)."""

    def tearDown(self):
        _REDIS_MOD.REDIS_AUTH_PASSWORD = None

    def test_auth_accepts_any_password_by_default(self):
        self.assertIsNone(REDIS_AUTH_PASSWORD)
        raw = b'*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$6\r\nwhatever\r\n'
        resp = generate_redis_response(raw, '10.0.0.8')
        self.assertEqual(resp, b'+OK\r\n')
        creds = extract_redis_credentials(raw)
        self.assertEqual(creds, ('admin', 'whatever'))

    def test_auth_empty_password_still_accepted(self):
        raw = b'*2\r\n$4\r\nAUTH\r\n$0\r\n\r\n'
        resp = generate_redis_response(raw, '10.0.0.8')
        self.assertEqual(resp, b'+OK\r\n')

    def test_auth_wrong_password_rejected(self):
        _REDIS_MOD.REDIS_AUTH_PASSWORD = 'honeypot'
        raw_wrong = b'*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$3\r\nbad\r\n'
        self.assertEqual(
            generate_redis_response(raw_wrong, '10.0.0.9'),
            b'-ERR invalid password\r\n',
        )

    def test_auth_correct_trap_password_accepted(self):
        _REDIS_MOD.REDIS_AUTH_PASSWORD = 'honeypot'
        raw_right = b'*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$8\r\nhoneypot\r\n'
        self.assertEqual(
            generate_redis_response(raw_right, '10.0.0.9'),
            b'+OK\r\n',
        )


class TestRedisNewCommands(unittest.TestCase):
    """Newly recognised commands must return plausible RESP replies (#650)."""

    def test_subscribe_push_array(self):
        raw = b'*2\r\n$9\r\nSUBSCRIBE\r\n$3\r\nfoo\r\n'
        resp = generate_redis_response(raw, '10.0.0.10')
        self.assertTrue(resp.startswith(b'*3\r\n'))
        self.assertIn(b'subscribe', resp)
        self.assertIn(b'foo', resp)

    def test_publish_receiver_count(self):
        raw = b'*3\r\n$7\r\nPUBLISH\r\n$3\r\nfoo\r\n$2\r\nhi\r\n'
        self.assertEqual(generate_redis_response(raw, '10.0.0.10'), b':0\r\n')

    def test_lpush_list_length(self):
        raw = b'*3\r\n$5\r\nLPUSH\r\n$1\r\nk\r\n$1\r\nv\r\n'
        self.assertEqual(generate_redis_response(raw, '10.0.0.10'), b':1\r\n')

    def test_expire_set(self):
        raw = b'*3\r\n$6\r\nEXPIRE\r\n$1\r\nk\r\n$3\r\n100\r\n'
        self.assertEqual(generate_redis_response(raw, '10.0.0.10'), b':1\r\n')

    def test_eval_bulk_reply(self):
        raw = b'*4\r\n$4\r\nEVAL\r\n$1\r\n1\r\n$1\r\n0\r\n$1\r\nk\r\n'
        resp = generate_redis_response(raw, '10.0.0.10')
        self.assertTrue(resp.startswith(b'$'))
        self.assertIn(b'OK', resp)

    def test_cluster_info_bulk(self):
        raw = b'*2\r\n$7\r\nCLUSTER\r\n$4\r\nINFO\r\n'
        resp = generate_redis_response(raw, '10.0.0.10')
        self.assertIn(b'$', resp)


if __name__ == '__main__':
    unittest.main()
