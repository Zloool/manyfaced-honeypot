"""Tests for the PHPUnit handler (issue #273).

Covers:
- DETECTED_ID resolves to the PHPUnit HTTP detected-id.
- The /phpunit main page renders the PHPUnit UI (contains ``PHPUnit``).
- The eval-stdin.php RCE probe path is captured (returns ``Error`` payload
  and a record_request is logged).
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from manyfaced.handlers.phpunit_handler import PhpUnitHandler

try:  # pragma: no cover - exercised by import resolution
    from manyfaced.common.status import PHPUNIT_HTTP
except Exception:  # noqa: BLE001 - defensive fallback
    PHPUNIT_HTTP = 1034


class TestPhpUnitHandler(unittest.TestCase):
    def test_detected_id(self) -> None:
        """DETECTED_ID must match the shared PHPUnit HTTP constant."""
        self.assertEqual(PhpUnitHandler.DETECTED_ID, PHPUNIT_HTTP)
        self.assertEqual(PhpUnitHandler.domain, 'phpunit')

    def test_main_page(self) -> None:
        """GET /phpunit returns the PHPUnit UI and flags PHPUNIT_HTTP."""
        handler = PhpUnitHandler()
        fake_profile = MagicMock()
        handler.get_or_create_profile = lambda ip: fake_profile  # type: ignore[method-assign]

        raw = 'GET /phpunit HTTP/1.1\r\nHost: example.com\r\n\r\n'
        response, detected = handler.generate_response('/phpunit', raw, '203.0.113.5')

        self.assertIn(b'PHPUnit', response)
        self.assertEqual(detected, PHPUNIT_HTTP)
        fake_profile.record_request.assert_called()

    def test_eval_stdin_probe(self) -> None:
        """POST to eval-stdin.php is captured and returns an Error payload."""
        handler = PhpUnitHandler()
        fake_profile = MagicMock()
        handler.get_or_create_profile = lambda ip: fake_profile  # type: ignore[method-assign]

        path = '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
        raw = (
            f'POST {path} HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            'Content-Length: 19\r\n'
            '\r\n'
            'system("id");\n'
        )
        response, detected = handler.generate_response(path, raw, '198.51.100.7')

        # The eval-stdin response returns the authentic md5('Hello PHPUnit')
        # digest (issue #494), matching real PHPUnit eval behaviour.
        self.assertIn(b'6a9f35012f4290369bcf45fd7ccf29cf', response)
        self.assertEqual(detected, PHPUNIT_HTTP)
        # The probe request must have been recorded (captured), and it must
        # be flagged as the CVE-2017-9841 RCE attack vector.
        fake_profile.record_request.assert_called()
        _, call_kwargs = fake_profile.record_request.call_args
        recorded = call_kwargs.get('request') or fake_profile.record_request.call_args[0][0]
        self.assertTrue(recorded.get('attack'))
        self.assertEqual(recorded.get('cve'), 'CVE-2017-9841')

    def test_urlencoded_probe_paths(self) -> None:
        """Decoded %2eenv / %2f paths still resolve to the PHPUnit UI."""
        handler = PhpUnitHandler()
        fake_profile = MagicMock()
        handler.get_or_create_profile = lambda ip: fake_profile  # type: ignore[method-assign]

        raw = 'GET /phpunit/%2eenv HTTP/1.1\r\nHost: example.com\r\n\r\n'
        response, detected = handler.generate_response('/phpunit/%2eenv', raw, '10.0.0.9')

        self.assertIn(b'PHPUnit', response)
        self.assertEqual(detected, PHPUNIT_HTTP)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
