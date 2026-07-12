"""Status-constant integrity tests (cluster C1).

Guards the detected-id constants in ``manyfaced.common.status``:

  * ``PHPUNIT_HTTP`` (1047) must be distinct from ``ENV_DISC_HTTP`` (1034)
    so real PHPUnit eval-stdin RCE probes are not mislabeled as
    env-disclosure captures (issue #475).
  * No two HTTP detected-id constants may share a value — a collision
    would let one face shadow another at the DB/grouping layer.

These are data-integrity checks (not behaviour), so they fail loudly if a
future edit reuses a value or collides a new face onto an existing one.
"""

import inspect
import unittest

import manyfaced.common.status as status

# The explicit DETECTED_ID constants we care about guarding.
from manyfaced.common.status import (
    ENV_DISC_HTTP,
    PHPUNIT_HTTP,
)


def _all_detected_id_constants():
    """Return {name: value} for every *_HTTP detected-id constant.

    We treat the ascending HTTP service IDs (>= 1000) and the descending
    non-HTTP probe IDs (< 4294967283) as the two disjoint detected-id
    spaces. Anything in the module that is an int and looks like a
    detected-id constant qualifies.
    """
    constants = {}
    for name, value in inspect.getmembers(status):
        if not name.isupper() or not name.endswith('_HTTP'):
            continue
        if not isinstance(value, int):
            continue
        constants[name] = value
    return constants


class TestStatusConstants(unittest.TestCase):
    """Detected-id constants must be unique and correctly distinguished."""

    def test_phpunit_http_distinct_from_env_disc_http(self):
        """PHPUnit RCE id (1047) must not collide with env-disc id (1034)."""
        self.assertNotEqual(PHPUNIT_HTTP, ENV_DISC_HTTP)
        self.assertEqual(PHPUNIT_HTTP, 1047)
        self.assertEqual(ENV_DISC_HTTP, 1034)

    def test_no_duplicate_detected_id_values(self):
        """No two DETECTED_ID constants may share a numeric value."""
        constants = _all_detected_id_constants()
        self.assertGreater(len(constants), 0, 'no detected-id constants found')
        values = list(constants.values())
        duplicate_values = [v for v in values if values.count(v) > 1]
        self.assertEqual(
            duplicate_values,
            [],
            f'duplicate detected-id values among constants: {constants}',
        )


if __name__ == '__main__':
    unittest.main()
