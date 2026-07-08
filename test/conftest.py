"""Configure import path and mock dependencies for testing."""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Make manyfaced package importable from project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip before any module that uses it is imported
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules['geoip'] = geoip_mock
sys.modules['geoip.geolite2'] = geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()


# Pristine ``config.settings`` snapshot, captured lazily on the first test run
# (not at import). Capturing at import would miss env vars that sibling
# conftests set via ``os.environ.setdefault`` during collection — e.g.
# ``test/test_config/conftest.py`` injects HONEY_HIVEPASS / HONEY_DEFAULT_KEY so
# ``validate_secrets()`` passes. Lazy capture guarantees the snapshot includes
# those secrets (issue #243 root-conftest must not clobber them).
_PRISTINE_SETTINGS = None


@pytest.fixture(autouse=True)
def _reset_test_globals():
    """Clear get_storage()'s singleton and restore pristine config between tests.

    Issue #243 caches one StorageBackend per process and the [postgres] extra is
    now installed, so a postgresql instance cached by one test package (or a
    mutated ``config.settings``) must not leak into another. Restoring the
    pristine ``settings`` guarantees every test starts from clean config.
    """
    import manyfaced.common.config as config_mod
    from manyfaced.db.storage import reset_storage_singleton

    global _PRISTINE_SETTINGS
    if _PRISTINE_SETTINGS is None:
        _PRISTINE_SETTINGS = config_mod.settings

    saved = config_mod.settings
    config_mod.settings = _PRISTINE_SETTINGS
    reset_storage_singleton()
    yield
    config_mod.settings = saved
    reset_storage_singleton()
