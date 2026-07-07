"""Tests for _resolve_db_path() and _resolve_backend()."""

import os
from unittest.mock import patch

# Keep HOME/USERPROFILE intact: config.py's Config.load() reads Path.home(),
# which raises on Windows when the env is fully cleared (patch.dict clear=True
# wipes USERPROFILE). We only need to guarantee HONEY_DB_PATH is absent.
_env_no_db = {k: v for k, v in os.environ.items() if k != 'HONEY_DB_PATH'}

# Imports handled by conftest.py sys.path setup
from manyfaced.db import storage  # noqa: E402
from manyfaced.db.storage import (  # noqa: E402
    _resolve_backend,
    _resolve_db_path,
    validate_db_path_absolute,
)


_PROJECT_ROOT = storage._PROJECT_ROOT


# ---------------------------------------------------------------------------
# _resolve_db_path tests
# ---------------------------------------------------------------------------


class TestResolveDbPath:
    """Tests for _resolve_db_path()."""

    def test_default_path_becomes_absolute_under_root(self):
        """Default relative fallback is rewritten to an absolute path (issue #188)."""
        with (
            patch.dict(os.environ, _env_no_db, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH=None),
        ):
            result = _resolve_db_path()
        assert os.path.isabs(result)
        assert result.endswith(os.path.join('bots', 'honeypot.sqlite'))

    def test_falls_back_to_toml_config_db_path(self):
        """When no env var is set, falls back to TOML config's database.path."""
        with (
            patch.dict(os.environ, _env_no_db, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH='/custom/from/toml.db'),
        ):
            result = _resolve_db_path()
        # Unix-style path has no drive letter so it's treated as relative on
        # Windows and rewritten to absolute; assert it resolves to that target.
        assert os.path.isabs(result)
        assert result.replace('\\', '/').endswith('/custom/from/toml.db')

    def test_env_overrides_toml_config(self):
        """HONEY_DB_PATH env var takes precedence over TOML config."""
        with (
            patch.dict(os.environ, {'HONEY_DB_PATH': '/env/override.db'}, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH='/toml/path.db'),
        ):
            result = _resolve_db_path()
        assert os.path.isabs(result)
        assert result.replace('\\', '/').endswith('/env/override.db')

    def test_custom_path_from_env(self):
        with patch.dict(os.environ, {'HONEY_DB_PATH': '/tmp/custom.db'}, clear=True):
            result = _resolve_db_path()
        assert os.path.isabs(result)
        assert result.replace('\\', '/').endswith('/tmp/custom.db')

    def test_relative_env_path_rewritten_to_absolute(self):
        """A relative HONEY_DB_PATH is rewritten to absolute under the project root (#188)."""
        with patch.dict(os.environ, {'HONEY_DB_PATH': 'data/nested/honeypot.db'}, clear=True):
            result = _resolve_db_path()
        assert os.path.isabs(result)
        assert result.endswith(os.path.join('data', 'nested', 'honeypot.db'))
        assert result.startswith(_PROJECT_ROOT)

    def test_validate_db_path_absolute_true_for_absolute(self):
        """validate_db_path_absolute() returns True when the configured path is absolute."""
        abs_path = os.path.abspath('/abs/path/db.sqlite')
        with patch.dict(os.environ, {'HONEY_DB_PATH': abs_path}, clear=True):
            assert validate_db_path_absolute() is True

    def test_validate_db_path_absolute_false_for_relative_default(self):
        """validate_db_path_absolute() returns False for the relative default (CI/deploy guard)."""
        with (
            patch.dict(os.environ, _env_no_db, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH=None),
        ):
            assert validate_db_path_absolute() is False


# ---------------------------------------------------------------------------
# _resolve_backend tests
# ---------------------------------------------------------------------------


class TestResolveBackend:
    """Tests for _resolve_backend()."""

    def test_default_backend_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            result = _resolve_backend()
        assert result == 'sqlite'

    def test_custom_backend_from_env_lowercase(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'postgresql'}, clear=True):
            result = _resolve_backend()
        assert result == 'postgresql'

    def test_custom_backend_from_env_uppercase(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'PostgreSQL'}, clear=True):
            result = _resolve_backend()
        assert result == 'postgresql'

    def test_custom_backend_from_env_mixed_case(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'SQLITE'}, clear=True):
            result = _resolve_backend()
        assert result == 'sqlite'

    def test_env_backend_stored_lowercase(self):
        with patch.dict(os.environ, {'HONEY_DB_BACKEND': 'POSTGRES'}, clear=True):
            result = _resolve_backend()
        assert result == 'postgres'
