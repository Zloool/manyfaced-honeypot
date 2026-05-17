"""Tests for _resolve_db_path() and _resolve_backend()."""

import os
from unittest.mock import patch

# Imports handled by conftest.py sys.path setup
from manyfaced.db.storage import _resolve_backend, _resolve_db_path  # noqa: E402


# ---------------------------------------------------------------------------
# _resolve_db_path tests
# ---------------------------------------------------------------------------


class TestResolveDbPath:
    """Tests for _resolve_db_path()."""

    def test_default_path_when_env_not_set(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH=None),
        ):
            result = _resolve_db_path()
        assert result == 'bots/honeypot.sqlite'

    def test_falls_back_to_toml_config_db_path(self):
        """When no env var is set, falls back to TOML config's database.path."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH='/custom/from/toml.db'),
        ):
            result = _resolve_db_path()
        assert result == '/custom/from/toml.db'

    def test_env_overrides_toml_config(self):
        """HONEY_DB_PATH env var takes precedence over TOML config."""
        with (
            patch.dict(os.environ, {'HONEY_DB_PATH': '/env/override.db'}, clear=True),
            patch('manyfaced.common.config.settings', DB_PATH='/toml/path.db'),
        ):
            result = _resolve_db_path()
        assert result == '/env/override.db'

    def test_custom_path_from_env(self):
        with patch.dict(os.environ, {'HONEY_DB_PATH': '/tmp/custom.db'}, clear=True):
            result = _resolve_db_path()
        assert result == '/tmp/custom.db'

    def test_env_path_with_subdirs(self):
        with patch.dict(os.environ, {'HONEY_DB_PATH': 'data/nested/honeypot.db'}, clear=True):
            result = _resolve_db_path()
        assert result == 'data/nested/honeypot.db'


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
