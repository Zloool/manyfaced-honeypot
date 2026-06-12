"""Shared fixtures for test_config submodule tests."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

project_root = os.path.abspath(os.path.join(__file__, '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set required secrets before importing config to avoid validation errors
os.environ.setdefault('HONEY_HIVEPASS', 'test_hivepass_for_tests')
os.environ.setdefault('HONEY_DEFAULT_KEY', 'test_default_key_for_tests')

geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules['geoip'] = geoip_mock
sys.modules['geoip.geolite2'] = geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()

from manyfaced.common.config import Config, _load_toml  # noqa: E402
from manyfaced.common.config_resolver import resolve_setting as _resolve, env_prefix as _env_prefix  # noqa: E402


def _write_toml(tmp_path: Path, content: str) -> Path:
    toml_path = tmp_path / 'config.toml'
    toml_path.write_text(content)
    return toml_path


class _TempDB:
    def __init__(self, path):
        self.path = path
        self._mock = None

    def __enter__(self):
        self._real_open = open
        self._mock = patch('manyfaced.common.utils.open', self._patched_open)
        self._mock.start()
        return self.path

    def __exit__(self, *exc):
        if self._mock:
            self._mock.stop()

    def _patched_open(self, path, mode, *args, **kwargs):
        return self._real_open(self.path, mode, *args, **kwargs)


def _make_time_counter(start=1000.0, increment=0.1):
    counter = [0]

    def side_effect():
        counter[0] += 1
        return start + counter[0] * increment

    return side_effect


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for key in list(os.environ.keys()):
        if key.startswith('HONEY_'):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def write_toml():
    def _write(content: str, tmp_path: Path) -> Path:
        return _write_toml(tmp_path, content)

    return _write
