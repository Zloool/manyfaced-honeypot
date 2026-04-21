"""
Tests for manyfaced.common.utils, manyfaced.common.config, and manyfaced.common.arguments.

Usage:
    /usr/bin/python3 -m pytest test/test_utils_config_args.py -v -c /home/zlol/manyfaced-honeypot/pytest.ini
"""

import os
import pickle
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ---------------------------------------------------------------------------
# Mock geoip modules before any module that uses it is imported
# ---------------------------------------------------------------------------
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules["geoip"] = geoip_mock
sys.modules["geoip.geolite2"] = geoip_mock.geolite2
sys.modules["GeoIP"] = MagicMock()

# ---------------------------------------------------------------------------
# Import units under test
# ---------------------------------------------------------------------------
from manyfaced.common.utils import dump_file, receive_timeout
from manyfaced.common.config import Config, _find_config_file, _load_toml, _resolve, _env_prefix
from manyfaced.common.arguments import parse


# ===================================================================
# Helper utilities
# ===================================================================

class _TempDB:
    """Context manager that patches dump_file to use a temp file."""

    def __init__(self, path):
        self.path = path
        self._mock = None

    def __enter__(self):
        self._real_open = open
        self._mock = patch("manyfaced.common.utils.open", self._patched_open)
        self._mock.start()
        return self.path

    def __exit__(self, *exc):
        if self._mock:
            self._mock.stop()

    def _patched_open(self, path, mode, *args, **kwargs):
        return self._real_open(self.path, mode, *args, **kwargs)


def _write_toml(tmp_path, content):
    """Write a TOML file and return its Path."""
    toml_path = tmp_path / "config.toml"
    toml_path.write_text(content)
    return toml_path


def _make_time_counter(start=1000.0, increment=0.1):
    """Create a time.time() side_effect that increments by `increment` each call."""
    counter = [0]

    def side_effect():
        counter[0] += 1
        return start + counter[0] * increment

    return side_effect


# ===================================================================
# utils.py  –  dump_file / receive_timeout
# ===================================================================


from manyfaced.common.arguments import parse

def _parse_with_args(monkeypatch, argv):
    """Helper: set sys.argv and call parse()."""
    monkeypatch.setattr("sys.argv", ["mfh.py"] + argv)
    return parse()


class TestParseDefaults:
    """No args → client=None, server=None, updater=False, verbose=False."""

    def test_no_args_defaults(self):
        """When no arguments are given, all optional flags should be None/False."""
        args = parse(args=[])

        assert args.client is None
        assert args.server is None
        assert args.updater is False
        assert args.verbose is False
        assert args.proxy is False
        assert args.generate_config is False



class TestParseClient:
    """-c 80 → client=80."""

    def test_client_port(self):
        args = parse(args=["-c", "80"])
        assert args.client == 80



class TestParseServer:
    """-s 666 → server=666."""

    def test_server_port(self):
        args = parse(args=["-s", "666"])
        assert args.server == 666



class TestParseClientServer:
    """-c 80 -s 666 → both set."""

    def test_client_and_server(self):
        args = parse(args=["-c", "80", "-s", "666"])
        assert args.client == 80
        assert args.server == 666



class TestParseVerbose:
    """-v → verbose=True."""

    def test_verbose_short(self):
        args = parse(args=["-v"])
        assert args.verbose is True

    def test_verbose_long(self):
        args = parse(args=["--verbose"])
        assert args.verbose is True



class TestParseUpdater:
    """-u → updater=True."""

    def test_updater(self):
        args = parse(args=["-u"])
        assert args.updater is True



class TestParseProxy:
    """-p → proxy=True."""

    def test_proxy_short(self):
        args = parse(args=["-p"])
        assert args.proxy is True

    def test_proxy_long(self):
        args = parse(args=["--proxy"])
        assert args.proxy is True



class TestParseGenerateConfig:
    """--generate-config → generate_config=True."""

    def test_generate_config(self):
        args = parse(args=["--generate-config"])
        assert args.generate_config is True



class TestParseAllFlags:
    """Combine all flags."""

    def test_all_flags(self):
        args = parse(args=["-c", "80", "-s", "666", "-u", "-v", "-p", "--generate-config"])
        assert args.client == 80
        assert args.server == 666
        assert args.updater is True
        assert args.verbose is True
        assert args.proxy is True
        assert args.generate_config is True



class TestParseClientNoPort:
    """-c without port → client=HONEYPORT default."""

    def test_client_no_port_uses_default(self):
        from manyfaced.common.settings import HONEYPORT
        args = parse(args=["-c"])
        assert args.client == HONEYPORT

    def test_server_no_port_uses_default(self):
        from manyfaced.common.settings import HIVEPORT
        args = parse(args=["-s"])
        assert args.server == HIVEPORT


# ===================================================================
# Additional edge-case tests
# ===================================================================


