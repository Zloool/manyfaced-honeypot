"""
Tests for manyfaced.common.utils, manyfaced.common.config, and manyfaced.common.arguments.

Usage:
    /usr/bin/python3 -m pytest test/test_utils_config_args.py -v -c /home/zlol/manyfaced-honeypot/pytest.ini
"""

import os
import sys
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


def _parse_with_args(monkeypatch, argv):
    """Helper: set sys.argv and call parse()."""
    monkeypatch.setattr("sys.argv", ["mfh.py"] + argv)
    return parse()


class TestParseDefaults:
    """No args → client=None, server=None, updater=False, verbose=False."""

    def test_no_args_defaults(self, monkeypatch):
        """When no arguments are given, all optional flags should be None/False."""
        args = _parse_with_args(monkeypatch, [])

        assert args.client is None
        assert args.server is None
        assert args.updater is False
        assert args.verbose is False
        assert args.proxy is False
        assert args.generate_config is False
        assert args.port_mode == "single"
        assert args.top_ports == ""


class TestParseClient:
    """-c 80 → client=80."""

    def test_client_port(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["-c", "80"])
        assert args.client == 80


class TestParseServer:
    """-s 666 → server=666."""

    def test_server_port(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["-s", "666"])
        assert args.server == 666


class TestParseClientServer:
    """-c 80 -s 666 → both set."""

    def test_client_and_server(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["-c", "80", "-s", "666"])
        assert args.client == 80
        assert args.server == 666


class TestParseVerbose:
    """-v → verbose=True."""

    def test_verbose_short(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["-v"])
        assert args.verbose is True

    def test_verbose_long(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--verbose"])
        assert args.verbose is True


class TestParseUpdater:
    """-u → updater=True."""

    def test_updater(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["-u"])
        assert args.updater is True


class TestParseProxy:
    """-p → proxy=True."""

    def test_proxy_short(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["-p"])
        assert args.proxy is True

    def test_proxy_long(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--proxy"])
        assert args.proxy is True


class TestParseGenerateConfig:
    """--generate-config → generate_config=True."""

    def test_generate_config(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--generate-config"])
        assert args.generate_config is True


class TestParseAllFlags:
    """Combine all flags."""

    def test_all_flags(self, monkeypatch):
        args = _parse_with_args(
            monkeypatch,
            ["-c", "80", "-s", "666", "-u", "-v", "-p", "--generate-config"],
        )
        assert args.client == 80
        assert args.server == 666
        assert args.updater is True
        assert args.verbose is True
        assert args.proxy is True
        assert args.generate_config is True


class TestParseClientNoPort:
    """-c without port → client=HONEYPORT default."""

    def test_client_no_port_uses_default(self, monkeypatch):
        from manyfaced.common.config import settings

        HONEYPORT = settings.HONEYPORT

        args = _parse_with_args(monkeypatch, ["-c"])
        assert args.client == HONEYPORT

    def test_server_no_port_uses_default(self, monkeypatch):
        from manyfaced.common.config import settings

        HIVEPORT = settings.HIVEPORT

        args = _parse_with_args(monkeypatch, ["-s"])
        assert args.server == HIVEPORT


# ===================================================================
# Port mode tests
# ===================================================================


class TestParsePortMode:
    """--port-mode flag tests."""

    def test_port_mode_single_default(self, monkeypatch):
        args = _parse_with_args(monkeypatch, [])
        assert args.port_mode == "single"

    def test_port_mode_single_explicit(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--port-mode", "single"])
        assert args.port_mode == "single"

    def test_port_mode_top(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--port-mode", "top"])
        assert args.port_mode == "top"

    def test_port_mode_all(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--port-mode", "all"])
        assert args.port_mode == "all"

    def test_port_mode_invalid_raises(self, monkeypatch):
        with pytest.raises(SystemExit):
            _parse_with_args(monkeypatch, ["--port-mode", "invalid"])


class TestParseTopPorts:
    """--top-ports flag tests."""

    def test_top_ports_default(self, monkeypatch):
        args = _parse_with_args(monkeypatch, [])
        assert args.top_ports == ""

    def test_top_ports_custom(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--top-ports", "80,443,8080"])
        assert args.top_ports == "80,443,8080"

    def test_top_ports_with_space(self, monkeypatch):
        args = _parse_with_args(monkeypatch, ["--top-ports", "80, 443, 8080"])
        assert args.top_ports == "80, 443, 8080"


class TestParsePortModeCombined:
    """Combined port mode and top-ports flags."""

    def test_port_mode_top_with_top_ports(self, monkeypatch):
        args = _parse_with_args(
            monkeypatch, ["--port-mode", "top", "--top-ports", "80,443"]
        )
        assert args.port_mode == "top"
        assert args.top_ports == "80,443"

    def test_port_mode_all_with_top_ports_ignored(self, monkeypatch):
        args = _parse_with_args(
            monkeypatch, ["--port-mode", "all", "--top-ports", "80"]
        )
        assert args.port_mode == "all"
        assert args.top_ports == "80"  # still stored, but not used when mode=all

    def test_all_flags_with_port_mode(self, monkeypatch):
        args = _parse_with_args(
            monkeypatch,
            [
                "-c",
                "80",
                "-s",
                "666",
                "-u",
                "-v",
                "-p",
                "--generate-config",
                "--port-mode",
                "top",
                "--top-ports",
                "80,443",
            ],
        )
        assert args.client == 80
        assert args.server == 666
        assert args.updater is True
        assert args.verbose is True
        assert args.proxy is True
        assert args.generate_config is True
        assert args.port_mode == "top"
        assert args.top_ports == "80,443"


# ===================================================================
# Additional edge-case tests
# ===================================================================
