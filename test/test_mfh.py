"""Tests for manyfaced.mfh entry point.

Covers:
- _acquire_lockfile / _release_lockfile
- run() with --generate-config
- run() auto-detect (no CLI args)
- run() with explicit --client / --server
- run() with both --client and --server
"""

import fcntl
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock optional dependencies before importing manyfaced modules
sys.modules["geoip"] = MagicMock()
sys.modules["geoip.geolite2"] = MagicMock()
sys.modules["GeoIP"] = MagicMock()


# ---------------------------------------------------------------------------
# Frozen-settings fixture helper
# ---------------------------------------------------------------------------


def _make_mock_settings(**overrides):
    """Return a frozen-like settings object with the given overrides.

    The real ``settings`` is a frozen dataclass, so we use a plain class
    that does not allow attribute assignment.
    """
    defaults = {
        "LOG_FILE": "/dev/null",
        "HONEYPORT": 8080,
        "HIVEPORT": 9090,
        "HONEY_PORT_MODE": "single",
        "HONEY_TOP_PORTS": "",
    }
    defaults.update(overrides)

    class MockSettings:
        __slots__ = defaults.keys()

        def __setattr__(self, name, value):
            raise AttributeError(f"cannot assign to '{name}' (frozen settings)")

        def __getattr__(self, name):
            raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")

    obj = MockSettings()
    for k, v in defaults.items():
        object.__setattr__(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# Lockfile tests
# ---------------------------------------------------------------------------


class TestLockfile(unittest.TestCase):
    """Test lockfile acquisition and release."""

    def test_acquire_lockfile(self):
        """Test that _acquire_lockfile creates a lockfile and acquires the lock."""
        from manyfaced.mfh import _acquire_lockfile, _release_lockfile

        with tempfile.NamedTemporaryFile(suffix=".lock", delete=False) as tmp:
            lockfile_path = tmp.name

        try:
            with patch("manyfaced.mfh.settings.LOCKFILE", lockfile_path):
                with patch("manyfaced.mfh.os.makedirs"):
                    _acquire_lockfile()
                    from manyfaced.mfh import _lock_fd

                    self.assertIsNotNone(_lock_fd)
                    tmp_content = open(lockfile_path).read()
                    self.assertEqual(int(tmp_content), os.getpid())
        finally:
            try:
                with patch("manyfaced.mfh.settings.LOCKFILE", lockfile_path):
                    _release_lockfile()
            except Exception:
                pass
            if os.path.exists(lockfile_path):
                os.unlink(lockfile_path)

    def test_acquire_lockfile_blocks_when_held(self):
        """Test that _acquire_lockfile exits when another instance holds the lock."""
        from manyfaced.mfh import _acquire_lockfile, _release_lockfile

        with tempfile.NamedTemporaryFile(suffix=".lock", delete=False) as tmp:
            lockfile_path = tmp.name

        try:
            fd = open(lockfile_path, "w")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            try:
                with patch("manyfaced.mfh.LOCKFILE", lockfile_path):
                    with patch("manyfaced.mfh.os.makedirs"):
                        with self.assertRaises(SystemExit):
                            _acquire_lockfile()
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
        finally:
            if os.path.exists(lockfile_path):
                os.unlink(lockfile_path)

    def test_release_lockfile(self):
        """Test that _release_lockfile releases the lock and cleans up."""
        from manyfaced.mfh import _acquire_lockfile, _release_lockfile

        with tempfile.NamedTemporaryFile(suffix=".lock", delete=False) as tmp:
            lockfile_path = tmp.name

        try:
            with patch("manyfaced.mfh.LOCKFILE", lockfile_path):
                with patch("manyfaced.mfh.os.makedirs"):
                    _acquire_lockfile()
                    _release_lockfile()
                    from manyfaced.mfh import _lock_fd

                    self.assertIsNone(_lock_fd)
        finally:
            if os.path.exists(lockfile_path):
                os.unlink(lockfile_path)


# ---------------------------------------------------------------------------
# run() tests
# ---------------------------------------------------------------------------


class TestRunGenerateConfig(unittest.TestCase):
    """Test run() with --generate-config flag."""

    def test_generate_config_exits(self):
        """Test that --generate-config creates a config file and exits."""
        mock_cfg = MagicMock()
        mock_cfg.generate_config_file.return_value = "/tmp/test_config.toml"

        with patch("manyfaced.mfh.Config.load", return_value=mock_cfg):
            with patch("manyfaced.mfh._acquire_lockfile"):
                with patch("manyfaced.mfh.setup_logging"):
                    with patch("manyfaced.mfh.os.path.isfile", return_value=True):
                        with patch("manyfaced.mfh.settings", _make_mock_settings()):
                            with patch(
                                "manyfaced.common.arguments.parse"
                            ) as mock_parse:
                                mock_args = MagicMock()
                                mock_args.client = None
                                mock_args.server = None
                                mock_args.generate_config = True
                                mock_args.port_mode = "single"
                                mock_args.top_ports = None
                                mock_parse.return_value = mock_args

                                from manyfaced.mfh import run

                                run()

        mock_cfg.generate_config_file.assert_called_once()


class TestRunAutoDetect(unittest.TestCase):
    """Test run() with no CLI args (auto-detect both client and server)."""

    def test_run_auto_detect_starts_both(self):
        """Test that no CLI args starts both client and server processes."""
        with patch("manyfaced.mfh._acquire_lockfile"):
            with patch("manyfaced.mfh.setup_logging"):
                with patch("manyfaced.mfh.os.path.isfile", return_value=True):
                    with patch("manyfaced.mfh.settings", _make_mock_settings()):
                        with patch("manyfaced.common.arguments.parse") as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = None
                            mock_args.server = None
                            mock_args.generate_config = False
                            mock_args.port_mode = "single"
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch("manyfaced.mfh.Process") as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch("manyfaced.mfh.Event") as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            self.assertEqual(mock_process_cls.call_count, 2)


class TestRunExplicitArgs(unittest.TestCase):
    """Test run() with explicit --client or --server args."""

    def test_run_only_client(self):
        """Test that --client-only starts only the client process."""
        with patch("manyfaced.mfh._acquire_lockfile"):
            with patch("manyfaced.mfh.setup_logging"):
                with patch("manyfaced.mfh.os.path.isfile", return_value=True):
                    with patch("manyfaced.mfh.settings", _make_mock_settings()):
                        with patch("manyfaced.common.arguments.parse") as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = 8080
                            mock_args.server = None
                            mock_args.generate_config = False
                            mock_args.port_mode = "single"
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch("manyfaced.mfh.Process") as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch("manyfaced.mfh.Event") as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            mock_process_cls.assert_called_once()
                            call_args = mock_process_cls.call_args
                            self.assertEqual(call_args.kwargs.get("name"), "client")

    def test_run_only_server(self):
        """Test that --server-only starts only the server process."""
        with patch("manyfaced.mfh._acquire_lockfile"):
            with patch("manyfaced.mfh.setup_logging"):
                with patch("manyfaced.mfh.os.path.isfile", return_value=True):
                    with patch("manyfaced.mfh.settings", _make_mock_settings()):
                        with patch("manyfaced.common.arguments.parse") as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = None
                            mock_args.server = 9090
                            mock_args.generate_config = False
                            mock_args.port_mode = "single"
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch("manyfaced.mfh.Process") as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch("manyfaced.mfh.Event") as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            mock_process_cls.assert_called_once()
                            call_args = mock_process_cls.call_args
                            self.assertEqual(call_args.kwargs.get("name"), "server")


class TestRunPortModeFromConfig(unittest.TestCase):
    """Test that auto-detect applies port_mode and top_ports from settings."""

    def test_run_applies_port_mode_from_settings(self):
        """Test that port_mode from settings is applied when auto-detecting."""
        with patch("manyfaced.mfh._acquire_lockfile"):
            with patch("manyfaced.mfh.setup_logging"):
                with patch("manyfaced.mfh.os.path.isfile", return_value=True):
                    with patch(
                        "manyfaced.mfh.settings",
                        _make_mock_settings(
                            HONEYPORT=8080,
                            HIVEPORT=9090,
                            HONEY_PORT_MODE="top",
                            HONEY_TOP_PORTS="80,443",
                        ),
                    ):
                        with patch("manyfaced.common.arguments.parse") as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = None
                            mock_args.server = None
                            mock_args.generate_config = False
                            mock_args.port_mode = "single"
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch("manyfaced.mfh.Process") as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch("manyfaced.mfh.Event") as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            self.assertEqual(mock_args.port_mode, "top")
                            self.assertEqual(mock_args.top_ports, "80,443")


if __name__ == "__main__":
    unittest.main()
