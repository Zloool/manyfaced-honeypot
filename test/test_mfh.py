"""Tests for manyfaced.mfh entry point.

Covers:
- _acquire_lockfile / _release_lockfile
- run() with --generate-config
- run() auto-detect (no CLI args)
- run() with explicit --client / --server
- run() with both --client and --server
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock optional dependencies before importing manyfaced modules
sys.modules['geoip'] = MagicMock()
from manyfaced.common.config import settings

sys.modules['geoip.geolite2'] = MagicMock()
sys.modules['GeoIP'] = MagicMock()


# ---------------------------------------------------------------------------
# Frozen-settings fixture helper
# ---------------------------------------------------------------------------


def _make_mock_settings(**overrides):
    """Return a frozen-like settings object with the given overrides.

    The real ``settings`` is a frozen dataclass, so we use a plain class
    that does not allow attribute assignment.
    """
    defaults = {
        'LOG_FILE': '/dev/null',
        'HONEYPORT': 8080,
        'HIVEPORT': 9090,
        'HONEY_PORT_MODE': 'single',
        'HONEY_TOP_PORTS': '',
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
        pytest.importorskip('fcntl')  # lockfile enforcement is POSIX-only
        from manyfaced.mfh import _acquire_lockfile, _release_lockfile

        with tempfile.NamedTemporaryFile(suffix='.lock', delete=False) as tmp:
            lockfile_path = tmp.name

        try:
            # Use object.__setattr__ to bypass frozen dataclass
            object.__setattr__(settings, 'LOCKFILE', lockfile_path)
            with patch('manyfaced.mfh.os.makedirs'):
                _acquire_lockfile()
                from manyfaced.mfh import _lock_fd

                self.assertIsNotNone(_lock_fd)
                with open(lockfile_path) as f:
                    tmp_content = f.read()
                self.assertEqual(int(tmp_content), os.getpid())
        finally:
            try:
                object.__setattr__(settings, 'LOCKFILE', '/run/manyfaced/lockfile')
                _release_lockfile()
            except Exception:
                pass
            if os.path.exists(lockfile_path):
                os.unlink(lockfile_path)

    def test_acquire_lockfile_blocks_when_held(self):
        """Test that _acquire_lockfile exits when another instance holds the lock."""
        fcntl = pytest.importorskip('fcntl')
        from manyfaced.mfh import _acquire_lockfile, _release_lockfile

        with tempfile.NamedTemporaryFile(suffix='.lock', delete=False) as tmp:
            lockfile_path = tmp.name

        try:
            fd = open(lockfile_path, 'w')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            try:
                object.__setattr__(settings, 'LOCKFILE', lockfile_path)
                with patch('manyfaced.mfh.os.makedirs'):
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

        with tempfile.NamedTemporaryFile(suffix='.lock', delete=False) as tmp:
            lockfile_path = tmp.name

        try:
            object.__setattr__(settings, 'LOCKFILE', lockfile_path)
            with patch('manyfaced.mfh.os.makedirs'):
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
        mock_cfg.generate_config_file.return_value = '/tmp/test_config.toml'

        with patch('manyfaced.mfh.Config.load', return_value=mock_cfg):
            with patch('manyfaced.mfh._acquire_lockfile'):
                with patch('manyfaced.mfh.setup_logging'):
                    with patch('manyfaced.mfh.os.path.isfile', return_value=True):
                        with patch('manyfaced.mfh.settings', _make_mock_settings()):
                            with patch('manyfaced.common.arguments.parse') as mock_parse:
                                mock_args = MagicMock()
                                mock_args.client = None
                                mock_args.server = None
                                mock_args.generate_config = True
                                mock_args.port_mode = 'single'
                                mock_args.top_ports = None
                                mock_parse.return_value = mock_args

                                from manyfaced.mfh import run

                                run()

        mock_cfg.generate_config_file.assert_called_once()


class TestRunAutoDetect(unittest.TestCase):
    """Test run() with no CLI args (auto-detect both client and server)."""

    def test_run_auto_detect_starts_both(self):
        """Test that no CLI args starts both client and server processes."""
        with patch('manyfaced.mfh._acquire_lockfile'):
            with patch('manyfaced.mfh.setup_logging'):
                with patch('manyfaced.mfh.os.path.isfile', return_value=True):
                    with patch('manyfaced.mfh.settings', _make_mock_settings()):
                        with patch('manyfaced.common.arguments.parse') as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = None
                            mock_args.server = None
                            mock_args.generate_config = False
                            mock_args.port_mode = 'single'
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch('manyfaced.mfh.Process') as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch('manyfaced.mfh.Event') as mock_event_cls:
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
        with patch('manyfaced.mfh._acquire_lockfile'):
            with patch('manyfaced.mfh.setup_logging'):
                with patch('manyfaced.mfh.os.path.isfile', return_value=True):
                    with patch('manyfaced.mfh.settings', _make_mock_settings()):
                        with patch('manyfaced.common.arguments.parse') as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = 8080
                            mock_args.server = None
                            mock_args.generate_config = False
                            mock_args.port_mode = 'single'
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch('manyfaced.mfh.Process') as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch('manyfaced.mfh.Event') as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            mock_process_cls.assert_called_once()
                            call_args = mock_process_cls.call_args
                            self.assertEqual(call_args.kwargs.get('name'), 'client')

    def test_run_only_server(self):
        """Test that --server-only starts only the server process."""
        with patch('manyfaced.mfh._acquire_lockfile'):
            with patch('manyfaced.mfh.setup_logging'):
                with patch('manyfaced.mfh.os.path.isfile', return_value=True):
                    with patch('manyfaced.mfh.settings', _make_mock_settings()):
                        with patch('manyfaced.common.arguments.parse') as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = None
                            mock_args.server = 9090
                            mock_args.generate_config = False
                            mock_args.port_mode = 'single'
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch('manyfaced.mfh.Process') as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch('manyfaced.mfh.Event') as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            mock_process_cls.assert_called_once()
                            call_args = mock_process_cls.call_args
                            self.assertEqual(call_args.kwargs.get('name'), 'server')


class TestRunPortModeFromConfig(unittest.TestCase):
    """Test that auto-detect applies port_mode and top_ports from settings."""

    def test_run_applies_port_mode_from_settings(self):
        """Test that port_mode from settings is applied when auto-detecting."""
        with patch('manyfaced.mfh._acquire_lockfile'):
            with patch('manyfaced.mfh.setup_logging'):
                with patch('manyfaced.mfh.os.path.isfile', return_value=True):
                    with patch(
                        'manyfaced.mfh.settings',
                        _make_mock_settings(
                            HONEYPORT=8080,
                            HIVEPORT=9090,
                            HONEY_PORT_MODE='top',
                            HONEY_TOP_PORTS='80,443',
                        ),
                    ):
                        with patch('manyfaced.common.arguments.parse') as mock_parse:
                            mock_args = MagicMock()
                            mock_args.client = None
                            mock_args.server = None
                            mock_args.generate_config = False
                            mock_args.port_mode = 'single'
                            mock_args.top_ports = None
                            mock_parse.return_value = mock_args

                            with patch('manyfaced.mfh.Process') as mock_process_cls:
                                mock_process_cls.return_value = MagicMock()

                                with patch('manyfaced.mfh.Event') as mock_event_cls:
                                    mock_event = MagicMock()
                                    mock_event.is_set.return_value = True
                                    mock_event_cls.return_value = mock_event

                                    from manyfaced.mfh import run

                                    run()

                            self.assertEqual(mock_args.port_mode, 'top')
                            self.assertEqual(mock_args.top_ports, '80,443')


class TestRunChildSupervision(unittest.TestCase):
    """Test the supervision loop: backoff + crash-loop guard (#180)."""

    def _run_with_dead_child(
        self, kill_parent_after_n_restarts, window_constants, event_toggles_true_at=0
    ):
        """Drive run() with a child that is never alive.

        Args:
            kill_parent_after_n_restarts: if >0, sys.exit is allowed to fire
                after this many restarts (crash-loop guard). Set 0 to assert
                sys.exit is never called.
            window_constants: dict overriding the module-level backoff/cap
                constants so the loop can be exercised quickly.
            event_toggles_true_at: after this many loop iterations the
                update_event flips to set(), ending the loop cleanly (used for
                the negative case where the guard must NOT fire).
        """
        import manyfaced.mfh as mfh

        # Fake clock: advance by a large fixed step on every time.time() call so
        # the exponential backoff cooldown always elapses immediately. This lets
        # the crash-loop guard be exercised with REAL production backoff
        # constants (which would otherwise make the loop wait ~30s between
        # restarts and time out) without slowing the test (#222).
        fake_clock = {'t': 0.0}

        def _fake_time():
            fake_clock['t'] += 31.0  # > _BACKOFF_MAX, so cooldown always passes
            return fake_clock['t']

        with (
            patch('manyfaced.mfh._acquire_lockfile'),
            patch('manyfaced.mfh.setup_logging'),
            patch('manyfaced.mfh.os.path.isfile', return_value=True),
            patch('manyfaced.mfh.settings', _make_mock_settings()),
            patch('manyfaced.common.arguments.parse') as mock_parse,
            patch('manyfaced.mfh.Process') as mock_process_cls,
            patch('manyfaced.mfh.Event') as mock_event_cls,
            patch('manyfaced.mfh.time.sleep'),
            patch('manyfaced.mfh.time.time', _fake_time),
            patch.object(mfh, '_BACKOFF_BASE', window_constants['base']),
            patch.object(mfh, '_BACKOFF_MAX', window_constants['max']),
            patch.object(mfh, '_MAX_RESTARTS_PER_WINDOW', window_constants['max_restarts']),
            patch.object(mfh, '_RESTART_WINDOW_SEC', window_constants['window']),
        ):
            mock_args = MagicMock()
            mock_args.client = 8080
            mock_args.server = 9090
            mock_args.generate_config = False
            mock_args.port_mode = 'single'
            mock_args.top_ports = None
            mock_parse.return_value = mock_args

            # Child process is never alive -> must be (re)started.
            dead_proc = MagicMock()
            dead_proc.is_alive.return_value = False
            mock_process_cls.return_value = dead_proc

            event = MagicMock()
            state = {'i': 0}

            def _is_set():
                state['i'] += 1
                return event_toggles_true_at > 0 and state['i'] > event_toggles_true_at

            event.is_set.side_effect = _is_set
            mock_event_cls.return_value = event

            from manyfaced.mfh import run

            run()
            return mock_process_cls.call_count

    def test_crash_loop_guard_exits_parent_after_cap(self):
        """A continuously-crashing child must trip the cap and sys.exit(1) even
        with the REAL production constants (backoff saturating at 30s), which is
        exactly the unreachable case from #222 — the old sliding-window guard
        could never accumulate 10 timestamps in 60s when restarts are 30s apart.
        """
        import manyfaced.mfh as mfh

        # Real production constants: base=1.0, max=30.0, cap=10. With saturated
        # 30s backoff the windowed count could never reach 10, so this only
        # passes because the guard now counts cumulative attempts.
        constants = {
            'base': 1.0,
            'max': 30.0,
            'max_restarts': mfh._MAX_RESTARTS_PER_WINDOW,
            'window': mfh._RESTART_WINDOW_SEC,
        }
        with patch.object(mfh, 'sys') as mock_sys:
            mock_sys.exit.side_effect = SystemExit(1)
            with self.assertRaises(SystemExit) as cm:
                self._run_with_dead_child(
                    kill_parent_after_n_restarts=mfh._MAX_RESTARTS_PER_WINDOW,
                    window_constants=constants,
                )
            self.assertEqual(cm.exception.code, 1)
            mock_sys.exit.assert_called_once_with(1)

    def test_healthy_child_resets_restart_bookkeeping(self):
        """A child that stays alive is never restarted (no crash-loop)."""
        import manyfaced.mfh as mfh

        with (
            patch('manyfaced.mfh._acquire_lockfile'),
            patch('manyfaced.mfh.setup_logging'),
            patch('manyfaced.mfh.os.path.isfile', return_value=True),
            patch('manyfaced.mfh.settings', _make_mock_settings()),
            patch('manyfaced.common.arguments.parse') as mock_parse,
            patch('manyfaced.mfh.Process') as mock_process_cls,
            patch('manyfaced.mfh.Event') as mock_event_cls,
            patch('manyfaced.mfh.time.sleep'),
            patch.object(mfh, 'sys') as mock_sys,
        ):
            mock_args = MagicMock()
            mock_args.client = 8080
            mock_args.server = 9090
            mock_args.generate_config = False
            mock_args.port_mode = 'single'
            mock_args.top_ports = None
            mock_parse.return_value = mock_args

            # Child is alive -> supervision must NOT restart it.
            alive_proc = MagicMock()
            alive_proc.is_alive.return_value = True
            mock_process_cls.return_value = alive_proc

            event = MagicMock()
            event.is_set.return_value = True  # end loop immediately
            mock_event_cls.return_value = event

            from manyfaced.mfh import run

            run()
            # Both started once at launch, never restarted.
            self.assertEqual(mock_process_cls.call_count, 2)
            mock_sys.exit.assert_not_called()


if __name__ == '__main__':
    unittest.main()
