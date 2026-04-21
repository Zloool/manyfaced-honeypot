"""Tests for manyfaced.common.update (trigger, pull)."""

import threading
from unittest.mock import patch

from manyfaced.common.update import pull, trigger


# ---------------------------------------------------------------------------
# trigger tests
# ---------------------------------------------------------------------------


class TestTrigger:
    """Tests for trigger()."""

    def test_sets_event_after_short_sleep(self):
        """trigger sets the event after the sleep period."""
        event = threading.Event()
        # Patch sleep to 0.1 seconds instead of 3600
        with patch("manyfaced.common.update.time.sleep", return_value=None):
            trigger(event)
        assert event.is_set()

    def test_sets_event_in_thread(self):
        """trigger works when run in a separate thread."""
        event = threading.Event()
        with patch("manyfaced.common.update.time.sleep", return_value=None):
            thread = threading.Thread(target=trigger, args=(event,))
            thread.start()
            thread.join(timeout=2)
        assert event.is_set()

    def test_catches_keyboard_interrupt(self):
        """trigger catches KeyboardInterrupt and calls sys.exit."""
        event = threading.Event()

        def raise_keyboard_interrupt(*args, **kwargs):
            raise KeyboardInterrupt()

        with patch("manyfaced.common.update.time.sleep", side_effect=raise_keyboard_interrupt):
            with patch("manyfaced.common.update.sys.exit") as mock_exit:
                trigger(event)
                mock_exit.assert_called_once_with()

    def test_event_not_set_before_trigger(self):
        """The event is not set before trigger is called."""
        event = threading.Event()
        assert not event.is_set()


# ---------------------------------------------------------------------------
# pull tests
# ---------------------------------------------------------------------------


class TestPull:
    """Tests for pull()."""

    def test_calls_git_pull(self):
        """pull calls subprocess.call with git pull arguments."""
        with patch("manyfaced.common.update.subprocess.call") as mock_call:
            pull("https://github.com/example/repo.git", "main")
            # Check that subprocess.call was called twice (git pull + pip install)
            assert mock_call.call_count == 2
            # First call should be git pull
            git_call = mock_call.call_args_list[0]
            assert git_call[0][0] == ("git", "pull", "https://github.com/example/repo.git", "main")

    def test_calls_pip_install(self):
        """pull calls subprocess.call with pip install arguments."""
        with patch("manyfaced.common.update.subprocess.call") as mock_call:
            pull("https://github.com/example/repo.git", "main")
            # Second call should be pip install
            pip_call = mock_call.call_args_list[1]
            assert pip_call[0][0] == ("pip", "install", "-r", "requirements.txt")

    def test_pull_with_different_repo_and_branch(self):
        """pull uses the provided repo and branch arguments."""
        with patch("manyfaced.common.update.subprocess.call") as mock_call:
            pull("https://github.com/other/thing.git", "develop")
            git_call = mock_call.call_args_list[0]
            assert git_call[0][0] == (
                "git",
                "pull",
                "https://github.com/other/thing.git",
                "develop",
            )

    def test_pull_calls_subprocess_call_twice(self):
        """pull makes exactly two subprocess.call invocations."""
        with patch("manyfaced.common.update.subprocess.call") as mock_call:
            pull("https://github.com/example/repo.git", "main")
            assert mock_call.call_count == 2
