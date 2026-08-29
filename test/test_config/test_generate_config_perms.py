"""Regression tests for generated config.toml permission hardening (issue #410).

The generated config.toml is now secret-free (secrets are sourced from HONEY_*
env vars; see CodeQL #174 / dashboard-secret exclusion issue #659), but it is
still chmod'd to 0o600 as defense-in-depth so any material written here is not
world-readable, and the freshly-created parent dir to 0o700. These assertions
are skipped on non-POSIX (Windows) where chmod is a no-op / unsupported, so the
suite stays green on both this dev host and Linux CI.
"""

import os
import stat
from pathlib import Path

import pytest

from .conftest import Config

# Only POSIX enforces the 0o600 / 0o700 modes we assert on. Windows does not
# support Unix permission bits, so skip the strict assertions there (issue #410).
POSIX = os.name == 'posix'


def _stat_mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class TestGenerateConfigPerms:
    """generate_config_file() must write a secret-bearing, non-world-readable file."""

    def test_generated_config_file_not_world_readable(self, tmp_path):
        """config.toml is chmod'd 0o600 (no group/other access) on POSIX."""
        cfg_path = tmp_path / 'nested' / 'config.toml'
        Config.load().generate_config_file(path=cfg_path)

        assert cfg_path.is_file()
        assert (cfg_path.read_text(encoding='utf-8')).strip()

        if not POSIX:
            pytest.skip('chmod is a no-op on non-POSIX platforms (issue #410)')

        mode = _stat_mode(cfg_path)
        assert mode == 0o600, f'expected 0o600, got {oct(mode)}'
        # Defense-in-depth: explicitly assert group/other cannot read.
        assert not (mode & (stat.S_IRGRP | stat.S_IROTH))

    def test_parent_dir_restricted_on_fresh_creation(self, tmp_path):
        """The freshly-created parent directory is created with mode 0o700."""
        cfg_path = tmp_path / 'fresh' / 'sub' / 'config.toml'
        parent = cfg_path.parent
        # Guarantee the dir does not yet exist so mkdir applies the mode.
        assert not parent.exists()

        Config.load().generate_config_file(path=cfg_path)

        assert parent.is_dir()

        if not POSIX:
            pytest.skip('chmod is a no-op on non-POSIX platforms (issue #410)')

        # mode only applies when the directory is actually created; verify it.
        mode = _stat_mode(parent)
        assert mode == 0o700, f'expected 0o700, got {oct(mode)}'
        assert not (
            mode
            & (
                stat.S_IRGRP
                | stat.S_IWGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IWOTH
                | stat.S_IXOTH
            )
        )
