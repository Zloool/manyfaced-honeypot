"""Tests for manyfaced.mfh lockfile helpers.

These run on POSIX (CI). On non-POSIX hosts fcntl is stubbed so the
file/open/unlink paths are still exercised.
"""

import types

import pytest

import manyfaced.common.config as config_mod
import manyfaced.mfh as mfh

pytest.importorskip('fcntl')  # lockfile tests are POSIX-only (fcntl)


def _patch_settings(monkeypatch, lockfile):
    # `settings` is a frozen dataclass, so replace the module-level reference
    # the lockfile helpers lazily import from.
    fake = types.SimpleNamespace(LOCKFILE=str(lockfile))
    monkeypatch.setattr(config_mod, 'settings', fake)
    return fake


def test_acquire_and_release_lockfile(tmp_path, monkeypatch):
    lockfile = tmp_path / 'mfh.lock'
    _patch_settings(monkeypatch, lockfile)

    mfh._acquire_lockfile()
    try:
        assert lockfile.exists()
        assert lockfile.read_text().strip().isdigit()
    finally:
        mfh._release_lockfile()

    assert not lockfile.exists()


def test_release_without_acquire_is_safe(tmp_path, monkeypatch):
    _patch_settings(monkeypatch, tmp_path / 'mfh2.lock')
    mfh._release_lockfile()  # no-op, must not raise


def test_acquire_creates_parent_dirs(tmp_path, monkeypatch):
    lockfile = tmp_path / 'nested' / 'dir' / 'mfh.lock'
    _patch_settings(monkeypatch, lockfile)
    mfh._acquire_lockfile()
    try:
        assert lockfile.exists()
    finally:
        mfh._release_lockfile()
