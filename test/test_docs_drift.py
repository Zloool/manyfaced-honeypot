"""Tests that check_docs_drift.py CI guard FAILS on injected drift.

These run the drift-check script as a subprocess against a minimal fixture
repo so we exercise the real script (it executes at import time, so it can't
be imported as a module). Mirrors the checks added for issue #147:
- reverse CLI-flag parity (README flag must exist in arguments.py)
- optional-dependency import reachability (phantom dep)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / '.github' / 'workflows' / 'scripts' / 'check_docs_drift.py'

GOOD_ARGS = (
    'import argparse\n'
    'def parse_args():\n'
    '    p = argparse.ArgumentParser()\n'
    "    p.add_argument('-c', dest='client')\n"
    "    p.add_argument('-s', dest='server')\n"
    "    p.add_argument('-v', '--verbose', action='store_true')\n"
    '    return p.parse_args()\n'
)

# A stub module that actually references the flags so Check 6 (argparse
# reachability) does not fire on the fixture.
STUB_MFH = (
    'import argparse\n'
    'from manyfaced.common.arguments import parse_args\n'
    'USAGE = "-c start client, -s start server, -v/--verbose verbose"\n'
    'def main():\n'
    '    args = parse_args()\n'
    '    print(args.client, args.server, args.verbose)\n'
)

GOOD_README = (
    '# Title\n\n'
    '| Flag | Default | Description |\n'
    '|------|---------|-------------|\n'
    '| `-c [PORT]` | disabled | Start CLIENT |\n'
    '| `-s [PORT]` | disabled | Start SERVER |\n'
    '| `-v` | false | Verbose |\n\n'
)

GOOD_PYPROJECT = '[project]\nname = "mfh"\n[project.optional-dependencies]\nhttp = ["requests"]\n'


def _write_fixture(tmp_path: Path, readme: str, args_py: str, pyproject: str) -> None:
    """Create a minimal repo fixture (README + arguments.py + pyproject + stub pkg)."""
    (tmp_path / 'README.md').write_text(readme)
    (tmp_path / 'manyfaced').mkdir(parents=True)
    (tmp_path / 'manyfaced' / '__init__.py').write_text('')
    (tmp_path / 'manyfaced' / 'common').mkdir(parents=True)
    (tmp_path / 'manyfaced' / 'common' / '__init__.py').write_text('')
    (tmp_path / 'manyfaced' / 'common' / 'arguments.py').write_text(args_py)
    (tmp_path / 'manyfaced' / 'common' / 'config.py').write_text(
        'class Config:\n    HONEYPORT = 8888\n    HIVEPORT = 9999\n'
    )
    (tmp_path / 'manyfaced' / 'mfh.py').write_text(STUB_MFH)
    (tmp_path / 'pyproject.toml').write_text(pyproject)
    (tmp_path / '.env.example').write_text('HONEYPORT=8888\n')
    # Check 1 (README directory tree) expects these paths to exist.
    (tmp_path / 'manyfaced' / 'server').mkdir(parents=True)
    (tmp_path / 'manyfaced' / 'server' / 'server.py').write_text('')
    (tmp_path / 'manyfaced' / 'client').mkdir(parents=True)
    (tmp_path / 'manyfaced' / 'client' / 'client.py').write_text('')
    (tmp_path / 'test').mkdir(parents=True)
    (tmp_path / 'test' / 'test_http_handler.py').write_text('')


def _run(tmp_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )


def test_clean_fixture_passes(tmp_path):
    _write_fixture(tmp_path, GOOD_README, GOOD_ARGS, '[project]\nname = "mfh"\n')
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_stale_readme_flag_fails(tmp_path):
    _write_fixture(tmp_path, GOOD_README, GOOD_ARGS, '[project]\nname="mfh"\n')
    readme = (
        '# Title\n\n'
        '| Flag | Default | Description |\n'
        '|------|---------|-------------|\n'
        '| `-c [PORT]` | disabled | Start CLIENT |\n'
        '| `-p` | false | Proxy mode |\n\n'
    )
    (tmp_path / 'README.md').write_text(readme)
    result = _run(tmp_path)
    assert result.returncode == 1
    assert '-p' in result.stdout


def test_phantom_optional_dep_fails(tmp_path):
    # 'requests' optional dep is never imported anywhere under manyfaced/
    _write_fixture(tmp_path, GOOD_README, GOOD_ARGS, GOOD_PYPROJECT)
    result = _run(tmp_path)
    assert result.returncode == 1
    assert 'requests' in result.stdout


def test_phantom_dep_resolved_when_imported(tmp_path):
    _write_fixture(tmp_path, GOOD_README, GOOD_ARGS, GOOD_PYPROJECT)
    # Add a real import of the optional dep under manyfaced/ -> should pass
    (tmp_path / 'manyfaced' / 'common' / 'http_client.py').write_text('import requests\n')
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
