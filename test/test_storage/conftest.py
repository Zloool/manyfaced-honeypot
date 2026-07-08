"""Shared fixtures for test_storage package."""

import sys
from unittest.mock import MagicMock

import pytest

import manyfaced.db.storage as storage_mod

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path
# ---------------------------------------------------------------------------
_project_root = __import__('os').path.abspath(
    __import__('os').path.join(__import__('os').path.dirname(__file__), '..', '..')
)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


@pytest.fixture
def mock_psycopg2(monkeypatch):
    """Return a MagicMock for psycopg2 and inject it into both sys.modules and
    the storage module (issue #243: psycopg2 may be genuinely importable now
    that the [postgres] extra is installed, so patching only sys.modules is not
    enough — the module-global reference must be replaced too).

    Singleton/config isolation across packages is handled by the root
    test/conftest.py autouse fixture.
    """
    mock = MagicMock()
    monkeypatch.setitem(sys.modules, 'psycopg2', mock)
    monkeypatch.setattr(storage_mod, 'psycopg2', mock)
    return mock
