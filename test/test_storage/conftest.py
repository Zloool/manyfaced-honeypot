"""Shared fixtures for test_storage package."""

import sys
from unittest.mock import MagicMock

import pytest


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
    """Return a MagicMock for psycopg2 and inject it into sys.modules."""
    mock = MagicMock()
    monkeypatch.setitem(sys.modules, 'psycopg2', mock)
    return mock
