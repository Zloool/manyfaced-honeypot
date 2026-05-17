"""Shared fixtures for handler tests."""

import os
import sys

# Ensure project root is in path (redundant with parent conftest, but safe)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
