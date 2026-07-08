"""Backwards-compatible alias for the Kubernetes routes.

The package's routes/__init__.py imports ``ROUTES`` from this module. The
canonical route table lives in ``routes_kubernetes.py``; this shim re-exports
it so the existing import keeps working.
"""

from manyfaced.handlers.routes.routes_kubernetes import ROUTES  # noqa: F401

__all__ = ['ROUTES']
