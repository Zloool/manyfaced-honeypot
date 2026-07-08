"""Backwards-compatible alias for the Kubernetes handler.

The package's handlers/__init__.py imports ``KubernetesHandler`` from this
module. The canonical implementation lives in ``kubernetes_handler.py``;
this shim re-exports it so existing imports keep working.
"""

from manyfaced.handlers.kubernetes_handler import KubernetesHandler  # noqa: F401

__all__ = ['KubernetesHandler']
