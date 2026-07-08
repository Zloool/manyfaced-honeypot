"""Jupyter routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import JUPYTER_HTTP


def _jupyter() -> type:
    from manyfaced.handlers.jupyter_handler import JupyterHandler

    return JupyterHandler


ROUTES: list[Route] = [
    # ---- Jupyter (issue #296) ----
    Route(PathExact('/jupyter'), _jupyter(), JUPYTER_HTTP, 'jupyter_0'),
    Route(PathExact('/lab'), _jupyter(), JUPYTER_HTTP, 'jupyter_1'),
    Route(PathExact('/notebooks'), _jupyter(), JUPYTER_HTTP, 'jupyter_2'),
    Route(PathExact('/tree'), _jupyter(), JUPYTER_HTTP, 'jupyter_3'),
]
