"""Jupyter Notebook routes (issue #288)."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import JUPYTER_HTTP


def _jupyter() -> type:
    from manyfaced.handlers.jupyter_handler import JupyterHandler

    return JupyterHandler


ROUTES: list[Route] = [
    # ---- Jupyter (issue #288) ----
    Route(PathExact('/jupyter'), _jupyter(), JUPYTER_HTTP, 'jupyter_jupyter'),
    Route(PathExact('/login'), _jupyter(), JUPYTER_HTTP, 'jupyter_login'),
    Route(PathExact('/lab'), _jupyter(), JUPYTER_HTTP, 'jupyter_lab'),
    Route(PathExact('/tree'), _jupyter(), JUPYTER_HTTP, 'jupyter_tree'),
    Route(PathExact('/api/contents'), _jupyter(), JUPYTER_HTTP, 'jupyter_api_contents'),
    Route(PathPrefix('/api/'), _jupyter(), JUPYTER_HTTP, 'jupyter_api'),
    Route(PathPrefix('/jupyter/'), _jupyter(), JUPYTER_HTTP, 'jupyter_slash'),
    Route(PathPrefix('/notebook'), _jupyter(), JUPYTER_HTTP, 'jupyter_notebook'),
]
