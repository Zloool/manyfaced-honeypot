"""Kubernetes routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import KUBERNETES_HTTP


def _k8s() -> type:
    from manyfaced.handlers.k8s_handler import KubernetesHandler

    return KubernetesHandler


ROUTES: list[Route] = [
    # ---- Kubernetes (issue #274) ----
    Route(PathExact('/api'), _k8s(), KUBERNETES_HTTP, 'k8s_0'),
    Route(PathExact('/apis'), _k8s(), KUBERNETES_HTTP, 'k8s_1'),
    Route(PathExact('/healthz'), _k8s(), KUBERNETES_HTTP, 'k8s_2'),
    Route(PathExact('/readyz'), _k8s(), KUBERNETES_HTTP, 'k8s_3'),
    Route(PathExact('/metrics'), _k8s(), KUBERNETES_HTTP, 'k8s_4'),
    Route(PathExact('/version'), _k8s(), KUBERNETES_HTTP, 'k8s_5'),
]
