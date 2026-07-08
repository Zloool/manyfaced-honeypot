"""Kubernetes (kube-apiserver / Dashboard) routes.

Mirrors the production probe paths that Kubernetes-oriented scanners hit.
Order matters: exact paths are listed before the catch-all prefixes so that
/healthz, /readyz and /dashboard are matched precisely rather than by prefix.

Note: probe paths arrive percent-encoded (e.g. /kubernetes/%2eenv). The router
matches on the raw, lower-cased path, and the handler decodes %2e -> '.' and
%2f -> '/' before routing. The PathPrefix('/kubernetes/') entry therefore also
catches the decoded '/kubernetes/.env' variant.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import KUBERNETES_HTTP


def _kubernetes() -> type:
    from manyfaced.handlers.kubernetes_handler import KubernetesHandler

    return KubernetesHandler


ROUTES: list[Route] = [
    # ---- Kubernetes (issue #274) -----------------------------------------
    Route(PathExact('/api'), _kubernetes(), KUBERNETES_HTTP, 'k8s_api'),
    Route(PathExact('/api/v1'), _kubernetes(), KUBERNETES_HTTP, 'k8s_api_v1'),
    Route(
        PathExact('/api/v1/namespaces'),
        _kubernetes(),
        KUBERNETES_HTTP,
        'k8s_api_v1_namespaces',
    ),
    Route(PathExact('/healthz'), _kubernetes(), KUBERNETES_HTTP, 'k8s_healthz'),
    Route(PathExact('/readyz'), _kubernetes(), KUBERNETES_HTTP, 'k8s_readyz'),
    Route(PathExact('/apis'), _kubernetes(), KUBERNETES_HTTP, 'k8s_apis'),
    Route(
        PathExact('/dashboard'),
        _kubernetes(),
        KUBERNETES_HTTP,
        'k8s_dashboard',
    ),
    # Percent-encoded dashboard .env disclosure probe: /kubernetes/%2eenv
    Route(
        PathPrefix('/kubernetes/'),
        _kubernetes(),
        KUBERNETES_HTTP,
        'k8s_dashboard_env',
    ),
    Route(PathPrefix('/api/'), _kubernetes(), KUBERNETES_HTTP, 'k8s_api_prefix'),
    Route(PathPrefix('/apis/'), _kubernetes(), KUBERNETES_HTTP, 'k8s_apis_prefix'),
]
