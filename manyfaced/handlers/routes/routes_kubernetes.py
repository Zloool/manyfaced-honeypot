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
    # Narrow prefix routes so *arbitrary* nested kube-apiserver paths
    # (/api/v1/namespaces/<ns>/secrets, /api/v1/targets, /apis/apps/v1/...)
    # classify as KUBERNETES_HTTP instead of falling through to the generic
    # Next.js /api/ prefix (issue #592). These are intentionally NARROW
    # (only /api/v1/ and /apis/) — they do NOT re-introduce the old greedy
    # /api/ shadowing from #453. Langflow's specific /api/v1/run|flows|
    # validate|upload exact routes are ordered BEFORE this table (in
    # routes/__init__.py) so they keep their own face.
    Route(PathPrefix('/api/v1/'), _kubernetes(), KUBERNETES_HTTP, 'k8s_api_v1_prefix'),
    Route(PathPrefix('/apis/'), _kubernetes(), KUBERNETES_HTTP, 'k8s_apis_prefix'),
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
    # NOTE: the previous greedy `PathPrefix('/api/')` and `PathPrefix('/apis/')`
    # routes shadowed every face nested under /api/ — Next.js server-action RCE
    # (/api/route), PHPUnit eval-stdin RCE (/api/vendor/phpunit/...), Grafana
    # (/api/datasources), RabbitMQ, Prometheus, and env-disclosure (/api/.env).
    # kube-apiserver only ever answers its own real endpoints, so we keep the
    # explicit /api, /api/v1, /apis exact routes above and drop the catch-all
    # prefixes (issue #453).  Non-kube /api/* now falls through to the
    # dedicated faces, and finally to the realistic 404 monster page.
]
