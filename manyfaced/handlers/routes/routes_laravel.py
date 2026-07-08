"""Laravel (PHP framework) routes (issue #286).

Covers the real production probe paths observed against Laravel deployments:
  /laravel/.env  /laravel/.env.staging  /laravel/info.php
  /storage/logs/laravel.log  /laravel/.env
  /_ignition/execute-solution  /_ignition/  /_ignition
  /laravel/core/.env.production  /laravel/core/.env.staging
  /laravel/core/.env.local  /laravel/core/.env  /laravel-app/src/.env

More-specific paths are listed first so they win over the broad prefixes.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import LARAVEL_HTTP


def _laravel() -> type:
    from manyfaced.handlers.laravel_handler import LaravelHandler

    return LaravelHandler


ROUTES: list[Route] = [
    # ---- Laravel (issue #286) ------------------------------------------------
    # Ignition debug handler — exact endpoints first, then prefix catch-all.
    Route(PathExact('/_ignition/execute-solution'), _laravel(), LARAVEL_HTTP, 'laravel_ignition_execute'),
    Route(PathExact('/_ignition'), _laravel(), LARAVEL_HTTP, 'laravel_ignition_exact'),
    Route(PathPrefix('/_ignition/'), _laravel(), LARAVEL_HTTP, 'laravel_ignition_prefix'),
    # laravel/core/.env.* disclosure probes (more specific before /laravel/ prefix).
    Route(PathPrefix('/laravel/core/'), _laravel(), LARAVEL_HTTP, 'laravel_core_env'),
    # laravel-app/src/.env disclosure probe.
    Route(PathPrefix('/laravel-app/src/'), _laravel(), LARAVEL_HTTP, 'laravel_app_src_env'),
    # Generic /laravel/ prefix (covers /.env, /info.php, etc.).
    Route(PathPrefix('/laravel/'), _laravel(), LARAVEL_HTTP, 'laravel_prefix'),
    Route(PathExact('/laravel'), _laravel(), LARAVEL_HTTP, 'laravel_exact'),
    # Storage logs disclosure (e.g. /storage/logs/laravel.log).
    Route(PathPrefix('/storage/logs/'), _laravel(), LARAVEL_HTTP, 'laravel_storage_logs'),
    # vendor/laravel source disclosure probes.
    Route(PathPrefix('/vendor/laravel/'), _laravel(), LARAVEL_HTTP, 'laravel_vendor'),
]
