"""EnvDisc (Env / config disclosure) routes.

Mirrors the bitrix routes layout: a lazy handler getter plus an ordered
ROUTES list using PathExact / PathPrefix matchers from the router.  These
cover the production probe paths scanners hit when hunting for leaked
environment / configuration files (issue #272).

URL-encoded variants are handled by the handler's defensive decode of the
path (e.g. ``/env/%2eenv`` -> ``/env/.env``).
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import ENV_DISC_HTTP


def _env_disc() -> type:
    from manyfaced.handlers.env_disc_handler import EnvDiscHandler

    return EnvDiscHandler


ROUTES: list[Route] = [
    # Fake .env disclosure endpoints
    Route(PathExact('/.env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_dot_env'),
    Route(PathExact('/env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_env'),
    Route(PathExact('/config.env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_config_env'),
    Route(PathExact('/.env.example'), _env_disc(), ENV_DISC_HTTP, 'env_disc_env_example'),
    Route(PathExact('/configuration'), _env_disc(), ENV_DISC_HTTP, 'env_disc_configuration'),
    # Prefix probes: /env/<anything> (incl. /env/.env, encoded as /env/%2eenv)
    Route(PathPrefix('/env/'), _env_disc(), ENV_DISC_HTTP, 'env_disc_env_prefix'),
    # Broad API config probes
    Route(PathPrefix('/api/'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_prefix'),
]
