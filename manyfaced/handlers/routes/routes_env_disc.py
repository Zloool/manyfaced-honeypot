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
    # Fake .env disclosure endpoints. NOTE: the bare PathExact('/.env') route is
    # intentionally NOT defined here — ConfigDisclosure (which appears later in
    # the route table, after WebDAV) owns the bare /.env probe so it is recorded
    # with CONFIG_DISCLOSURE_HTTP (issue #508). EnvDisc keeps its own nested /
    # admin / /api secret sub-paths below.
    Route(PathExact('/env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_env'),
    Route(PathExact('/config.env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_config_env'),
    Route(PathExact('/.env.example'), _env_disc(), ENV_DISC_HTTP, 'env_disc_env_example'),
    Route(PathExact('/configuration'), _env_disc(), ENV_DISC_HTTP, 'env_disc_configuration'),
    # Prefix probes: /env/<anything> (incl. /env/.env, encoded as /env/%2eenv)
    Route(PathPrefix('/env/'), _env_disc(), ENV_DISC_HTTP, 'env_disc_env_prefix'),
    # Admin-nested env disclosure probes previously shadowed by Drupal's greedy
    # /admin/ prefix (issue #508): /admin/.env, /admin/phpinfo.php,
    # /admin/settings.json, /admin/database.yml, /admin/debug.env, etc.
    Route(PathExact('/admin/.env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_env'),
    Route(PathPrefix('/admin/.env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_env_prefix'),
    Route(PathExact('/admin/phpinfo.php'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_phpinfo'),
    Route(
        PathPrefix('/admin/phpinfo'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_phpinfo_prefix'
    ),
    Route(PathExact('/admin/settings.json'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_settings'),
    Route(PathPrefix('/admin/database'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_database'),
    Route(PathPrefix('/admin/debug'), _env_disc(), ENV_DISC_HTTP, 'env_disc_admin_debug'),
    # API config/env disclosure probes. Specific secret sub-paths only — the
    # previous bare `PathPrefix('/api/')` shadowed Next.js server-action RCE
    # (/api/route) and PHPUnit eval-stdin (/api/vendor/phpunit/...) (issue #453).
    Route(PathPrefix('/api/.env'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_env'),
    Route(PathPrefix('/api/.git'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_git'),
    Route(PathPrefix('/api/wp-config'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_wpconfig'),
    Route(PathPrefix('/api/phpinfo'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_phpinfo'),
    Route(PathPrefix('/api/email'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_email'),
    Route(PathPrefix('/api/secrets'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_secrets'),
    Route(PathPrefix('/api/config'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_config'),
    Route(PathPrefix('/api/settings'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_settings'),
    Route(PathPrefix('/api/database'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_database'),
    Route(PathPrefix('/api/debug'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_debug'),
    Route(PathPrefix('/api/admin'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_admin'),
    Route(PathPrefix('/api/sql'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_sql'),
    Route(PathPrefix('/api/json'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_json'),
    Route(PathPrefix('/api/xmlrpc'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_xmlrpc'),
    Route(PathPrefix('/api/web.config'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_webconfig'),
    Route(PathPrefix('/api/.ht'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_ht'),
    Route(PathPrefix('/api/composer'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_composer'),
    Route(PathPrefix('/api/package'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_package'),
    Route(PathPrefix('/api/redis'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_redis'),
    Route(PathPrefix('/api/php.ini'), _env_disc(), ENV_DISC_HTTP, 'env_disc_api_phpini'),
]
