"""PHPUnit (eval-stdin RCE / CVE-2017-9841) routes."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

try:  # pragma: no cover - exercised by import resolution
    from manyfaced.common.status import PHPUNIT_HTTP
except Exception:  # noqa: BLE001 - defensive fallback
    PHPUNIT_HTTP = 1034


def _phpunit() -> type:
    from manyfaced.handlers.phpunit_handler import PhpUnitHandler

    return PhpUnitHandler


ROUTES: list[Route] = [
    # ---- PHPUnit (eval-stdin RCE, CVE-2017-9841) ---------------------------
    # The high-value RCE probe path.
    Route(
        PathExact('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'),
        _phpunit(),
        PHPUNIT_HTTP,
        'phpunit_eval_stdin',
    ),
    # Canonical PHPUnit UI paths seen in production probing.
    Route(PathExact('/phpunit'), _phpunit(), PHPUNIT_HTTP, 'phpunit_root'),
    Route(PathExact('/phpunit/phpunit'), _phpunit(), PHPUNIT_HTTP, 'phpunit_bin'),
    Route(PathExact('/phpunit/scratch.php'), _phpunit(), PHPUNIT_HTTP, 'phpunit_scratch'),
    # Prefix coverage (also catches %2eenv -> .env decoding handled in handler).
    Route(PathPrefix('/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_prefix'),
    Route(PathPrefix('/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_vendor_prefix'),
    # Deep web-root variants (issue #350): production probes hit paths like
    # /www/vendor/phpunit/.../eval-stdin.php, /yii/vendor/phpunit/..., etc.
    # These previously fell through to the generic monster page. Add a prefix
    # route per observed root so they all reach PHPUnitHandler.
    Route(PathPrefix('/www/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_www'),
    Route(PathPrefix('/yii/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_yii'),
    Route(PathPrefix('/laravel/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_laravel'),
    Route(PathPrefix('/app/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_app'),
    Route(PathPrefix('/cms/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_cms'),
    Route(PathPrefix('/lib/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_lib'),
    Route(PathPrefix('/panel/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_panel'),
    Route(PathPrefix('/public/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_public'),
    Route(PathPrefix('/ws/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_ws'),
    Route(PathPrefix('/demo/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_demo'),
    Route(PathPrefix('/testing/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_testing'),
    Route(PathPrefix('/tests/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_tests'),
    Route(PathPrefix('/apps/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_apps'),
    Route(PathPrefix('/backup/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_backup'),
    Route(PathPrefix('/v2/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_v2'),
    Route(PathPrefix('/blog/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_blog'),
    Route(PathPrefix('/api/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_api'),
    Route(PathPrefix('/zend/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_zend'),
    Route(PathPrefix('/workspace/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_workspace'),
    Route(PathPrefix('/crm/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_crm'),
    Route(PathPrefix('/vercel/vendor/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_vercel'),
    Route(PathPrefix('/lib/phpunit/'), _phpunit(), PHPUNIT_HTTP, 'phpunit_lib_phpunit'),
]
