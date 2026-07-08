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
]
