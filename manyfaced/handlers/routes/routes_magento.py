"""Magento routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import MAGENTO_HTTP


def _magento() -> type:
    from manyfaced.handlers.magento_handler import MagentoHandler

    return MagentoHandler


ROUTES: list[Route] = [
    # ---- Magento (issue #293) ----
    Route(PathExact('/magento'), _magento(), MAGENTO_HTTP, 'magento_0'),
    Route(PathExact('/admin'), _magento(), MAGENTO_HTTP, 'magento_1'),
    Route(PathExact('/index.php/admin'), _magento(), MAGENTO_HTTP, 'magento_2'),
    Route(PathPrefix('/index.php/admin/'), _magento(), MAGENTO_HTTP, 'magento_prefix_2'),
]
