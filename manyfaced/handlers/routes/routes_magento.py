"""Magento (Adobe Commerce) routes.

Routes are ordered most-specific first so they win over the broad prefixes.
URL-encoded probe segments (%2e -> '.', %2f -> '/') are decoded by the handler
before dispatch, so PathPrefix('/magento/') catches /magento/%2eenv probes.

Real probe paths covered:
  /                     -> storefront / home
  /admin                -> admin login
  /customer/account/login -> customer login
  /magento/%2eenv      -> fake .env disclosure (decoded /magento/.env)
  /setup                -> Web Setup Wizard
  /index.php/admin      -> admin login (entry-script form)
  /static               -> static assets (storefront)
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import MAGENTO_HTTP


def _magento() -> type:
    from manyfaced.handlers.magento_handler import MagentoHandler

    return MagentoHandler


ROUTES: list[Route] = [
    # ---- Magento (issue #293) ----
    Route(PathExact('/admin'), _magento(), MAGENTO_HTTP, 'magento_admin'),
    Route(PathExact('/customer/account/login'), _magento(), MAGENTO_HTTP, 'magento_customer_login'),
    Route(PathExact('/index.php/admin'), _magento(), MAGENTO_HTTP, 'magento_index_admin'),
    Route(PathExact('/setup'), _magento(), MAGENTO_HTTP, 'magento_setup'),
    Route(PathPrefix('/magento/'), _magento(), MAGENTO_HTTP, 'magento_prefix'),
    Route(PathPrefix('/static/'), _magento(), MAGENTO_HTTP, 'magento_static'),
]
