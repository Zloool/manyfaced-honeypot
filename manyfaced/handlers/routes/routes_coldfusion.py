"""ColdFusion routes — Adobe ColdFusion HTTP endpoints (CVE-2026-48282)."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

# Hardcoded detected-id for the ColdFusion face. Do NOT edit status.py.
DETECTED_ID = 1042


def _coldfusion() -> type:
    from manyfaced.handlers.coldfusion_handler import ColdFusionHandler

    return ColdFusionHandler


ROUTES: list[Route] = [
    # ---- ColdFusion Administrator ------------------------------------------
    Route(PathExact('/cfide/administrator/'), _coldfusion(), DETECTED_ID, 'coldfusion_admin'),
    Route(
        PathPrefix('/cfide/administrator/'), _coldfusion(), DETECTED_ID, 'coldfusion_admin_slash'
    ),
    Route(PathExact('/administrator/'), _coldfusion(), DETECTED_ID, 'coldfusion_administrator'),
    Route(
        PathPrefix('/administrator/'), _coldfusion(), DETECTED_ID, 'coldfusion_administrator_slash'
    ),
    # ---- ColdFusion CFIDE web root -----------------------------------------
    Route(PathExact('/cfide/'), _coldfusion(), DETECTED_ID, 'coldfusion_cfide'),
    Route(PathPrefix('/cfide/'), _coldfusion(), DETECTED_ID, 'coldfusion_cfide_slash'),
    # ---- ColdFusion Component Manager --------------------------------------
    Route(PathExact('/ccm/'), _coldfusion(), DETECTED_ID, 'coldfusion_ccm'),
    Route(PathPrefix('/ccm/'), _coldfusion(), DETECTED_ID, 'coldfusion_ccm_slash'),
    # ---- ColdFusion internal web root (graph / __export RCE) ---------------
    Route(PathExact('/cfusion/'), _coldfusion(), DETECTED_ID, 'coldfusion_cfusion'),
    Route(PathPrefix('/cfusion/'), _coldfusion(), DETECTED_ID, 'coldfusion_cfusion_slash'),
    # ---- ColdFusion AJAX / Spry scripts ------------------------------------
    Route(PathPrefix('/cf_scripts/'), _coldfusion(), DETECTED_ID, 'coldfusion_cf_scripts'),
]
