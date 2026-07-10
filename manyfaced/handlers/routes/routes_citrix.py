"""Citrix NetScaler Gateway routes."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

# Hardcoded detected id for the Citrix NetScaler Gateway face (do NOT touch status.py).
DETECTED_ID = 1044


def _citrix() -> type:
    from manyfaced.handlers.citrix_handler import CitrixHandler

    return CitrixHandler


ROUTES: list[Route] = [
    # ---- Citrix NetScaler Gateway -----------------------------------------
    Route(PathExact('/vpn/index.html'), _citrix(), DETECTED_ID, 'citrix_gateway_login'),
    Route(PathExact('/cgi/login'), _citrix(), DETECTED_ID, 'citrix_cgi_login'),
    Route(PathPrefix('/nf/'), _citrix(), DETECTED_ID, 'citrix_nf_auth'),
    Route(PathPrefix('/logon/'), _citrix(), DETECTED_ID, 'citrix_logon_point'),
    # CVE-2026-3055 out-of-bounds-read probe prefixes (SAML / OAuth / PCI DSS).
    Route(PathPrefix('/pcidss/'), _citrix(), DETECTED_ID, 'citrix_cve_2026_3055_pcidss'),
    Route(PathPrefix('/oauth'), _citrix(), DETECTED_ID, 'citrix_cve_2026_3055_oauth'),
    Route(PathPrefix('/saml'), _citrix(), DETECTED_ID, 'citrix_cve_2026_3055_saml'),
]
