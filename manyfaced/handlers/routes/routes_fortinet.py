"""Fortinet (FortiGate SSL-VPN / FortiManager) routes.

Probe paths mirrored from FortiBleed / FortiGate SSL-VPN campaigns:
  /remote/login       SSL-VPN login page
  /remote/logincheck  SSL-VPN login (POST) — credential capture
  /remote/logout      SSL-VPN logout
  /api/v2/            FortiGate REST API (JSON)
  /jsonrpc            FortiManager JSON-RPC endpoint (POST)

DETECTED_ID is hardcoded (1043) — status.py is intentionally not imported.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

# Hardcoded detected-id for the Fortinet face.
DETECTED_ID = 1043


def _fortinet() -> type:
    from manyfaced.handlers.fortinet_handler import FortinetHandler

    return FortinetHandler


ROUTES: list[Route] = [
    # ---- FortiGate SSL-VPN (FortiBleed campaign) --------------------------
    Route(PathExact('/remote/login'), _fortinet(), DETECTED_ID, 'fortinet_sslvpn_login'),
    Route(PathExact('/remote/logincheck'), _fortinet(), DETECTED_ID, 'fortinet_sslvpn_logincheck'),
    Route(PathExact('/remote/logout'), _fortinet(), DETECTED_ID, 'fortinet_sslvpn_logout'),
    # ---- FortiGate REST API (JSON) ----------------------------------------
    Route(PathPrefix('/api/v2/'), _fortinet(), DETECTED_ID, 'fortinet_fortigate_api'),
    # ---- FortiManager JSON-RPC --------------------------------------------
    Route(PathExact('/jsonrpc'), _fortinet(), DETECTED_ID, 'fortinet_fmgr_jsonrpc'),
]
