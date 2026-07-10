"""Splunk Enterprise routes (issue #397 / CVE-2026-20253).

Matches the production Splunk Enterprise probe paths observed in the wild:
  /                       -> Splunk Web landing page
  /en-US/                 -> Splunk Web landing page
  /en-US/account/login    -> Splunk Web login form
  /services/auth/login    -> splunkd session endpoint (POST creds)
  /services/search/jobs   -> splunkd search job creation (POST)
  /servicesNS/            -> splunkd REST config surface
  /api/                   -> generic Splunk API surface
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

# Hardcoded detected-id for the Splunk face (do NOT touch status.py).
DETECTED_ID = 1046


def _splunk() -> type:
    from manyfaced.handlers.splunk_handler import SplunkHandler

    return SplunkHandler


ROUTES: list[Route] = [
    # ---- Splunk Enterprise (issue #397 / CVE-2026-20253) ----
    # NOTE: bare '/' is intentionally NOT claimed — the global monster-page
    # catch-all owns it (see test_root_path_catchall). Splunk is reachable
    # via /en-US/, /en-US/account/login, /services/*.
    Route(PathExact('/en-US/'), _splunk(), DETECTED_ID, 'splunk_web_landing'),
    Route(PathExact('/en-US/account/login'), _splunk(), DETECTED_ID, 'splunk_web_login'),
    Route(PathExact('/services/auth/login'), _splunk(), DETECTED_ID, 'splunk_auth_login'),
    Route(PathExact('/services/search/jobs'), _splunk(), DETECTED_ID, 'splunk_search_jobs'),
    Route(PathPrefix('/servicesNS/'), _splunk(), DETECTED_ID, 'splunk_servicesns'),
    Route(PathPrefix('/api/'), _splunk(), DETECTED_ID, 'splunk_api'),
]
