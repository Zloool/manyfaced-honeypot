"""Microsoft SharePoint routes (CVE-2026-45659 face, issue #396).

Routes mirror the canonical SharePoint front-end probe paths:
  /_layouts/      SharePoint application pages (15-mode + legacy)
  /_api/          SharePoint REST API
  /_vti_bin/      SharePoint Web Services front-end (SOAP)
  /webservices/   legacy SOAP web services directory
  /login          forms-based login (credential capture)
The CVE-2026-45659 deserialization probe path is matched inside the handler via
PathPrefix('/_layouts/') and answered 200 to capture the payload.

This module deliberately does NOT import manyfaced.common.status; the detected
id (1045) is hard-coded on the handler and referenced here as a literal so the
shared status.py is left untouched.
"""

from __future__ import annotations

# Hard-coded detected id for this face (matches SharePointHandler.DETECTED_ID).
SHAREPOINT_HTTP = 1045

from manyfaced.handlers.router import PathExact, PathPrefix, Route  # noqa: E402


def _sharepoint() -> type:
    from manyfaced.handlers.sharepoint_handler import SharePointHandler

    return SharePointHandler


ROUTES: list[Route] = [
    # ---- SharePoint (issue #396 / CVE-2026-45659) -------------------------
    Route(PathPrefix('/_layouts/'), _sharepoint(), SHAREPOINT_HTTP, 'sharepoint_layouts'),
    Route(PathPrefix('/_api/'), _sharepoint(), SHAREPOINT_HTTP, 'sharepoint_api'),
    Route(PathPrefix('/_vti_bin/'), _sharepoint(), SHAREPOINT_HTTP, 'sharepoint_vti_bin'),
    Route(PathPrefix('/webservices/'), _sharepoint(), SHAREPOINT_HTTP, 'sharepoint_webservices'),
    Route(PathExact('/login'), _sharepoint(), SHAREPOINT_HTTP, 'sharepoint_login'),
]
