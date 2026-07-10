"""Joomla routes — canonical Joomla! endpoints dispatched to JoomlaHandler.

Routes are ordered most-specific first so the SP Page Builder upload endpoint
(``index.php?option=com_sppagebuilder``) and the admin panel win over the
generic ``/index.php`` and ``/`` prefixes.  The global route table appends a
catch-all ``Any()`` last, so these prefixes must remain specific.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

# Hardcoded detected-id (must match JoomlaHandler.DETECTED_ID). Intentionally
# not imported from manyfaced.common.status to keep this new face self-contained.
JOOMLA_DETECTED_ID = 1040


def _joomla() -> type:
    """Lazily import JoomlaHandler to avoid import cycles at module load."""
    from manyfaced.handlers.joomla_handler import JoomlaHandler

    return JoomlaHandler


ROUTES: list[Route] = [
    # ---- Joomla administrator panel (exact + prefix, most specific first) ----
    Route(PathExact('/administrator'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_admin'),
    Route(PathPrefix('/administrator/'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_admin_slash'),
    # ---- SP Page Builder upload endpoint (CVE-2026-48908 / CVE-2026-56290) ----
    Route(PathPrefix('/index.php'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_sppagebuilder'),
    # ---- Front controller ----
    Route(PathExact('/index.php'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_index_php'),
    # NOTE: deliberately do NOT claim bare '/' — the global catch-all monster
    # page owns it (see test_root_path_catchall). Joomla's front page is
    # reachable via /index.php instead.
    # ---- Common Joomla! top-level paths ----
    Route(PathPrefix('/templates'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_templates'),
    Route(PathPrefix('/components'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_components'),
    Route(PathPrefix('/api'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_api'),
    Route(PathPrefix('/language'), _joomla(), JOOMLA_DETECTED_ID, 'joomla_language'),
]
