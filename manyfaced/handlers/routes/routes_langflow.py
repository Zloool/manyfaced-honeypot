"""Langflow (low-code LLM app builder) routes.

Routes mirror the production Langflow UI and REST API probe paths:
  /  /login  /api/v1/run  /api/v1/flows  /api/v1/validate  /api/v1/upload
The /api/v1/upload endpoint is reachable without authentication and mirrors
CVE-2026-55255 (authorization-bypass file upload) exploitation attempts.
"""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, Route


def _langflow() -> type:
    from manyfaced.handlers.langflow_handler import LangflowHandler

    return LangflowHandler


ROUTES: list[Route] = [
    # ---- Langflow (CVE-2026-55255) -----------------------------------------
    Route(PathExact('/'), _langflow(), 1041, 'langflow_root'),
    Route(PathExact('/login'), _langflow(), 1041, 'langflow_login'),
    Route(PathExact('/api/v1/run'), _langflow(), 1041, 'langflow_api_run'),
    Route(PathExact('/api/v1/flows'), _langflow(), 1041, 'langflow_api_flows'),
    Route(PathExact('/api/v1/validate'), _langflow(), 1041, 'langflow_api_validate'),
    Route(PathExact('/api/v1/upload'), _langflow(), 1041, 'langflow_api_upload'),
]
