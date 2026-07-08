"""MCP routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, Route

from manyfaced.common.status import MCP_HTTP


def _mcp() -> type:
    from manyfaced.handlers.mcp_handler import MCPHandler

    return MCPHandler


ROUTES: list[Route] = [
    # ---- MCP (issue #283) ----
    Route(PathExact('/mcp'), _mcp(), MCP_HTTP, 'mcp_0'),
    Route(PathExact('/sse'), _mcp(), MCP_HTTP, 'mcp_1'),
]
