"""A sandboxed Model Context Protocol server for source code.

Read-only developer tools over one contained workspace, implementing MCP
revision 2026-07-28: stateless, per-request version negotiation, no
``initialize`` handshake.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
