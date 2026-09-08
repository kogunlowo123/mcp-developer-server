"""The published tool set.

Seven tools, all read-only, listed once and in one place so that "what can this
server be asked to do?" has a two-line answer a reviewer can check.

What is deliberately absent is as much of the design as what is present:

* **No shell tool.** A general-purpose command tool hands a model every
  privilege the process has, and no sandbox above it can constrain what the
  command does.
* **No write, move or delete.** The server never opens a file for writing. A
  compromised or confused client cannot damage the workspace through it, and
  that is a property of the code rather than of a permission prompt.
* **No test runner.** Running a project's tests means executing the project's
  code, which is not containable by path rules — the very thing this server's
  sandbox is built on. A tool that broke that guarantee would make the rest of
  it unclaimable.
* **No network fetch.** The one subprocess this server runs is git, with a
  transport that cannot reach a remote.
"""

from __future__ import annotations

from mcp_devserver.tools.base import (
    Limits,
    ToolContext,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)
from mcp_devserver.tools.files import LIST_DIRECTORY, READ_FILE
from mcp_devserver.tools.git import GIT_DIFF, GIT_LOG
from mcp_devserver.tools.overview import PROJECT_OVERVIEW
from mcp_devserver.tools.search import SEARCH_CODE
from mcp_devserver.tools.symbols import FIND_SYMBOL

#: Every tool this server publishes.
BUILTIN_TOOLS: tuple[ToolSpec, ...] = (
    FIND_SYMBOL,
    GIT_DIFF,
    GIT_LOG,
    LIST_DIRECTORY,
    PROJECT_OVERVIEW,
    READ_FILE,
    SEARCH_CODE,
)


def build_registry(tools: tuple[ToolSpec, ...] = BUILTIN_TOOLS) -> ToolRegistry:
    """Build the registry a server publishes."""
    return ToolRegistry(tools)


__all__ = [
    "BUILTIN_TOOLS",
    "Limits",
    "ToolContext",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "build_registry",
]
