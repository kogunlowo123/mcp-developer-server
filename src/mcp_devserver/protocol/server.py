"""Method dispatch: the three RPCs this server answers, and how it answers them.

The dispatcher is transport-independent by construction. It takes a decoded
JSON-RPC request and returns a decoded response, or ``None`` for a notification.
Both transports in this package are thin wrappers around
:meth:`Server.handle_payload`, which is what makes it possible to run the same
conformance suite over stdio and over HTTP and get identical results.

Statelessness is enforced rather than intended. :class:`Server` holds
configuration and a tool registry — things fixed at start-up — and nothing
derived from a request. Every per-request value lives in a
:class:`~mcp_devserver.protocol.meta.RequestContext` built inside ``handle`` and
discarded when it returns. There is no session table to consult and none to
forget to clear, which is why interleaving unrelated requests on one connection
cannot produce a different answer than sending them separately.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import time
from typing import Any, Final

import structlog

from mcp_devserver.config import Settings
from mcp_devserver.errors import (
    InvalidParamsError,
    McpError,
    MethodNotFoundError,
    UnsupportedProtocolVersionError,
)
from mcp_devserver.protocol import jsonrpc, spec
from mcp_devserver.protocol.meta import RequestContext, parse_context, result_meta, server_info
from mcp_devserver.sandbox.denylist import Denylist
from mcp_devserver.sandbox.workspace import Workspace
from mcp_devserver.security.redaction import Redactor
from mcp_devserver.security.untrusted import UntrustedContentScanner
from mcp_devserver.tools import ToolRegistry, build_registry
from mcp_devserver.tools.base import Limits, ToolContext

_log = structlog.get_logger(__name__)

#: How many tools one ``tools/list`` page carries. Small enough that pagination
#: is exercised by the real tool set rather than only by a test fixture.
PAGE_SIZE: Final[int] = 5

#: ``cacheScope`` values from the specification. ``server`` means the result is
#: identical for every client of this server, which is true here: the tool set
#: does not vary by caller, because there is no per-caller state to vary by.
CACHE_SCOPE_SERVER: Final[str] = "server"


def _encode_cursor(offset: int) -> str:
    """Render an opaque pagination cursor.

    Opaque on purpose. A cursor a client can construct is a cursor a client will
    construct, and then the server's paging strategy is part of its contract.
    """
    return base64.urlsafe_b64encode(f"offset:{offset}".encode()).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> int:
    padding = "=" * (-len(cursor) % 4)
    try:
        decoded = base64.urlsafe_b64decode(cursor + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise InvalidParamsError(
            "cursor is not one this server issued; omit it to start from the beginning"
        ) from exc

    prefix, _, value = decoded.partition(":")
    if prefix != "offset" or not value.isdigit():
        raise InvalidParamsError(
            "cursor is not one this server issued; omit it to start from the beginning"
        )
    return int(value)


class Server:
    """The MCP server: configuration, a tool registry, and three methods."""

    def __init__(
        self,
        settings: Settings,
        *,
        registry: ToolRegistry | None = None,
        version: str = "0.1.0",
    ) -> None:
        self._settings = settings
        self._registry = registry or build_registry()
        self._version = version
        self._info = server_info(settings.server.name, version, title=settings.server.title)
        self._workspace = Workspace(
            settings.sandbox.workspace,
            denylist=Denylist.with_extra(settings.sandbox.deny_extra),
            max_file_bytes=settings.sandbox.max_file_bytes,
            follow_symlinks=settings.sandbox.follow_symlinks,
        )
        self._limits = Limits(
            max_file_bytes=settings.sandbox.max_file_bytes,
            max_read_lines=settings.sandbox.max_read_lines,
            max_search_results=settings.sandbox.max_search_results,
            max_search_files=settings.sandbox.max_search_files,
            max_result_bytes=settings.sandbox.max_result_bytes,
            max_directory_entries=settings.sandbox.max_directory_entries,
            max_git_entries=settings.sandbox.max_git_entries,
            tool_timeout_seconds=settings.sandbox.tool_timeout_seconds,
        )
        self._redactor = Redactor(enabled=settings.security.redact_secrets)
        self._scanner = UntrustedContentScanner()

    # -- accessors ---------------------------------------------------------

    @property
    def settings(self) -> Settings:
        """The configuration this server was built with."""
        return self._settings

    @property
    def registry(self) -> ToolRegistry:
        """The published tool registry."""
        return self._registry

    @property
    def workspace(self) -> Workspace:
        """The contained workspace."""
        return self._workspace

    @property
    def info(self) -> dict[str, Any]:
        """The ``serverInfo`` object attached to every result."""
        return dict(self._info)

    def capabilities(self) -> dict[str, Any]:
        """Report what this server can do, in the shape ``server/discover`` returns."""
        return {
            "tools": {
                "listChanged": False,
                "count": len(self._registry),
            }
        }

    # -- dispatch ----------------------------------------------------------

    async def handle_payload(self, payload: object) -> dict[str, Any] | None:
        """Handle one already-decoded request payload."""
        try:
            request = jsonrpc.from_payload(payload)
        except McpError as error:
            identifier = payload.get("id") if isinstance(payload, dict) else None
            if not isinstance(identifier, str | int) or isinstance(identifier, bool):
                identifier = None
            return jsonrpc.failure(identifier, error)
        return await self.handle(request)

    async def handle_text(self, raw: str) -> dict[str, Any] | None:
        """Handle one request from its wire text."""
        try:
            request = jsonrpc.parse(raw)
        except McpError as error:
            return jsonrpc.failure(None, error)
        return await self.handle(request)

    async def handle(
        self, request: jsonrpc.Request, *, header_version: str | None = None
    ) -> dict[str, Any] | None:
        """Handle one parsed request.

        Returns ``None`` for a notification. A notification that fails is logged
        and dropped: JSON-RPC forbids answering one, and a server that answers
        anyway desynchronises a client that is not reading for a response.
        """
        started = time.perf_counter()
        try:
            result = await self._dispatch(request, header_version=header_version)
        except McpError as error:
            _log.warning(
                "rpc.error",
                method=request.method,
                code=error.code,
                message=error.message,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            if request.is_notification:
                return None
            return jsonrpc.failure(request.id, error)
        except Exception:
            # An unexpected failure becomes an internal error with no detail.
            # The traceback goes to the log, not to the client: a stack trace
            # names absolute paths outside the workspace, which is exactly the
            # information the sandbox exists to withhold.
            _log.exception("rpc.unhandled", method=request.method)
            if request.is_notification:
                return None
            return jsonrpc.failure(request.id, McpError("internal error"))

        _log.info(
            "rpc.ok",
            method=request.method,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        identifier = request.id
        if identifier is None:
            return None
        return jsonrpc.success(identifier, result)

    async def _dispatch(
        self, request: jsonrpc.Request, *, header_version: str | None
    ) -> dict[str, Any]:
        if request.method == spec.LEGACY_INITIALIZE:
            # A legacy client's first message. Answering with the version error
            # tells it exactly which revisions this server speaks, in the shape
            # the specification defines, in one round trip. This is the whole of
            # this server's backward compatibility, and it is deliberate:
            # ARCHITECTURE.md ADR-002.
            requested = request.params.get("protocolVersion")
            raise UnsupportedProtocolVersionError(
                requested if isinstance(requested, str) else "legacy-initialize"
            )

        context = parse_context(request.meta, header_version=header_version)

        match request.method:
            case spec.DISCOVER:
                return self._discover(context)
            case spec.TOOLS_LIST:
                return self._tools_list(request.params, context)
            case spec.TOOLS_CALL:
                return await self._tools_call(request.params, context)
            case _:
                raise MethodNotFoundError(request.method)

    # -- methods -----------------------------------------------------------

    def _discover(self, context: RequestContext) -> dict[str, Any]:
        """``server/discover``: what this server is and what it can do."""
        return {
            "resultType": spec.RESULT_COMPLETE,
            "supportedVersions": list(spec.SUPPORTED_VERSIONS),
            "capabilities": self.capabilities(),
            "instructions": self._settings.server.instructions,
            "ttlMs": self._settings.server.discovery_ttl_ms,
            "cacheScope": CACHE_SCOPE_SERVER,
            "_meta": result_meta(self._info, context),
        }

    def _tools_list(self, params: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        """``tools/list``: the published tools, paginated and in a stable order."""
        cursor = params.get("cursor")
        offset = 0
        if cursor is not None:
            if not isinstance(cursor, str):
                raise InvalidParamsError("cursor must be a string")
            offset = _decode_cursor(cursor)

        declarations = self._registry.declarations()
        if offset > len(declarations):
            raise InvalidParamsError(
                "cursor points past the end of the tool list; omit it to start again"
            )
        page = declarations[offset : offset + PAGE_SIZE]
        result: dict[str, Any] = {
            "resultType": spec.RESULT_COMPLETE,
            "tools": page,
            "ttlMs": self._settings.server.discovery_ttl_ms,
            "cacheScope": CACHE_SCOPE_SERVER,
            "_meta": result_meta(self._info, context),
        }
        if offset + PAGE_SIZE < len(declarations):
            result["nextCursor"] = _encode_cursor(offset + PAGE_SIZE)
        return result

    async def _tools_call(self, params: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        """``tools/call``: run one tool inside the sandbox."""
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise InvalidParamsError("name must be a non-empty string naming a published tool")

        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise InvalidParamsError("arguments must be an object")

        tool_context = ToolContext(
            workspace=self._workspace,
            limits=self._limits,
            redactor=self._redactor,
            scanner=self._scanner,
        )

        # Handlers are synchronous filesystem work. Running one on the event
        # loop would block every other request on the connection for the length
        # of a directory walk, which on a large repository is not milliseconds.
        try:
            outcome = await asyncio.wait_for(
                asyncio.to_thread(self._registry.invoke, name, arguments, tool_context),
                timeout=self._limits.tool_timeout_seconds + 5.0,
            )
        except TimeoutError:
            # The outer bound. Handlers check their own deadline; this catches a
            # handler that is blocked somewhere it cannot check, so that a stuck
            # call cannot hold the connection open indefinitely.
            _log.warning("tool.hard_timeout", tool=name)
            return {
                "resultType": spec.RESULT_COMPLETE,
                "content": [
                    {
                        "type": spec.CONTENT_TEXT,
                        "text": (
                            f"{name} did not finish within its time budget and was abandoned."
                        ),
                    }
                ],
                "structuredContent": {"error": "timed_out", "tool": name},
                "isError": True,
                "_meta": result_meta(self._info, context),
            }

        if self._settings.observability.log_tool_arguments:
            _log.info(
                "tool.call",
                tool=name,
                arguments=sorted(arguments),
                client=context.client.label(),
            )
        else:
            _log.info("tool.call", tool=name, client=context.client.label())

        outcome["_meta"] = result_meta(self._info, context)
        return outcome
