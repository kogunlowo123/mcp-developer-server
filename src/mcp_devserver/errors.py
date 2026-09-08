"""The two failure vocabularies this server speaks, and the boundary between them.

The Model Context Protocol distinguishes two kinds of failure, and conflating
them is the most common way an MCP server misbehaves:

**Protocol errors** are failures of the request itself — a method that does not
exist, a malformed envelope, a missing required ``_meta`` field, a tool name that
was never registered. They become a JSON-RPC ``error`` object. The client's
transport layer sees them; the model usually does not.

**Tool execution errors** are failures of a request that was perfectly well
formed — a path outside the workspace, a file that is too large, a search that
timed out. They are *results*, carrying ``isError: true``, and the model is meant
to read them and try something else.

The rule this package follows: if the caller could not have known better, it is a
protocol error; if the caller asked a reasonable question and the answer is "no,
and here is why", it is a tool error. A sandbox denial is a tool error, because
"that path is outside the workspace" is information the model should act on, and
because a denial that surfaced as a transport failure would be invisible to it.
"""

from __future__ import annotations

from typing import Any, Final

from mcp_devserver.protocol import spec


class McpError(Exception):
    """A failure that becomes a JSON-RPC error object.

    ``code`` and ``data`` are carried on the exception so that the dispatcher
    can serialise any failure without knowing which one it caught.
    """

    code: int = spec.INTERNAL_ERROR

    def __init__(self, message: str, *, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.data = data

    def to_error_object(self) -> dict[str, Any]:
        """Render the JSON-RPC ``error`` member."""
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


class ParseError(McpError):
    """The request body was not JSON."""

    code = spec.PARSE_ERROR


class InvalidRequestError(McpError):
    """The body was JSON but not a JSON-RPC request."""

    code = spec.INVALID_REQUEST


class MethodNotFoundError(McpError):
    """The method is not one this server implements."""

    code = spec.METHOD_NOT_FOUND

    def __init__(self, method: str) -> None:
        super().__init__(f"unknown method {method!r}", data={"method": method})
        self.method = method


class InvalidParamsError(McpError):
    """The parameters, or the required ``_meta`` fields, were wrong.

    This is also the code for a resource that does not exist. Earlier revisions
    had ``-32002`` for that; 2026-07-28 withdrew it, because "no such tool" and
    "no such argument" are the same class of caller mistake.
    """

    code = spec.INVALID_PARAMS


class HeaderMismatchError(McpError):
    """A transport header contradicts the value in ``_meta``.

    Emitted when an HTTP request carries a protocol-version header that names a
    different revision than the request body does. The specification requires
    the two to agree rather than picking a winner, because a proxy that rewrites
    one and not the other would otherwise silently downgrade the exchange.
    """

    code = spec.HEADER_MISMATCH


class MissingRequiredClientCapabilityError(McpError):
    """The request needs a client capability the client did not declare."""

    code = spec.MISSING_REQUIRED_CLIENT_CAPABILITY

    def __init__(self, *required: str) -> None:
        listed = ", ".join(sorted(required))
        super().__init__(
            f"this request requires client capabilities the client did not declare: {listed}",
            data={"requiredCapabilities": sorted(required)},
        )
        self.required = frozenset(required)


class UnsupportedProtocolVersionError(McpError):
    """The client asked for a revision this server does not serve."""

    code = spec.UNSUPPORTED_PROTOCOL_VERSION

    def __init__(self, requested: str) -> None:
        super().__init__(
            f"unsupported protocol version {requested!r}",
            data={"supported": list(spec.SUPPORTED_VERSIONS), "requested": requested},
        )
        self.requested = requested


# ---------------------------------------------------------------------------
# Tool execution failures
# ---------------------------------------------------------------------------

#: Stable, documented identifiers. They are part of the contract: a client can
#: branch on ``structuredContent["error"]`` without parsing prose.
ERROR_OUTSIDE_WORKSPACE: Final[str] = "outside_workspace"
ERROR_DENIED_PATH: Final[str] = "denied_path"
ERROR_NOT_FOUND: Final[str] = "not_found"
ERROR_NOT_A_FILE: Final[str] = "not_a_file"
ERROR_NOT_A_DIRECTORY: Final[str] = "not_a_directory"
ERROR_TOO_LARGE: Final[str] = "too_large"
ERROR_BINARY: Final[str] = "binary_file"
ERROR_TIMED_OUT: Final[str] = "timed_out"
ERROR_TOO_MANY_RESULTS: Final[str] = "too_many_results"
ERROR_BAD_PATTERN: Final[str] = "bad_pattern"
ERROR_NOT_A_REPOSITORY: Final[str] = "not_a_repository"
ERROR_GIT_FAILED: Final[str] = "git_failed"
ERROR_UNSUPPORTED: Final[str] = "unsupported"


class ToolExecutionError(Exception):
    """A tool ran and could not do what was asked.

    This is not a protocol error. It becomes a ``CallToolResult`` with
    ``isError: true``, which is what lets a model read the reason and adapt —
    the difference between "the model learns the file is too big" and "the
    client's transport logs an exception the model never sees".

    ``remedy`` is deliberately part of the type. A denial that does not say what
    would have worked teaches the model nothing, and it will try the same call
    again.
    """

    def __init__(self, code: str, message: str, *, remedy: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remedy = remedy

    def to_structured(self) -> dict[str, Any]:
        """Render the machine-readable half of the error result."""
        payload: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.remedy:
            payload["remedy"] = self.remedy
        return payload

    def to_text(self) -> str:
        """Render the half a model reads."""
        if self.remedy:
            return f"{self.message} {self.remedy}"
        return self.message


class SandboxError(ToolExecutionError):
    """A path or resource was refused by the workspace sandbox.

    Its own type because the audit log and the security tests both need to
    count denials without matching on error codes.
    """


class ConfigurationError(Exception):
    """The server was asked to start in a state it must not start in.

    Raised during construction, never during a request. A server that cannot
    contain its workspace must fail to start rather than serve one request with
    a hole in it.
    """
