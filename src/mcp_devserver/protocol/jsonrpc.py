"""JSON-RPC 2.0 envelope parsing and serialisation.

Parsing is deliberately strict and deliberately separate from dispatch. A
malformed envelope must produce a well-formed error, and the only way to
guarantee that is for the code that recognises a request to have no opinion
about what the request means.

One subtlety that is easy to get wrong and that the tests pin: a request without
an ``id`` is a *notification*, and a notification must never be answered — not
even with an error. A server that replies to a notification breaks clients that
are not reading for a response, and it turns a fire-and-forget call into a
protocol violation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

from mcp_devserver.errors import InvalidRequestError, McpError, ParseError
from mcp_devserver.protocol import spec

#: JSON-RPC allows a string, a number or null for ``id``. Null is legal but
#: indistinguishable from "absent" in most client libraries, so this server
#: treats it as a notification, matching the JSON-RPC specification's advice
#: that null ids are discouraged.
type RequestId = str | int


@dataclass(frozen=True, slots=True)
class Request:
    """One parsed JSON-RPC request.

    ``params`` is normalised to a mapping. JSON-RPC permits positional
    parameters; MCP does not use them, and accepting them would mean every
    handler carried two argument paths. A positional call is rejected at the
    envelope, where the rejection is one branch instead of many.
    """

    method: str
    params: dict[str, Any]
    id: RequestId | None

    @property
    def is_notification(self) -> bool:
        """Whether this request expects no response."""
        return self.id is None

    @property
    def meta(self) -> dict[str, Any]:
        """The raw ``_meta`` member, or an empty mapping if absent."""
        raw = self.params.get("_meta")
        return raw if isinstance(raw, dict) else {}


def parse(raw: str | bytes) -> Request:
    """Parse one request from a JSON text.

    Raises :class:`ParseError` when the text is not JSON and
    :class:`InvalidRequestError` when it is JSON but not a JSON-RPC request.
    """
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ParseError(f"request body is not valid JSON: {exc}") from exc
    return from_payload(payload)


def from_payload(payload: object) -> Request:
    """Validate an already-decoded payload as a JSON-RPC request."""
    if not isinstance(payload, dict):
        raise InvalidRequestError("a JSON-RPC request must be a JSON object")

    version = payload.get("jsonrpc")
    if version != spec.JSONRPC_VERSION:
        raise InvalidRequestError(f"jsonrpc must be {spec.JSONRPC_VERSION!r}, got {version!r}")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise InvalidRequestError("method must be a non-empty string")

    params = payload.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise InvalidRequestError(
            "params must be a JSON object; this server does not accept positional parameters"
        )

    identifier = payload.get("id")
    if identifier is not None and not isinstance(identifier, str | int):
        raise InvalidRequestError("id must be a string, a number, or absent")
    # A JSON boolean is an instance of int in Python, and `true` is not a legal
    # JSON-RPC id.
    if isinstance(identifier, bool):
        raise InvalidRequestError("id must be a string, a number, or absent")

    return Request(method=method, params=params, id=identifier)


def success(identifier: RequestId, result: dict[str, Any]) -> dict[str, Any]:
    """Render a successful response envelope."""
    return {"jsonrpc": spec.JSONRPC_VERSION, "id": identifier, "result": result}


def failure(identifier: RequestId | None, error: McpError) -> dict[str, Any]:
    """Render an error response envelope.

    ``identifier`` may be ``None``: when a request could not be parsed far
    enough to recover its id, JSON-RPC requires the response to carry a null id
    rather than omitting it.
    """
    return {
        "jsonrpc": spec.JSONRPC_VERSION,
        "id": identifier,
        "error": error.to_error_object(),
    }


def encode(payload: dict[str, Any]) -> str:
    """Serialise a response.

    ``ensure_ascii`` stays on. Transports here are newline-delimited, and a
    non-ASCII byte sequence containing U+2028 or U+2029 is a line terminator to
    some JSON parsers but not to others; escaping everything removes the
    question. ``separators`` keeps the framing compact, which matters for a
    stdio transport reading a line at a time.
    """
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


#: The largest request this server will decode, in bytes. A JSON-RPC server
#: reading from a pipe has no natural bound on a single line, and an unbounded
#: read is a denial of service against the process the editor spawned.
MAX_REQUEST_BYTES: Final[int] = 1_048_576
