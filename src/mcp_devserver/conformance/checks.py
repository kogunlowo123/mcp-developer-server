"""The conformance checks: what the specification requires, as executable assertions.

Each check names the requirement it tests and its level. ``MUST`` failures are
non-conformance; ``SHOULD`` failures are reported and, by default, do not fail
the gate — but they are visible, which is the point. A suite that quietly
treated a SHOULD as optional would let a server drift out of interoperability
one recommendation at a time.

The checks are written against the wire, not against the implementation. Nothing
here imports :class:`~mcp_devserver.protocol.server.Server`, so the same suite
runs against this server over stdio, against it over HTTP, and — for the
protocol-level checks — against any other MCP server speaking revision
2026-07-28.

The one honest caveat: C018 to C020 call tools by name (``read_file``,
``project_overview``) because the behaviours they check — a tool failure
arriving as ``isError`` rather than a JSON-RPC error, and an undeclared argument
being refused — cannot be tested without invoking something. Against a different
server those three would need different tool names. Everything from C001 to C017
and C021 to C023 is server-independent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

from mcp_devserver.conformance.client import Client
from mcp_devserver.protocol import spec

MUST: Final[str] = "MUST"
SHOULD: Final[str] = "SHOULD"


class CheckFailedError(Exception):
    """A check's assertion did not hold."""


def expect(condition: object, message: str) -> None:
    """Assert inside a check.

    A function rather than ``assert``: the statement is removed under ``-O``,
    and a conformance suite that silently passes when optimisations are enabled
    is worse than no suite.
    """
    if not condition:
        raise CheckFailedError(message)


def _meta(version: str = spec.PROTOCOL_VERSION, **extra: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        spec.META_PROTOCOL_VERSION: version,
        spec.META_CLIENT_CAPABILITIES: {},
        spec.META_CLIENT_INFO: {"name": "mcp-conformance", "version": "0.1.0"},
    }
    meta.update(extra)
    return meta


def _request(
    method: str, *, identifier: Any = 1, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if "_meta" not in body["params"]:
        body["params"]["_meta"] = _meta()
    if identifier is not None:
        body["id"] = identifier
    return body


def _result(response: dict[str, Any] | None, *, method: str) -> dict[str, Any]:
    if response is None:
        raise CheckFailedError(f"{method} returned no response")
    expect("error" not in response, f"{method} returned an error: {response.get('error')}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise CheckFailedError(f"{method} result is not an object: {result!r}")
    return dict(result)


def _error(response: dict[str, Any] | None, *, method: str) -> dict[str, Any]:
    if response is None:
        raise CheckFailedError(f"{method} returned no response where an error was required")
    error = response.get("error")
    if not isinstance(error, dict):
        raise CheckFailedError(f"{method} did not return an error object: {response}")
    return dict(error)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


async def discover_is_implemented(client: Client) -> None:
    """server/discover is mandatory and returns the required members."""
    result = _result(await client.send(_request(spec.DISCOVER)), method=spec.DISCOVER)
    expect(result.get("resultType") == spec.RESULT_COMPLETE, "resultType is not 'complete'")
    versions = result.get("supportedVersions")
    expect(isinstance(versions, list) and versions, "supportedVersions is missing or empty")
    expect(isinstance(result.get("capabilities"), dict), "capabilities is missing")


async def discover_reports_server_info(client: Client) -> None:
    """Results SHOULD carry serverInfo in _meta."""
    result = _result(await client.send(_request(spec.DISCOVER)), method=spec.DISCOVER)
    meta = result.get("_meta")
    expect(isinstance(meta, dict), "_meta is missing from the discover result")
    info = meta.get(spec.META_SERVER_INFO) if isinstance(meta, dict) else None
    expect(isinstance(info, dict), f"{spec.META_SERVER_INFO} is missing from _meta")
    if isinstance(info, dict):
        expect(isinstance(info.get("name"), str) and info["name"], "serverInfo.name is missing")
        expect(isinstance(info.get("version"), str), "serverInfo.version is missing")


async def discover_reports_caching(client: Client) -> None:
    """server/discover SHOULD tell a client how long it may cache the answer."""
    result = _result(await client.send(_request(spec.DISCOVER)), method=spec.DISCOVER)
    expect("ttlMs" in result, "ttlMs is absent, so a client cannot cache discovery")
    ttl = result.get("ttlMs")
    expect(isinstance(ttl, int) and ttl >= 0, f"ttlMs is not a non-negative integer: {ttl!r}")


async def every_result_carries_result_type(client: Client) -> None:
    """Every result MUST carry resultType."""
    methods: tuple[tuple[str, dict[str, Any]], ...] = (
        (spec.DISCOVER, {}),
        (spec.TOOLS_LIST, {}),
    )
    for method, params in methods:
        result = _result(await client.send(_request(method, params=params)), method=method)
        value = result.get("resultType")
        expect(
            value in spec.RESULT_TYPES,
            f"{method} returned resultType {value!r}, which is not one of "
            f"{sorted(spec.RESULT_TYPES)}",
        )


async def tools_list_returns_valid_tools(client: Client) -> None:
    """tools/list returns Tool objects with legal names and object schemas."""
    result = _result(await client.send(_request(spec.TOOLS_LIST)), method=spec.TOOLS_LIST)
    tools = result.get("tools")
    expect(isinstance(tools, list) and tools, "tools/list returned no tools")
    if not isinstance(tools, list):
        return
    for tool in tools:
        expect(isinstance(tool, dict), f"a tool entry is not an object: {tool!r}")
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        expect(isinstance(name, str), "a tool has no name")
        expect(
            isinstance(name, str) and spec.TOOL_NAME_PATTERN.match(name) is not None,
            f"tool name {name!r} is not 1-128 characters of [A-Za-z0-9_.-]",
        )
        schema = tool.get("inputSchema")
        expect(isinstance(schema, dict), f"{name}: inputSchema is not an object")
        if isinstance(schema, dict):
            expect(
                schema.get("type") == "object",
                f"{name}: inputSchema must declare type 'object'",
            )


async def tools_list_is_deterministic(client: Client) -> None:
    """tools/list SHOULD return a stable order across calls."""
    first = _result(await client.send(_request(spec.TOOLS_LIST)), method=spec.TOOLS_LIST)
    second = _result(
        await client.send(_request(spec.TOOLS_LIST, identifier=2)), method=spec.TOOLS_LIST
    )
    names_first = [tool.get("name") for tool in first.get("tools", [])]
    names_second = [tool.get("name") for tool in second.get("tools", [])]
    expect(
        names_first == names_second,
        f"tools/list order changed between calls: {names_first} then {names_second}",
    )


async def tools_list_paginates(client: Client) -> None:
    """A nextCursor must page forward and eventually stop."""
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(20):
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor
        result = _result(
            await client.send(_request(spec.TOOLS_LIST, params=params)), method=spec.TOOLS_LIST
        )
        page = [str(tool.get("name")) for tool in result.get("tools", [])]
        expect(page or cursor is None, "a cursor page returned no tools")
        seen.extend(page)
        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            break
        expect(isinstance(next_cursor, str) and next_cursor, "nextCursor is not a non-empty string")
        cursor = str(next_cursor)
    else:
        raise CheckFailedError("tools/list paginated more than 20 times without terminating")

    expect(len(seen) == len(set(seen)), f"pagination returned a tool twice: {seen}")


async def bad_cursor_is_invalid_params(client: Client) -> None:
    """A cursor the server did not issue MUST be rejected, not ignored."""
    error = _error(
        await client.send(_request(spec.TOOLS_LIST, params={"cursor": "not-a-real-cursor"})),
        method=spec.TOOLS_LIST,
    )
    expect(
        error.get("code") == spec.INVALID_PARAMS,
        f"a bad cursor returned {error.get('code')}, expected {spec.INVALID_PARAMS}",
    )


async def missing_protocol_version_is_rejected(client: Client) -> None:
    """_meta without a protocol version MUST be an invalid-params error."""
    meta: dict[str, Any] = {spec.META_CLIENT_CAPABILITIES: {}}
    error = _error(
        await client.send(_request(spec.DISCOVER, params={"_meta": meta})),
        method=spec.DISCOVER,
    )
    expect(
        error.get("code") == spec.INVALID_PARAMS,
        f"a missing protocol version returned {error.get('code')}, expected {spec.INVALID_PARAMS}",
    )


async def missing_client_capabilities_is_rejected(client: Client) -> None:
    """_meta without clientCapabilities MUST be an invalid-params error."""
    meta: dict[str, Any] = {spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION}
    error = _error(
        await client.send(_request(spec.DISCOVER, params={"_meta": meta})),
        method=spec.DISCOVER,
    )
    expect(
        error.get("code") == spec.INVALID_PARAMS,
        f"missing clientCapabilities returned {error.get('code')}, expected {spec.INVALID_PARAMS}",
    )


async def unsupported_version_names_what_is_supported(client: Client) -> None:
    """An unsupported version MUST return -32022 with the supported list."""
    error = _error(
        await client.send(_request(spec.DISCOVER, params={"_meta": _meta(version="1999-01-01")})),
        method=spec.DISCOVER,
    )
    expect(
        error.get("code") == spec.UNSUPPORTED_PROTOCOL_VERSION,
        f"an unsupported version returned {error.get('code')}, "
        f"expected {spec.UNSUPPORTED_PROTOCOL_VERSION}",
    )
    data = error.get("data")
    expect(isinstance(data, dict), "the version error carries no data object")
    if isinstance(data, dict):
        supported = data.get("supported")
        expect(
            isinstance(supported, list) and bool(supported),
            "the version error does not name the versions the server supports",
        )
        expect(data.get("requested") == "1999-01-01", "the version error does not echo the request")


async def legacy_initialize_is_answered(client: Client) -> None:
    """A legacy initialize MUST NOT be silently accepted."""
    payload = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": spec.LEGACY_INITIALIZE,
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}},
    }
    error = _error(await client.send(payload), method=spec.LEGACY_INITIALIZE)
    expect(
        error.get("code") == spec.UNSUPPORTED_PROTOCOL_VERSION,
        f"initialize returned {error.get('code')}, expected "
        f"{spec.UNSUPPORTED_PROTOCOL_VERSION} naming the supported revisions",
    )


async def unknown_method_is_method_not_found(client: Client) -> None:
    """An unknown method MUST return -32601."""
    error = _error(await client.send(_request("nope/nope")), method="nope/nope")
    expect(
        error.get("code") == spec.METHOD_NOT_FOUND,
        f"an unknown method returned {error.get('code')}, expected {spec.METHOD_NOT_FOUND}",
    )


async def unknown_tool_is_a_protocol_error(client: Client) -> None:
    """Calling a tool that was never published MUST be a protocol error."""
    error = _error(
        await client.send(
            _request(spec.TOOLS_CALL, params={"name": "no_such_tool", "arguments": {}})
        ),
        method=spec.TOOLS_CALL,
    )
    expect(
        error.get("code") == spec.INVALID_PARAMS,
        f"an unknown tool returned {error.get('code')}, expected {spec.INVALID_PARAMS}",
    )
    expect(
        error.get("code") not in spec.WITHDRAWN_CODES,
        f"the server emitted {error.get('code')}, a code this revision withdrew",
    )


async def malformed_envelope_is_invalid_request(client: Client) -> None:
    """A payload that is not a JSON-RPC request MUST return -32600."""
    error = _error(
        await client.send({"jsonrpc": "1.0", "id": 5, "method": spec.DISCOVER}),
        method="malformed",
    )
    expect(
        error.get("code") == spec.INVALID_REQUEST,
        f"a wrong jsonrpc version returned {error.get('code')}, expected {spec.INVALID_REQUEST}",
    )


async def error_codes_stay_out_of_the_reserved_range(client: Client) -> None:
    """A server MUST NOT invent codes inside the specification's reserved range."""
    low, high = spec.RESERVED_RANGE
    allowed = {
        spec.HEADER_MISMATCH,
        spec.MISSING_REQUIRED_CLIENT_CAPABILITY,
        spec.UNSUPPORTED_PROTOCOL_VERSION,
    }
    probes: list[dict[str, Any]] = [
        _request("nope/nope"),
        _request(spec.TOOLS_CALL, params={"name": "no_such_tool", "arguments": {}}),
        _request(spec.TOOLS_LIST, params={"cursor": "bad"}),
        _request(spec.DISCOVER, params={"_meta": _meta(version="1999-01-01")}),
        _request(spec.DISCOVER, params={"_meta": {spec.META_CLIENT_CAPABILITIES: {}}}),
        {"jsonrpc": "1.0", "id": 7, "method": spec.DISCOVER},
    ]
    for probe in probes:
        response = await client.send(probe)
        if response is None or "error" not in response:
            continue
        code = response["error"].get("code")
        if isinstance(code, int) and low <= code <= high:
            expect(
                code in allowed,
                f"the server emitted reserved code {code}, which this revision does not define",
            )
        expect(
            code not in spec.WITHDRAWN_CODES,
            f"the server emitted withdrawn code {code}",
        )


async def notifications_are_not_answered(client: Client) -> None:
    """A request without an id MUST NOT receive a response."""
    payload = _request(spec.DISCOVER, identifier=None)
    response = await client.send(payload)
    expect(response is None, f"a notification was answered with {response!r}")


async def tool_errors_are_results_not_protocol_errors(client: Client) -> None:
    """A tool that cannot do what was asked MUST return isError, not a JSON-RPC error."""
    result = _result(
        await client.send(
            _request(
                spec.TOOLS_CALL,
                params={
                    "name": "read_file",
                    "arguments": {"path": "../../etc/passwd"},
                },
            )
        ),
        method=spec.TOOLS_CALL,
    )
    expect(result.get("isError") is True, "a sandbox denial did not set isError")
    expect(result.get("resultType") == spec.RESULT_COMPLETE, "an error result has no resultType")
    content = result.get("content")
    expect(isinstance(content, list) and content, "an error result carries no content")


async def tool_call_returns_structured_content(client: Client) -> None:
    """A successful call returns both readable content and structured content."""
    result = _result(
        await client.send(
            _request(spec.TOOLS_CALL, params={"name": "project_overview", "arguments": {}})
        ),
        method=spec.TOOLS_CALL,
    )
    expect(result.get("isError") is False, f"project_overview failed: {result}")
    expect(isinstance(result.get("content"), list), "content is not a list")
    expect(isinstance(result.get("structuredContent"), dict), "structuredContent is not an object")
    for block in result.get("content", []):
        expect(isinstance(block, dict), "a content block is not an object")
        if isinstance(block, dict):
            expect(
                block.get("type")
                in {
                    spec.CONTENT_TEXT,
                    spec.CONTENT_IMAGE,
                    spec.CONTENT_AUDIO,
                    spec.CONTENT_RESOURCE_LINK,
                    spec.CONTENT_RESOURCE,
                },
                f"content block type {block.get('type')!r} is not a defined type",
            )


async def unknown_arguments_are_rejected(client: Client) -> None:
    """An argument the schema does not declare MUST be refused, not ignored."""
    error = _error(
        await client.send(
            _request(
                spec.TOOLS_CALL,
                params={
                    "name": "project_overview",
                    "arguments": {"definitely_not_an_argument": 1},
                },
            )
        ),
        method=spec.TOOLS_CALL,
    )
    expect(
        error.get("code") == spec.INVALID_PARAMS,
        f"an undeclared argument returned {error.get('code')}, expected {spec.INVALID_PARAMS}",
    )


async def requests_do_not_share_state(client: Client) -> None:
    """The server MUST NOT rely on prior requests on the same connection.

    Sent as an interleaved sequence with unrelated methods between two
    identical calls. If any per-connection state existed, the second call would
    have a chance to differ from the first.
    """
    first = _result(
        await client.send(_request(spec.TOOLS_LIST, identifier="a")), method=spec.TOOLS_LIST
    )
    await client.send(_request(spec.DISCOVER, identifier="b"))
    await client.send(
        _request(
            spec.TOOLS_CALL,
            identifier="c",
            params={"name": "project_overview", "arguments": {}},
        )
    )
    second = _result(
        await client.send(_request(spec.TOOLS_LIST, identifier="d")), method=spec.TOOLS_LIST
    )
    expect(
        first.get("tools") == second.get("tools"),
        "tools/list differed after unrelated requests, which means the server holds "
        "per-connection state",
    )


async def reserved_meta_prefix_is_rejected(client: Client) -> None:
    """A client MUST NOT invent keys under the specification's reserved prefix."""
    meta = _meta()
    meta["io.modelcontextprotocol/inventedByTheClient"] = True
    response = await client.send(_request(spec.DISCOVER, params={"_meta": meta}))
    expect(response is not None, "no response to a reserved _meta key")
    # Either rejected outright, or ignored. Both are defensible; silently
    # *acting* on it would not be, and there is no way to act on this one.
    if response is not None and "error" in response:
        expect(
            response["error"].get("code") == spec.INVALID_PARAMS,
            f"a reserved _meta key returned {response['error'].get('code')}",
        )


async def trace_context_is_accepted(client: Client) -> None:
    """Traceparent is explicitly exempt from the _meta prefix rules."""
    meta = _meta()
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    meta["traceparent"] = traceparent
    result = _result(
        await client.send(_request(spec.DISCOVER, params={"_meta": meta})), method=spec.DISCOVER
    )
    expect(result.get("resultType") == spec.RESULT_COMPLETE, "trace context broke discovery")


@dataclass(frozen=True, slots=True)
class Check:
    """One conformance check."""

    identifier: str
    level: str
    title: str
    run: Callable[[Client], Awaitable[None]]


#: The suite. Ordered so that a failure early on explains the failures after it:
#: a server that cannot answer ``server/discover`` will fail most of the rest,
#: and reading the report top-down should tell you why.
CHECKS: Final[tuple[Check, ...]] = (
    Check("C001", MUST, "server/discover is implemented", discover_is_implemented),
    Check("C002", SHOULD, "results carry serverInfo in _meta", discover_reports_server_info),
    Check("C003", SHOULD, "discovery declares a cache lifetime", discover_reports_caching),
    Check("C004", MUST, "every result carries resultType", every_result_carries_result_type),
    Check("C005", MUST, "tools/list returns valid Tool objects", tools_list_returns_valid_tools),
    Check("C006", SHOULD, "tools/list order is deterministic", tools_list_is_deterministic),
    Check("C007", MUST, "tools/list pagination terminates", tools_list_paginates),
    Check("C008", MUST, "an unissued cursor is rejected", bad_cursor_is_invalid_params),
    Check(
        "C009",
        MUST,
        "a request without a protocol version is rejected",
        missing_protocol_version_is_rejected,
    ),
    Check(
        "C010",
        MUST,
        "a request without clientCapabilities is rejected",
        missing_client_capabilities_is_rejected,
    ),
    Check(
        "C011",
        MUST,
        "an unsupported version returns -32022 and the supported list",
        unsupported_version_names_what_is_supported,
    ),
    Check(
        "C012", MUST, "a legacy initialize is answered, not ignored", legacy_initialize_is_answered
    ),
    Check("C013", MUST, "an unknown method returns -32601", unknown_method_is_method_not_found),
    Check("C014", MUST, "an unknown tool is a protocol error", unknown_tool_is_a_protocol_error),
    Check(
        "C015", MUST, "a malformed envelope returns -32600", malformed_envelope_is_invalid_request
    ),
    Check(
        "C016",
        MUST,
        "no error code invades the reserved range",
        error_codes_stay_out_of_the_reserved_range,
    ),
    Check("C017", MUST, "notifications receive no response", notifications_are_not_answered),
    Check(
        "C018",
        MUST,
        "tool failures are results, not protocol errors",
        tool_errors_are_results_not_protocol_errors,
    ),
    Check(
        "C019",
        MUST,
        "a successful call returns content and structuredContent",
        tool_call_returns_structured_content,
    ),
    Check("C020", MUST, "undeclared arguments are rejected", unknown_arguments_are_rejected),
    Check("C021", MUST, "requests do not share connection state", requests_do_not_share_state),
    Check(
        "C022", SHOULD, "reserved _meta prefixes are not honoured", reserved_meta_prefix_is_rejected
    ),
    Check("C023", MUST, "trace context in _meta is accepted", trace_context_is_accepted),
)
