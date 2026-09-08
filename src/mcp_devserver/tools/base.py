"""Tool declarations, the registry that publishes them, and the result they return.

The shape of a tool here is a small dataclass plus a plain function, rather than
a decorator that hides registration. The reason is auditability: ``tools/list``
must return exactly the set of things this server can be asked to do, and a
reviewer should be able to read that set in one place and be sure there is not an
eleventh tool registered by an import side effect somewhere.

Every tool in this server is **read-only**. There is no tool that writes a file,
creates a process from caller-supplied text, or reaches the network. That is a
property of the set, not a promise in a docstring, and ``tests/security`` asserts
it by inspecting the registry.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from mcp_devserver.errors import (
    InvalidParamsError,
    ToolExecutionError,
)
from mcp_devserver.protocol import schema as schema_module
from mcp_devserver.protocol import spec
from mcp_devserver.sandbox.workspace import Workspace
from mcp_devserver.security.redaction import Redactor
from mcp_devserver.security.untrusted import (
    Assessment,
    UntrustedContentScanner,
    fence,
    new_nonce,
)


@dataclass(frozen=True, slots=True)
class Limits:
    """Every bound a tool run is subject to.

    Bounds are values rather than constants so that a deployment can tighten
    them, and so that the tests can set a limit low enough to hit deliberately
    instead of building a two-gigabyte fixture.
    """

    max_file_bytes: int = 1_048_576
    max_read_lines: int = 4_000
    max_search_results: int = 200
    max_search_files: int = 20_000
    max_result_bytes: int = 262_144
    max_directory_entries: int = 1_000
    max_git_entries: int = 200
    tool_timeout_seconds: float = 15.0


@dataclass(slots=True)
class ToolContext:
    """What a tool handler is given.

    Constructed per request. It holds no reference to any earlier request, which
    is what makes the statelessness requirement a property of the type rather
    than a rule to remember.
    """

    workspace: Workspace
    limits: Limits
    redactor: Redactor
    scanner: UntrustedContentScanner
    nonce: str = field(default_factory=new_nonce)
    started_at: float = field(default_factory=time.monotonic)

    def deadline_exceeded(self) -> bool:
        """Whether this call has used its whole time budget."""
        return (time.monotonic() - self.started_at) >= self.limits.tool_timeout_seconds

    def remaining_seconds(self) -> float:
        """Seconds left in the budget, never negative."""
        return max(0.0, self.limits.tool_timeout_seconds - (time.monotonic() - self.started_at))


@dataclass(frozen=True, slots=True)
class ToolResult:
    """What a handler returns, before it becomes a ``CallToolResult``.

    ``content`` is what a model reads; ``structured`` is what a program reads.
    Both are produced for every tool, because a client that has to parse prose
    to find a line number is a client that will parse it wrongly.
    """

    text: str
    structured: dict[str, Any]
    #: Content that came from files rather than from this server. It is fenced
    #: and scanned; it is never rewritten. See ``security/untrusted.py``.
    untrusted: str = ""
    untrusted_label: str = "file-content"

    def render(self, context: ToolContext) -> dict[str, Any]:
        """Build the ``CallToolResult`` members for a successful call.

        The order below is the whole of the correctness here, and it was wrong
        once: everything is *assembled* first, and redaction runs over the
        finished structure last. Redacting an input and then attaching something
        derived from the un-redacted original — a scanner excerpt, say — leaves a
        credential in the result even though the pass "ran". A single pass over
        the assembled object closes that for anything added here in future, not
        only for what is added today.

        The one thing deliberately outside that pass is the *scan*, which runs
        against the content exactly as it is on disk. Scanning redacted text
        would miss an injected instruction that happened to sit beside a
        credential.
        """
        blocks: list[dict[str, Any]] = []
        structured: dict[str, Any] = dict(self.structured)

        if self.text:
            blocks.append({"type": spec.CONTENT_TEXT, "text": self.text})

        if self.untrusted:
            assessment: Assessment = context.scanner.scan(self.untrusted)
            structured["untrusted_content"] = True
            structured["content_assessment"] = assessment.as_dict()
            blocks.append(
                {
                    "type": spec.CONTENT_TEXT,
                    "text": fence(
                        self.untrusted,
                        nonce=context.nonce,
                        label=self.untrusted_label,
                    ),
                }
            )

        redacted_blocks, block_redaction = _redact_structure(blocks, context)
        redacted_structured, structured_redaction = _redact_structure(structured, context)

        count = block_redaction[0] + structured_redaction[0]
        rules = block_redaction[1] | structured_redaction[1]

        # Attached after the pass, and safe to be: it names rules, never values.
        redacted_structured["redaction"] = {
            "applied": count > 0,
            "count": count,
            "rules": sorted(rules),
        }

        return {
            "resultType": spec.RESULT_COMPLETE,
            "content": redacted_blocks,
            "structuredContent": redacted_structured,
            "isError": False,
        }


def _redact_structure(value: Any, context: ToolContext) -> tuple[Any, tuple[int, set[str]]]:
    """Redact every string inside a structured result, returning what fired.

    Walks the structure rather than serialising it: redacting a JSON dump and
    re-parsing it would mangle any value that happened to contain a quote, and
    would redact keys as well as values.
    """
    if isinstance(value, str):
        outcome = context.redactor.apply(value)
        return outcome.text, (outcome.count, set(outcome.rules))
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        count = 0
        rules: set[str] = set()
        for key, item in value.items():
            redacted, (fired, names) = _redact_structure(item, context)
            result[key] = redacted
            count += fired
            rules |= names
        return result, (count, rules)
    if isinstance(value, list):
        items: list[Any] = []
        count = 0
        rules = set()
        for item in value:
            redacted, (fired, names) = _redact_structure(item, context)
            items.append(redacted)
            count += fired
            rules |= names
        return items, (count, rules)
    return value, (0, set())


def error_result(failure: ToolExecutionError) -> dict[str, Any]:
    """Build the ``CallToolResult`` members for a failed call.

    ``isError`` rather than a JSON-RPC error, because the model asked a
    reasonable question and the answer is a refusal it can act on. A denial
    delivered as a transport failure never reaches the model that needs to learn
    from it.
    """
    return {
        "resultType": spec.RESULT_COMPLETE,
        "content": [{"type": spec.CONTENT_TEXT, "text": failure.to_text()}],
        "structuredContent": failure.to_structured(),
        "isError": True,
    }


#: A handler is synchronous. Filesystem work is synchronous, and pretending
#: otherwise with an ``async def`` that never awaits would put blocking I/O on
#: the event loop. The dispatcher runs handlers in a worker thread instead.
type Handler = Callable[[ToolContext, Mapping[str, Any]], ToolResult]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One published tool.

    ``annotations`` carries the specification's behavioural hints. Every tool
    here sets ``readOnlyHint`` true and ``destructiveHint`` false, and a test
    asserts it, so the hints describe the code rather than aspiring to.
    """

    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler: Handler
    #: Whether the tool can return bytes that originated in a file. Used by the
    #: audit log and by the security tests, which assert that every tool
    #: returning file bytes marks them.
    returns_file_content: bool = False

    def __post_init__(self) -> None:
        """Refuse a tool whose name or schemas the server must not publish."""
        if not spec.TOOL_NAME_PATTERN.match(self.name):
            raise ValueError(f"tool name {self.name!r} is not 1-128 characters of [A-Za-z0-9_.-]")
        schema_module.assert_safe(self.input_schema, where=f"{self.name}.inputSchema")
        schema_module.assert_safe(self.output_schema, where=f"{self.name}.outputSchema")

    def declaration(self) -> dict[str, Any]:
        """Render the ``Tool`` object for ``tools/list``."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                # False: results describe files on disk, which change.
                "openWorldHint": False,
            },
        }


def object_schema(
    properties: dict[str, Any],
    *,
    required: Iterable[str] = (),
    description: str = "",
) -> dict[str, Any]:
    """Build an object schema with the members every published schema needs.

    ``additionalProperties: false`` on every published schema is not
    boilerplate. Without it a typo in an argument name is accepted and the tool
    runs with a default, which is the quiet kind of wrong.
    """
    document: dict[str, Any] = {
        "$schema": spec.DEFAULT_SCHEMA_DIALECT,
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        document["required"] = sorted(required)
    if description:
        document["description"] = description
    return document


#: The schema for a tool that takes nothing. The specification is explicit that
#: this is an object schema with no properties, not an omitted field.
NO_ARGUMENTS: Final[dict[str, Any]] = object_schema({})


class ToolRegistry:
    """The published set of tools.

    Registration is explicit and duplicate names are refused. ``list`` is sorted
    by name: the specification recommends a deterministic order so that clients
    can cache the listing and so that a prompt containing it stays stable across
    calls, which is the difference between a warm prompt cache and a cold one.
    """

    def __init__(self, tools: Iterable[ToolSpec] = ()) -> None:
        self._tools: dict[str, ToolSpec] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: ToolSpec) -> None:
        """Add a tool, refusing a name that is already taken."""
        if tool.name in self._tools:
            raise ValueError(f"tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool

    def __contains__(self, name: object) -> bool:
        """Whether a tool of this name is registered."""
        return name in self._tools

    def __len__(self) -> int:
        """How many tools are registered."""
        return len(self._tools)

    def names(self) -> tuple[str, ...]:
        """Every registered name, in the published order."""
        return tuple(sorted(self._tools))

    def get(self, name: str) -> ToolSpec:
        """Look up a tool, raising a protocol error when it is not registered.

        A protocol error, not a tool error: the client asked for something that
        was never advertised, and no argument change would make it work.
        """
        try:
            return self._tools[name]
        except KeyError:
            raise InvalidParamsError(
                f"unknown tool {name!r}; call tools/list to see what this server publishes"
            ) from None

    def declarations(self) -> list[dict[str, Any]]:
        """Render every ``Tool`` object, in the published order."""
        return [self._tools[name].declaration() for name in sorted(self._tools)]

    def specs(self) -> tuple[ToolSpec, ...]:
        """Every spec, in the published order."""
        return tuple(self._tools[name] for name in sorted(self._tools))

    def invoke(
        self, name: str, arguments: Mapping[str, Any], context: ToolContext
    ) -> dict[str, Any]:
        """Validate arguments and run one tool, converting failures to results."""
        tool = self.get(name)
        schema_module.validate(dict(arguments), tool.input_schema)
        try:
            return tool.handler(context, arguments).render(context)
        except ToolExecutionError as failure:
            return error_result(failure)
