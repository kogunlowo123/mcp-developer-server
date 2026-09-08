"""Constants taken directly from the Model Context Protocol specification.

Everything in this module is a transcription, not a design decision. It is kept
separate from the logic that uses it so that a specification revision is a diff
against one file, and so that the tests can assert on the specification's own
names rather than on strings scattered through the implementation.

Reference: Model Context Protocol, revision ``2026-07-28``.

The 2026-07-28 revision is a redesign rather than an increment. The differences
that shape this package:

* There is no ``initialize`` handshake. Every request carries its own protocol
  version and client capabilities in ``_meta``, and the server holds no
  per-connection state.
* ``server/discover`` is mandatory and replaces the handshake's role.
* Every result carries ``resultType``.
* The range ``-32020``..``-32099`` is reserved for specification-defined errors.
"""

from __future__ import annotations

import re
from typing import Final

# ---------------------------------------------------------------------------
# Protocol versions
# ---------------------------------------------------------------------------

#: The revision this server implements.
PROTOCOL_VERSION: Final[str] = "2026-07-28"

#: Every revision this server will serve, newest first. A request naming a
#: version that is not in this tuple is answered with ``UNSUPPORTED_PROTOCOL_VERSION``
#: and the tuple itself, so the client can retry without a second round trip.
#:
#: Only one entry: this server is modern-only. Legacy revisions (2025-11-25 and
#: earlier) used a stateful ``initialize`` handshake, and supporting both eras
#: would mean two dispatch paths, two capability models and two test suites for
#: no gain in a project whose subject is the sandbox. ARCHITECTURE.md ADR-002
#: records the decision; ``legacy_initialize_error`` in this package is the ten
#: lines that tell a legacy client what to do instead.
SUPPORTED_VERSIONS: Final[tuple[str, ...]] = (PROTOCOL_VERSION,)

#: Revisions that used the ``initialize`` handshake. A request for one of these
#: gets a version error naming what is supported, not a silent failure.
LEGACY_VERSIONS: Final[frozenset[str]] = frozenset(
    {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
)

# ---------------------------------------------------------------------------
# JSON-RPC
# ---------------------------------------------------------------------------

JSONRPC_VERSION: Final[str] = "2.0"

# Standard JSON-RPC 2.0 codes.
PARSE_ERROR: Final[int] = -32700
INVALID_REQUEST: Final[int] = -32600
METHOD_NOT_FOUND: Final[int] = -32601
INVALID_PARAMS: Final[int] = -32602
INTERNAL_ERROR: Final[int] = -32603

# Specification-defined codes introduced by 2026-07-28.
HEADER_MISMATCH: Final[int] = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY: Final[int] = -32021
UNSUPPORTED_PROTOCOL_VERSION: Final[int] = -32022

#: Inclusive bounds of the range the specification reserves for itself. An
#: implementation MUST NOT invent codes inside it; ``tests/conformance`` asserts
#: that every code this server can emit is either a standard JSON-RPC code or one
#: of the three named above.
RESERVED_RANGE: Final[tuple[int, int]] = (-32099, -32020)

#: Codes from earlier revisions that MUST NOT be emitted any more. ``-32002``
#: was "resource not found" and ``-32042`` was "request too large"; both are now
#: ``INVALID_PARAMS`` with a message. Named here so a test can prove they never
#: leave the server.
WITHDRAWN_CODES: Final[frozenset[int]] = frozenset({-32002, -32042})

# ---------------------------------------------------------------------------
# _meta
# ---------------------------------------------------------------------------

META_PREFIX: Final[str] = "io.modelcontextprotocol/"

#: Required on every request.
META_PROTOCOL_VERSION: Final[str] = META_PREFIX + "protocolVersion"
META_CLIENT_CAPABILITIES: Final[str] = META_PREFIX + "clientCapabilities"

#: Optional on a request.
META_CLIENT_INFO: Final[str] = META_PREFIX + "clientInfo"
META_LOG_LEVEL: Final[str] = META_PREFIX + "logLevel"

#: The specification says servers SHOULD attach this to every result.
META_SERVER_INFO: Final[str] = META_PREFIX + "serverInfo"

#: ``_meta`` keys are ``[prefix/]name``. The prefix is a dot-separated label
#: sequence; the name is a token. Both are constrained so that keys stay
#: unambiguous across implementations.
META_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<prefix>[A-Za-z0-9][A-Za-z0-9._-]*)/)?(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)$"
)

#: Any prefix whose second label is one of these is reserved to the
#: specification. ``io.modelcontextprotocol`` and ``x.mcp`` are both reserved;
#: ``com.example`` is not.
RESERVED_SECOND_LABELS: Final[frozenset[str]] = frozenset({"modelcontextprotocol", "mcp"})

#: W3C trace context propagates through ``_meta`` under bare keys, which the
#: reservation rules explicitly exempt.
TRACE_CONTEXT_KEYS: Final[frozenset[str]] = frozenset({"traceparent", "tracestate", "baggage"})

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

#: Every result carries ``resultType``. A client that receives a result without
#: one MUST treat it as complete, which means a server that omits it fails
#: silently rather than loudly — so this server always sets it, and a
#: conformance test asserts it across every method.
RESULT_COMPLETE: Final[str] = "complete"
RESULT_INPUT_REQUIRED: Final[str] = "input_required"
RESULT_TYPES: Final[frozenset[str]] = frozenset({RESULT_COMPLETE, RESULT_INPUT_REQUIRED})

# ---------------------------------------------------------------------------
# Methods
# ---------------------------------------------------------------------------

DISCOVER: Final[str] = "server/discover"
TOOLS_LIST: Final[str] = "tools/list"
TOOLS_CALL: Final[str] = "tools/call"

#: The method a legacy client sends first. Answered with a version error.
LEGACY_INITIALIZE: Final[str] = "initialize"

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

#: Tool names are 1-128 characters of ``[A-Za-z0-9_.-]``.
TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

#: The JSON Schema dialect assumed when a schema does not declare ``$schema``.
DEFAULT_SCHEMA_DIALECT: Final[str] = "https://json-schema.org/draft/2020-12/schema"

CONTENT_TEXT: Final[str] = "text"
CONTENT_IMAGE: Final[str] = "image"
CONTENT_AUDIO: Final[str] = "audio"
CONTENT_RESOURCE_LINK: Final[str] = "resource_link"
CONTENT_RESOURCE: Final[str] = "resource"
