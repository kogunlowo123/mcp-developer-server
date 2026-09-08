"""The ``_meta`` member: what every request must carry, and what every result returns.

In revision 2026-07-28 there is no handshake. The consequence is that ``_meta``
is not decoration — it is the whole of the negotiation, repeated on every
request, and a server that reads it loosely has no negotiation at all.

Three things are checked here, in this order, because the order determines which
error a client sees:

1. **Key syntax.** Reserved prefixes may not be invented by a client.
2. **Protocol version.** A version this server cannot serve is answered with the
   list of versions it can, so the client can retry immediately.
3. **Client capabilities.** Required, and required to be an object. A client
   that declares nothing declares an empty object; a client that omits the field
   has sent a malformed request.

Version before capabilities is deliberate: a client speaking a revision this
server does not implement may well have a different capability model, and
telling it "your capabilities are wrong" would be misleading.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from mcp_devserver.errors import (
    HeaderMismatchError,
    InvalidParamsError,
    MissingRequiredClientCapabilityError,
    UnsupportedProtocolVersionError,
)
from mcp_devserver.protocol import spec

#: The reservation rule looks at the *second* label of a prefix, counting from
#: zero: ``io.modelcontextprotocol`` is reserved, ``com.example`` is not.
_RESERVED_LABEL_POSITION: Final[int] = 1


@dataclass(frozen=True, slots=True)
class ClientInfo:
    """Optional client identification. Advisory: nothing is authorised by it."""

    name: str = ""
    version: str = ""
    title: str = ""

    @classmethod
    def parse(cls, raw: object) -> ClientInfo:
        """Read a ``clientInfo`` object, ignoring members that are not strings.

        Lenient on purpose. ``clientInfo`` is optional and advisory; rejecting a
        request because a client sent a number where a name was expected would
        fail a request over a field that grants nothing.
        """
        if not isinstance(raw, dict):
            return cls()
        return cls(
            name=raw.get("name", "") if isinstance(raw.get("name"), str) else "",
            version=raw.get("version", "") if isinstance(raw.get("version"), str) else "",
            title=raw.get("title", "") if isinstance(raw.get("title"), str) else "",
        )

    def label(self) -> str:
        """Render a short identifier for logs. Never used for a security decision."""
        if not self.name:
            return "unidentified"
        return f"{self.name}/{self.version}" if self.version else self.name


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Everything the per-request negotiation established.

    This is the only state a handler receives, and it is derived entirely from
    the request in hand. Nothing here can come from an earlier request, which is
    what makes the statelessness requirement structural rather than a promise.
    """

    protocol_version: str
    capabilities: frozenset[str]
    client: ClientInfo = field(default_factory=ClientInfo)
    log_level: str = ""
    trace: dict[str, str] = field(default_factory=dict)

    def require(self, *capabilities: str) -> None:
        """Assert that the client declared every named capability."""
        missing = {name for name in capabilities if name not in self.capabilities}
        if missing:
            raise MissingRequiredClientCapabilityError(*missing)


def _validate_key(key: str) -> None:
    """Reject a ``_meta`` key a client is not allowed to use.

    The reservation rule is about the *second* label of the prefix, not the
    first: ``io.modelcontextprotocol/x`` and ``x.mcp/y`` are both reserved,
    while ``com.example/z`` is not. Trace-context keys are bare and exempt.
    """
    if key in spec.TRACE_CONTEXT_KEYS:
        return

    match = spec.META_KEY_PATTERN.match(key)
    if match is None:
        raise InvalidParamsError(f"_meta key {key!r} is not a valid meta key")

    prefix = match.group("prefix")
    if prefix is None:
        return
    labels = prefix.split(".")
    reserved = len(labels) >= _RESERVED_LABEL_POSITION + 1 and (
        labels[_RESERVED_LABEL_POSITION] in spec.RESERVED_SECOND_LABELS
    )
    if reserved and not key.startswith(spec.META_PREFIX):
        raise InvalidParamsError(f"_meta key {key!r} uses a prefix reserved by the specification")


def parse_context(
    meta: dict[str, Any],
    *,
    header_version: str | None = None,
) -> RequestContext:
    """Validate ``_meta`` and derive the request context.

    ``header_version`` is the transport-level protocol version, when the
    transport has one. HTTP does; stdio does not. When both are present they
    must agree: a proxy that rewrites the header without rewriting the body
    would otherwise silently change which revision the exchange is conducted in,
    and the specification requires that be an error rather than a preference.
    """
    for key in meta:
        _validate_key(key)

    version = meta.get(spec.META_PROTOCOL_VERSION)
    if not isinstance(version, str) or not version:
        raise InvalidParamsError(
            f"_meta must include {spec.META_PROTOCOL_VERSION!r} as a non-empty string; "
            "this revision negotiates per request and has no initialize handshake"
        )

    if header_version is not None and header_version != version:
        raise HeaderMismatchError(
            "the protocol version in the transport header does not match the one in _meta",
            data={"header": header_version, "meta": version},
        )

    if version not in spec.SUPPORTED_VERSIONS:
        raise UnsupportedProtocolVersionError(version)

    raw_capabilities = meta.get(spec.META_CLIENT_CAPABILITIES)
    if not isinstance(raw_capabilities, dict):
        raise InvalidParamsError(
            f"_meta must include {spec.META_CLIENT_CAPABILITIES!r} as an object; "
            "a client with no capabilities sends an empty object, not nothing"
        )

    log_level = meta.get(spec.META_LOG_LEVEL)
    trace = {
        key: value
        for key, value in meta.items()
        if key in spec.TRACE_CONTEXT_KEYS and isinstance(value, str)
    }

    return RequestContext(
        protocol_version=version,
        capabilities=frozenset(raw_capabilities),
        client=ClientInfo.parse(meta.get(spec.META_CLIENT_INFO)),
        log_level=log_level if isinstance(log_level, str) else "",
        trace=trace,
    )


def server_info(name: str, version: str, title: str = "") -> dict[str, Any]:
    """Build the ``serverInfo`` object attached to every result."""
    info: dict[str, Any] = {"name": name, "version": version}
    if title:
        info["title"] = title
    return info


def result_meta(info: dict[str, Any], context: RequestContext | None = None) -> dict[str, Any]:
    """Build a result's ``_meta``.

    Trace context is echoed when the client sent it, so that a client
    correlating a response to a span does not have to hold the request open.
    """
    meta: dict[str, Any] = {spec.META_SERVER_INFO: info}
    if context is not None:
        meta.update(context.trace)
    return meta
