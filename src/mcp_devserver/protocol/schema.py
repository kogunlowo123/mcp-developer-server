"""A small, bounded JSON Schema validator, and the guard that keeps it bounded.

Two jobs, and they are separate on purpose.

**Validating arguments.** Every tool publishes an ``inputSchema``, and the
specification requires servers to validate tool inputs. This module implements
the subset of Draft 2020-12 the published schemas actually use: objects with
typed properties, ``required``, ``enum``, ``additionalProperties: false``,
numeric bounds, string length and pattern, and homogeneous arrays. Nothing more.

A subset validator is a deliberate choice over a dependency. The schemas here
are written in this repository and reviewed with the tools; a full
implementation would add a package whose feature surface is far larger than what
is used, and the interesting failure — a tool that accepts an argument it should
have refused — is exactly what the tests can pin against a small validator they
can read. What the validator does *not* support, it rejects loudly at
registration rather than ignoring at request time: an unsupported keyword in a
published schema fails the server's own start-up self-check, so a schema can
never silently validate nothing.

**Guarding ``$ref``.** The specification is explicit that ``$ref`` MUST NOT be
resolved against network URIs by default, and that schema composition needs
bounds. A validator that fetched ``$ref: "https://attacker.example/s.json"``
would be a server-side request forgery primitive reachable from any client, and
one that recursed without a depth bound would be a denial of service. This
module resolves nothing but local ``#/$defs`` pointers, refuses any other
``$ref`` outright, and caps nesting depth.
"""

from __future__ import annotations

import re
from typing import Any, Final

from mcp_devserver.errors import ConfigurationError, InvalidParamsError

#: The deepest a schema or an instance may nest. Beyond this the validator
#: refuses rather than recursing: a JSON document is attacker-controlled input
#: and Python's recursion limit is not a security boundary.
MAX_DEPTH: Final[int] = 12

#: Keywords this validator understands. Anything else in a registered schema is
#: a configuration error, not a silently-ignored constraint.
SUPPORTED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "$defs",
        "$ref",
        "title",
        "description",
        "default",
        "examples",
        "type",
        "enum",
        "const",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
    }
)

_TYPES: Final[dict[str, type | tuple[type, ...]]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def assert_safe(schema: dict[str, Any], *, where: str) -> None:
    """Reject a schema this server must not publish or evaluate.

    Called at registration, so a bad schema stops the process rather than
    surviving until a request reaches it.
    """
    _walk(schema, where=where, depth=0)


def _walk(node: object, *, where: str, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ConfigurationError(f"schema for {where} nests deeper than {MAX_DEPTH} levels")
    if isinstance(node, list):
        for item in node:
            _walk(item, where=where, depth=depth + 1)
        return
    if not isinstance(node, dict):
        return

    reference = node.get("$ref")
    if reference is not None and (
        not isinstance(reference, str) or not reference.startswith("#/$defs/")
    ):
        raise ConfigurationError(
            f"schema for {where} contains $ref {reference!r}; this server resolves only "
            "local '#/$defs/...' pointers and never dereferences a network URI"
        )

    for keyword, value in node.items():
        if keyword in {"properties", "$defs"}:
            if not isinstance(value, dict):
                raise ConfigurationError(f"schema for {where}: {keyword!r} must be an object")
            for child in value.values():
                _walk(child, where=where, depth=depth + 1)
            continue
        if keyword not in SUPPORTED_KEYWORDS:
            raise ConfigurationError(
                f"schema for {where} uses {keyword!r}, which this validator does not implement; "
                "a keyword that is not implemented would be a constraint that is not enforced"
            )
        _walk(value, where=where, depth=depth + 1)


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if not isinstance(reference, str):
        return schema
    pointer = reference.removeprefix("#/$defs/")
    definitions = root.get("$defs")
    if not isinstance(definitions, dict) or pointer not in definitions:
        raise InvalidParamsError(f"schema reference {reference!r} could not be resolved")
    target = definitions[pointer]
    if not isinstance(target, dict):
        raise InvalidParamsError(f"schema reference {reference!r} does not name an object")
    return target


def validate(instance: object, schema: dict[str, Any], *, path: str = "") -> None:
    """Validate an instance, raising :class:`InvalidParamsError` on the first failure.

    A protocol error rather than a tool error: arguments that do not match a
    published schema are a client mistake, and the client — not the model —
    is the party that can fix them.
    """
    _validate(instance, schema, root=schema, path=path or "arguments", depth=0)


def _fail(path: str, detail: str) -> InvalidParamsError:
    return InvalidParamsError(f"{path} {detail}")


def _validate(
    instance: object,
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: str,
    depth: int,
) -> None:
    if depth > MAX_DEPTH:
        raise _fail(path, f"nests deeper than the {MAX_DEPTH}-level limit")

    schema = _resolve(schema, root)

    expected = schema.get("type")
    if isinstance(expected, str):
        python_type = _TYPES.get(expected)
        if python_type is None:
            raise _fail(path, f"declares unknown type {expected!r}")
        # JSON has no boolean/integer overlap; Python does, and `True` passing
        # an integer check is a real source of accepted-but-wrong arguments.
        if expected in {"integer", "number"} and isinstance(instance, bool):
            raise _fail(path, f"must be a {expected}, not a boolean")
        if not isinstance(instance, python_type):
            raise _fail(path, f"must be a {expected}")

    if "const" in schema and instance != schema["const"]:
        raise _fail(path, f"must equal {schema['const']!r}")

    allowed = schema.get("enum")
    if isinstance(allowed, list) and instance not in allowed:
        rendered = ", ".join(repr(value) for value in allowed)
        raise _fail(path, f"must be one of: {rendered}")

    if isinstance(instance, str):
        _validate_string(instance, schema, path=path)
    elif isinstance(instance, int | float) and not isinstance(instance, bool):
        _validate_number(instance, schema, path=path)
    elif isinstance(instance, list):
        _validate_array(instance, schema, root=root, path=path, depth=depth)
    elif isinstance(instance, dict):
        _validate_object(instance, schema, root=root, path=path, depth=depth)


def _validate_string(instance: str, schema: dict[str, Any], *, path: str) -> None:
    minimum = schema.get("minLength")
    if isinstance(minimum, int) and len(instance) < minimum:
        raise _fail(path, f"must be at least {minimum} characters")
    maximum = schema.get("maxLength")
    if isinstance(maximum, int) and len(instance) > maximum:
        raise _fail(path, f"must be at most {maximum} characters")
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, instance) is None:
        raise _fail(path, f"must match {pattern!r}")


def _validate_number(instance: float, schema: dict[str, Any], *, path: str) -> None:
    minimum = schema.get("minimum")
    if isinstance(minimum, int | float) and instance < minimum:
        raise _fail(path, f"must be at least {minimum}")
    maximum = schema.get("maximum")
    if isinstance(maximum, int | float) and instance > maximum:
        raise _fail(path, f"must be at most {maximum}")


def _validate_array(
    instance: list[Any],
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: str,
    depth: int,
) -> None:
    minimum = schema.get("minItems")
    if isinstance(minimum, int) and len(instance) < minimum:
        raise _fail(path, f"must have at least {minimum} items")
    maximum = schema.get("maxItems")
    if isinstance(maximum, int) and len(instance) > maximum:
        raise _fail(path, f"must have at most {maximum} items")
    if schema.get("uniqueItems") is True:
        rendered = [repr(item) for item in instance]
        if len(set(rendered)) != len(rendered):
            raise _fail(path, "must not contain duplicate items")
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for index, item in enumerate(instance):
            _validate(item, item_schema, root=root, path=f"{path}[{index}]", depth=depth + 1)


def _validate_object(
    instance: dict[str, Any],
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: str,
    depth: int,
) -> None:
    properties = schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}

    required = schema.get("required")
    if isinstance(required, list):
        missing = [name for name in required if name not in instance]
        if missing:
            rendered = ", ".join(sorted(str(name) for name in missing))
            noun = "properties" if len(missing) > 1 else "property"
            raise _fail(path, f"is missing required {noun}: {rendered}")

    if schema.get("additionalProperties") is False:
        unexpected = sorted(set(instance) - set(properties))
        if unexpected:
            rendered = ", ".join(unexpected)
            # Named rather than ignored: an unknown argument is usually a typo
            # in the name of a real one, and accepting it means the call runs
            # with a default the caller did not intend.
            raise _fail(path, f"has properties this tool does not accept: {rendered}")

    for name, child in properties.items():
        if name in instance and isinstance(child, dict):
            _validate(instance[name], child, root=root, path=f"{path}.{name}", depth=depth + 1)
