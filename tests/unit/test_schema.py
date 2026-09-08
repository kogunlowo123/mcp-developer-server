"""The bounded JSON Schema validator, and the ``$ref`` guard."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_devserver.errors import ConfigurationError, InvalidParamsError
from mcp_devserver.protocol.schema import MAX_DEPTH, assert_safe, validate

pytestmark = pytest.mark.unit


def obj(properties: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "additionalProperties": False, **extra}


class TestSafetyGuard:
    def test_a_network_ref_is_refused_at_registration(self):
        # Resolving this would be a server-side request forgery primitive
        # reachable from any client.
        schema = obj({"x": {"$ref": "https://attacker.example/schema.json"}})
        with pytest.raises(ConfigurationError, match="never dereferences a network URI"):
            assert_safe(schema, where="test")

    def test_a_file_ref_is_refused(self):
        schema = obj({"x": {"$ref": "file:///etc/passwd"}})
        with pytest.raises(ConfigurationError, match=r"\$ref"):
            assert_safe(schema, where="test")

    def test_a_local_defs_ref_is_allowed(self):
        schema = obj({"x": {"$ref": "#/$defs/name"}}, **{"$defs": {"name": {"type": "string"}}})
        assert_safe(schema, where="test")

    def test_an_unimplemented_keyword_is_refused(self):
        # A keyword the validator does not implement is a constraint that would
        # not be enforced, so it must never reach a published schema.
        with pytest.raises(ConfigurationError, match="does not implement"):
            assert_safe(obj({"x": {"type": "string", "allOf": []}}), where="test")

    def test_a_schema_deeper_than_the_limit_is_refused(self):
        schema: dict[str, Any] = {"type": "string"}
        for _ in range(MAX_DEPTH + 4):
            schema = obj({"child": schema})
        with pytest.raises(ConfigurationError, match="nests deeper"):
            assert_safe(schema, where="test")


class TestTypes:
    def test_a_string_where_an_integer_is_declared(self):
        with pytest.raises(InvalidParamsError, match="must be a integer"):
            validate({"n": "5"}, obj({"n": {"type": "integer"}}))

    def test_a_boolean_does_not_satisfy_integer(self):
        # `True` is an int in Python. A validator that used isinstance alone
        # would accept `{"limit": true}` and run with a limit of 1.
        with pytest.raises(InvalidParamsError, match="not a boolean"):
            validate({"n": True}, obj({"n": {"type": "integer"}}))

    def test_an_integer_satisfies_number(self):
        validate({"n": 3}, obj({"n": {"type": "number"}}))

    def test_null_is_its_own_type(self):
        validate({"n": None}, obj({"n": {"type": "null"}}))


class TestObjects:
    def test_a_missing_required_property(self):
        with pytest.raises(InvalidParamsError, match="missing required property: path"):
            validate({}, obj({"path": {"type": "string"}}, required=["path"]))

    def test_several_missing_required_properties_are_named_together(self):
        schema = obj({"a": {"type": "string"}, "b": {"type": "string"}}, required=["a", "b"])
        with pytest.raises(InvalidParamsError, match="missing required properties: a, b"):
            validate({}, schema)

    def test_an_undeclared_property_is_refused(self):
        # Usually a typo in the name of a real argument. Accepting it means the
        # call silently runs with a default the caller did not intend.
        with pytest.raises(InvalidParamsError, match="does not accept: pth"):
            validate({"pth": "x"}, obj({"path": {"type": "string"}}))

    def test_nested_objects_are_validated(self):
        schema = obj({"inner": obj({"n": {"type": "integer"}})})
        with pytest.raises(InvalidParamsError, match=r"arguments\.inner\.n"):
            validate({"inner": {"n": "no"}}, schema)


class TestConstraints:
    def test_enum(self):
        with pytest.raises(InvalidParamsError, match="must be one of"):
            validate({"k": "nope"}, obj({"k": {"type": "string", "enum": ["a", "b"]}}))

    def test_const(self):
        with pytest.raises(InvalidParamsError, match="must equal"):
            validate({"k": 2}, obj({"k": {"const": 1}}))

    def test_string_bounds_and_pattern(self):
        schema = obj({"k": {"type": "string", "minLength": 2, "maxLength": 4, "pattern": "^a"}})
        validate({"k": "abc"}, schema)
        with pytest.raises(InvalidParamsError, match="at least 2 characters"):
            validate({"k": "a"}, schema)
        with pytest.raises(InvalidParamsError, match="at most 4 characters"):
            validate({"k": "abcde"}, schema)
        with pytest.raises(InvalidParamsError, match="must match"):
            validate({"k": "bcd"}, schema)

    def test_number_bounds(self):
        schema = obj({"k": {"type": "integer", "minimum": 1, "maximum": 10}})
        validate({"k": 5}, schema)
        with pytest.raises(InvalidParamsError, match="at least 1"):
            validate({"k": 0}, schema)
        with pytest.raises(InvalidParamsError, match="at most 10"):
            validate({"k": 11}, schema)

    def test_array_bounds_items_and_uniqueness(self):
        schema = obj(
            {
                "k": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 2,
                    "uniqueItems": True,
                }
            }
        )
        validate({"k": ["a"]}, schema)
        with pytest.raises(InvalidParamsError, match="at least 1 items"):
            validate({"k": []}, schema)
        with pytest.raises(InvalidParamsError, match="at most 2 items"):
            validate({"k": ["a", "b", "c"]}, schema)
        with pytest.raises(InvalidParamsError, match="duplicate"):
            validate({"k": ["a", "a"]}, schema)
        with pytest.raises(InvalidParamsError, match=r"arguments\.k\[0\]"):
            validate({"k": [1]}, schema)


class TestReferences:
    def test_a_local_reference_is_resolved(self):
        schema = obj(
            {"k": {"$ref": "#/$defs/word"}},
            **{"$defs": {"word": {"type": "string", "minLength": 2}}},
        )
        validate({"k": "ok"}, schema)
        with pytest.raises(InvalidParamsError, match="at least 2 characters"):
            validate({"k": "x"}, schema)

    def test_an_unresolvable_reference_is_an_error_not_a_silent_pass(self):
        schema = obj({"k": {"$ref": "#/$defs/missing"}}, **{"$defs": {}})
        with pytest.raises(InvalidParamsError, match="could not be resolved"):
            validate({"k": "x"}, schema)


class TestInstanceDepth:
    def test_a_deeply_nested_instance_is_refused(self):
        # The schema is shallow but recursive through $defs, so the *instance*
        # is what drives the depth. A validator without an instance bound would
        # recurse until Python's stack gave out.
        schema: dict[str, Any] = {
            "type": "object",
            "properties": {"child": {"$ref": "#/$defs/node"}},
            "additionalProperties": False,
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {"child": {"$ref": "#/$defs/node"}},
                    "additionalProperties": False,
                }
            },
        }
        instance: dict[str, Any] = {}
        for _ in range(MAX_DEPTH + 4):
            instance = {"child": instance}
        with pytest.raises(InvalidParamsError, match="nests deeper"):
            validate(instance, schema)
