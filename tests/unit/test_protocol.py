"""JSON-RPC envelopes, ``_meta`` negotiation, and the specification constants."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_devserver.errors import (
    HeaderMismatchError,
    InvalidParamsError,
    InvalidRequestError,
    MissingRequiredClientCapabilityError,
    ParseError,
    UnsupportedProtocolVersionError,
)
from mcp_devserver.protocol import jsonrpc, spec
from mcp_devserver.protocol.meta import ClientInfo, parse_context, result_meta, server_info

pytestmark = pytest.mark.unit


class TestSpecConstants:
    def test_the_reserved_range_is_ordered_and_contains_the_defined_codes(self):
        low, high = spec.RESERVED_RANGE
        assert low < high
        for code in (
            spec.HEADER_MISMATCH,
            spec.MISSING_REQUIRED_CLIENT_CAPABILITY,
            spec.UNSUPPORTED_PROTOCOL_VERSION,
        ):
            assert low <= code <= high

    def test_withdrawn_codes_are_outside_the_set_this_server_can_emit(self):
        emitted = {
            spec.PARSE_ERROR,
            spec.INVALID_REQUEST,
            spec.METHOD_NOT_FOUND,
            spec.INVALID_PARAMS,
            spec.INTERNAL_ERROR,
            spec.HEADER_MISMATCH,
            spec.MISSING_REQUIRED_CLIENT_CAPABILITY,
            spec.UNSUPPORTED_PROTOCOL_VERSION,
        }
        assert not (emitted & spec.WITHDRAWN_CODES)

    def test_the_current_version_is_the_one_this_server_serves(self):
        assert spec.PROTOCOL_VERSION in spec.SUPPORTED_VERSIONS

    def test_legacy_versions_are_not_served(self):
        assert not (spec.LEGACY_VERSIONS & set(spec.SUPPORTED_VERSIONS))

    @pytest.mark.parametrize("name", ["read_file", "a", "A.b-c_d", "x" * 128])
    def test_legal_tool_names(self, name: str):
        assert spec.TOOL_NAME_PATTERN.match(name) is not None

    @pytest.mark.parametrize("name", ["", "has space", "x" * 129, "slash/name", "emoji✨"])
    def test_illegal_tool_names(self, name: str):
        assert spec.TOOL_NAME_PATTERN.match(name) is None


class TestEnvelopeParsing:
    def test_a_well_formed_request(self):
        request = jsonrpc.parse('{"jsonrpc":"2.0","id":1,"method":"server/discover"}')
        assert request.method == "server/discover"
        assert request.id == 1
        assert request.params == {}
        assert not request.is_notification

    def test_text_that_is_not_json_is_a_parse_error(self):
        with pytest.raises(ParseError):
            jsonrpc.parse("{not json")

    def test_a_non_object_payload_is_an_invalid_request(self):
        with pytest.raises(InvalidRequestError):
            jsonrpc.from_payload([1, 2, 3])

    def test_the_wrong_jsonrpc_version_is_refused(self):
        with pytest.raises(InvalidRequestError, match="jsonrpc must be"):
            jsonrpc.from_payload({"jsonrpc": "1.0", "method": "x", "id": 1})

    def test_a_missing_method_is_refused(self):
        with pytest.raises(InvalidRequestError, match="method must be"):
            jsonrpc.from_payload({"jsonrpc": "2.0", "id": 1})

    def test_positional_parameters_are_refused(self):
        with pytest.raises(InvalidRequestError, match="positional"):
            jsonrpc.from_payload({"jsonrpc": "2.0", "method": "x", "params": [1], "id": 1})

    def test_null_params_are_treated_as_empty(self):
        request = jsonrpc.from_payload({"jsonrpc": "2.0", "method": "x", "params": None, "id": 1})
        assert request.params == {}

    def test_a_request_without_an_id_is_a_notification(self):
        request = jsonrpc.from_payload({"jsonrpc": "2.0", "method": "x"})
        assert request.is_notification

    def test_a_boolean_id_is_refused(self):
        # `true` is an int in Python and not a legal JSON-RPC id, so a naive
        # isinstance check accepts it.
        with pytest.raises(InvalidRequestError, match="id must be"):
            jsonrpc.from_payload({"jsonrpc": "2.0", "method": "x", "id": True})

    def test_a_structured_id_is_refused(self):
        with pytest.raises(InvalidRequestError):
            jsonrpc.from_payload({"jsonrpc": "2.0", "method": "x", "id": {"a": 1}})

    def test_meta_defaults_to_empty(self):
        request = jsonrpc.from_payload({"jsonrpc": "2.0", "method": "x", "id": 1})
        assert request.meta == {}


class TestEnvelopeRendering:
    def test_success_and_failure_shapes(self):
        assert jsonrpc.success(7, {"a": 1}) == {"jsonrpc": "2.0", "id": 7, "result": {"a": 1}}
        rendered = jsonrpc.failure(None, InvalidRequestError("bad"))
        assert rendered["id"] is None
        assert rendered["error"]["code"] == spec.INVALID_REQUEST

    def test_error_data_is_included_only_when_present(self):
        assert "data" not in InvalidRequestError("x").to_error_object()
        assert UnsupportedProtocolVersionError("1999-01-01").to_error_object()["data"] == {
            "supported": list(spec.SUPPORTED_VERSIONS),
            "requested": "1999-01-01",
        }

    def test_encoding_escapes_non_ascii(self):
        # U+2028 inside a JSON string is a line terminator to some parsers, and
        # this transport is newline-delimited. Built with chr() so the character
        # itself never appears in this file, where it would be invisible.
        separator = chr(0x2028)
        payload = f"a{separator}b"
        encoded = jsonrpc.encode({"jsonrpc": "2.0", "id": 1, "result": {"t": payload}})
        assert separator not in encoded
        assert "u2028" in encoded
        assert json.loads(encoded)["result"]["t"] == payload

    def test_encoding_is_single_line(self):
        encoded = jsonrpc.encode({"jsonrpc": "2.0", "id": 1, "result": {"a": [1, 2]}})
        assert "\n" not in encoded


class TestMetaNegotiation:
    def test_a_well_formed_meta_produces_a_context(self, request_meta: dict[str, Any]):
        context = parse_context(dict(request_meta))
        assert context.protocol_version == spec.PROTOCOL_VERSION
        assert context.client.name == "pytest"
        assert context.capabilities == frozenset()

    def test_a_missing_protocol_version_is_invalid_params(self):
        with pytest.raises(InvalidParamsError, match="protocolVersion"):
            parse_context({spec.META_CLIENT_CAPABILITIES: {}})

    def test_a_missing_client_capabilities_is_invalid_params(self):
        with pytest.raises(InvalidParamsError, match="clientCapabilities"):
            parse_context({spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION})

    def test_client_capabilities_must_be_an_object(self):
        with pytest.raises(InvalidParamsError, match="clientCapabilities"):
            parse_context(
                {
                    spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION,
                    spec.META_CLIENT_CAPABILITIES: ["sampling"],
                }
            )

    def test_an_unsupported_version_names_what_is_supported(self):
        with pytest.raises(UnsupportedProtocolVersionError) as caught:
            parse_context(
                {
                    spec.META_PROTOCOL_VERSION: "2025-11-25",
                    spec.META_CLIENT_CAPABILITIES: {},
                }
            )
        assert caught.value.data == {
            "supported": list(spec.SUPPORTED_VERSIONS),
            "requested": "2025-11-25",
        }

    def test_the_version_is_checked_before_the_capabilities(self):
        # A client speaking a revision this server does not implement may have a
        # different capability model; telling it its capabilities are wrong
        # would send it looking in the wrong place.
        with pytest.raises(UnsupportedProtocolVersionError):
            parse_context({spec.META_PROTOCOL_VERSION: "1999-01-01"})

    def test_a_header_that_disagrees_with_meta_is_refused(self, request_meta: dict[str, Any]):
        with pytest.raises(HeaderMismatchError) as caught:
            parse_context(dict(request_meta), header_version="2025-11-25")
        assert caught.value.code == spec.HEADER_MISMATCH

    def test_a_header_that_agrees_is_accepted(self, request_meta: dict[str, Any]):
        context = parse_context(dict(request_meta), header_version=spec.PROTOCOL_VERSION)
        assert context.protocol_version == spec.PROTOCOL_VERSION

    def test_a_client_may_not_invent_a_reserved_prefix(self, request_meta: dict[str, Any]):
        meta = dict(request_meta)
        meta["x.mcp/invented"] = True
        with pytest.raises(InvalidParamsError, match="reserved"):
            parse_context(meta)

    def test_an_unreserved_prefix_is_accepted(self, request_meta: dict[str, Any]):
        meta = dict(request_meta)
        meta["com.example/thing"] = 1
        assert parse_context(meta).protocol_version == spec.PROTOCOL_VERSION

    def test_a_malformed_key_is_refused(self, request_meta: dict[str, Any]):
        meta = dict(request_meta)
        meta["not a valid key"] = 1
        with pytest.raises(InvalidParamsError, match="not a valid meta key"):
            parse_context(meta)

    def test_trace_context_keys_are_exempt(self, request_meta: dict[str, Any]):
        meta = dict(request_meta)
        meta["traceparent"] = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
        meta["tracestate"] = "vendor=1"
        context = parse_context(meta)
        assert context.trace["traceparent"].startswith("00-")

    def test_required_capabilities_are_enforced(self, request_meta: dict[str, Any]):
        context = parse_context(dict(request_meta))
        with pytest.raises(MissingRequiredClientCapabilityError) as caught:
            context.require("sampling", "elicitation")
        assert caught.value.data == {"requiredCapabilities": ["elicitation", "sampling"]}

    def test_declared_capabilities_satisfy_the_requirement(self):
        context = parse_context(
            {
                spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION,
                spec.META_CLIENT_CAPABILITIES: {"sampling": {}},
            }
        )
        context.require("sampling")


class TestClientInfo:
    def test_a_missing_client_info_is_not_an_error(self):
        assert ClientInfo.parse(None).label() == "unidentified"

    def test_non_string_members_are_ignored_rather_than_rejected(self):
        # clientInfo grants nothing, so failing a request over it would fail a
        # request for no security benefit.
        info = ClientInfo.parse({"name": 7, "version": "1.0"})
        assert info.name == ""
        assert info.version == "1.0"

    def test_the_label_combines_name_and_version(self):
        assert ClientInfo.parse({"name": "zed", "version": "2"}).label() == "zed/2"


class TestResultMeta:
    def test_server_info_is_attached(self):
        info = server_info("mcp-devserver", "1.2.3", title="Dev Server")
        meta = result_meta(info)
        assert meta[spec.META_SERVER_INFO] == {
            "name": "mcp-devserver",
            "version": "1.2.3",
            "title": "Dev Server",
        }

    def test_trace_context_is_echoed_back(self, request_meta: dict[str, Any]):
        meta = dict(request_meta)
        meta["traceparent"] = "00-" + "c" * 32 + "-" + "d" * 16 + "-01"
        context = parse_context(meta)
        assert result_meta(server_info("s", "1"), context)["traceparent"].startswith("00-")
