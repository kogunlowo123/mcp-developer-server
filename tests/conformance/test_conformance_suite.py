"""The conformance suite, run against this server — and against broken ones.

The second half is what makes this a gate rather than a decoration. A suite that
only ever runs against a correct server proves nothing about whether it would
notice an incorrect one, so each negative control here breaks exactly one
specification requirement and asserts that the corresponding check fails.

That is the property CI depends on: a regression in the protocol layer turns a
green run red, rather than printing twenty-three ticks regardless.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from mcp_devserver.conformance.checks import CHECKS, MUST, SHOULD
from mcp_devserver.conformance.client import Client, InProcessClient
from mcp_devserver.conformance.runner import Report, run_suite, write_report
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import Server

pytestmark = pytest.mark.conformance


#: A response mutator: given the request and the response, return the
#: response the client should see.
#: One JSON-RPC payload, decoded.
type Payload = dict[str, Any]

#: A response mutator's signature.
type Mutation = Callable[[Payload, Payload | None], Payload | None]


class MutatingClient:
    """Wraps a client and damages its responses in one specific way.

    Each negative control is a one-line mutation, so a failing check names the
    requirement it is defending rather than "something is wrong".
    """

    def __init__(self, inner: Client, mutate: Mutation) -> None:
        self._inner = inner
        self._mutate = mutate

    @property
    def label(self) -> str:
        """Where this client points."""
        return f"mutated {self._inner.label}"

    async def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        response = await self._inner.send(payload)
        return self._mutate(payload, response)


class TestTheServerConforms:
    async def test_every_check_passes(self, client: InProcessClient):
        report = await run_suite(client, strict=True)
        failures = [outcome for outcome in report.outcomes if not outcome.passed]
        assert failures == [], "\n".join(
            f"{outcome.identifier}: {outcome.detail}" for outcome in failures
        )
        assert report.green

    async def test_the_suite_covers_both_requirement_levels(self, client: InProcessClient):
        levels = {check.level for check in CHECKS}
        assert levels == {MUST, SHOULD}

    async def test_check_identifiers_are_unique_and_ordered(self):
        identifiers = [check.identifier for check in CHECKS]
        assert identifiers == sorted(identifiers)
        assert len(set(identifiers)) == len(identifiers)

    async def test_the_report_renders_and_serialises(self, client: InProcessClient, tmp_path):
        report = await run_suite(client)
        rendered = report.render()
        assert "CONFORMANT" in rendered
        assert f"{len(CHECKS)} passed" in rendered

        destination = tmp_path / "reports" / "conformance.json"
        write_report(report, destination)
        assert destination.exists()
        assert '"green": true' in destination.read_text(encoding="utf-8")


class TestTheSuiteDetectsNonConformance:
    """One broken requirement at a time, and the check that must notice."""

    async def _run(self, server: Server, mutate: Mutation) -> Report:
        return await run_suite(MutatingClient(InProcessClient(server), mutate))

    def _failed(self, report: Report, identifier: str) -> bool:
        return any(
            outcome.identifier == identifier and not outcome.passed for outcome in report.outcomes
        )

    async def test_a_missing_result_type_is_caught(self, server: Server):
        def drop_result_type(payload: Payload, response: Payload | None) -> Payload | None:
            if response and "result" in response:
                response["result"].pop("resultType", None)
            return response

        report = await self._run(server, drop_result_type)
        assert self._failed(report, "C004")
        assert not report.green

    async def test_a_missing_server_info_is_caught(self, server: Server):
        def drop_server_info(payload: Payload, response: Payload | None) -> Payload | None:
            if response and "result" in response:
                response["result"].pop("_meta", None)
            return response

        report = await self._run(server, drop_server_info)
        assert self._failed(report, "C002")

    async def test_an_answered_notification_is_caught(self, server: Server):
        def answer_everything(payload: Payload, response: Payload | None) -> Payload | None:
            if response is None:
                return {"jsonrpc": "2.0", "id": None, "result": {"resultType": "complete"}}
            return response

        report = await self._run(server, answer_everything)
        assert self._failed(report, "C017")

    async def test_a_wrong_error_code_is_caught(self, server: Server):
        def relabel_errors(payload: Payload, response: Payload | None) -> Payload | None:
            if response and "error" in response:
                response["error"]["code"] = spec.INTERNAL_ERROR
            return response

        report = await self._run(server, relabel_errors)
        # Several checks assert on specific codes; the version one is the
        # clearest single signal.
        assert self._failed(report, "C011")
        assert not report.green

    async def test_a_withdrawn_error_code_is_caught(self, server: Server):
        def use_withdrawn_code(payload: Payload, response: Payload | None) -> Payload | None:
            if response and "error" in response:
                response["error"]["code"] = -32002
            return response

        report = await self._run(server, use_withdrawn_code)
        assert self._failed(report, "C016")

    async def test_a_tool_denial_delivered_as_a_protocol_error_is_caught(self, server: Server):
        def convert_tool_errors(payload: Payload, response: Payload | None) -> Payload | None:
            if (
                response
                and payload.get("method") == spec.TOOLS_CALL
                and isinstance(response.get("result"), dict)
                and response["result"].get("isError")
            ):
                return {
                    "jsonrpc": "2.0",
                    "id": response["id"],
                    "error": {"code": spec.INVALID_PARAMS, "message": "denied"},
                }
            return response

        report = await self._run(server, convert_tool_errors)
        assert self._failed(report, "C018")

    async def test_an_unstable_tool_order_is_caught(self, server: Server):
        calls = {"count": 0}

        def shuffle_tools(payload: Payload, response: Payload | None) -> Payload | None:
            if response and payload.get("method") == spec.TOOLS_LIST:
                calls["count"] += 1
                if calls["count"] % 2 == 0:
                    response["result"]["tools"] = list(reversed(response["result"]["tools"]))
            return response

        report = await self._run(server, shuffle_tools)
        assert self._failed(report, "C006")

    async def test_an_ignored_bad_cursor_is_caught(self, server: Server):
        def swallow_cursor_errors(payload: Payload, response: Payload | None) -> Payload | None:
            if response and payload.get("method") == spec.TOOLS_LIST and "error" in response:
                return {
                    "jsonrpc": "2.0",
                    "id": response["id"],
                    "result": {"resultType": "complete", "tools": []},
                }
            return response

        report = await self._run(server, swallow_cursor_errors)
        assert self._failed(report, "C008")

    async def test_an_accepted_legacy_initialize_is_caught(self, server: Server):
        def accept_initialize(payload: Payload, response: Payload | None) -> Payload | None:
            if payload.get("method") == spec.LEGACY_INITIALIZE:
                return {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "result": {"resultType": "complete", "protocolVersion": "2025-11-25"},
                }
            return response

        report = await self._run(server, accept_initialize)
        assert self._failed(report, "C012")

    async def test_a_server_that_accepts_a_missing_protocol_version_is_caught(self, server: Server):
        def accept_anything(payload: Payload, response: Payload | None) -> Payload | None:
            params = payload.get("params", {})
            meta = params.get("_meta", {}) if isinstance(params, dict) else {}
            if spec.META_PROTOCOL_VERSION not in meta and response and "error" in response:
                return {
                    "jsonrpc": "2.0",
                    "id": response["id"],
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": ["x"],
                        "capabilities": {},
                    },
                }
            return response

        report = await self._run(server, accept_anything)
        assert self._failed(report, "C009")


class TestStrictness:
    async def test_a_should_failure_does_not_fail_the_default_gate(self, server: Server):
        def drop_ttl(payload: Payload, response: Payload | None) -> Payload | None:
            if response and isinstance(response.get("result"), dict):
                response["result"].pop("ttlMs", None)
            return response

        client = MutatingClient(InProcessClient(server), drop_ttl)
        lenient = await run_suite(client, strict=False)
        assert any(
            outcome.identifier == "C003" and not outcome.passed for outcome in lenient.outcomes
        )
        assert lenient.green

    async def test_strict_promotes_it_to_a_failure(self, server: Server):
        def drop_ttl(payload: Payload, response: Payload | None) -> Payload | None:
            if response and isinstance(response.get("result"), dict):
                response["result"].pop("ttlMs", None)
            return response

        client = MutatingClient(InProcessClient(server), drop_ttl)
        strict = await run_suite(client, strict=True)
        assert not strict.green

    async def test_a_must_failure_fails_either_way(self, server: Server):
        def drop_result_type(payload: Payload, response: Payload | None) -> Payload | None:
            if response and "result" in response:
                response["result"].pop("resultType", None)
            return response

        client = MutatingClient(InProcessClient(server), drop_result_type)
        assert not (await run_suite(client, strict=False)).green
        assert not (await run_suite(client, strict=True)).green

    async def test_a_check_that_raises_is_a_failure_not_a_crash(self, server: Server):
        def return_nonsense(payload: Payload, response: Payload | None) -> Payload | None:
            return {"jsonrpc": "2.0", "id": 1, "result": "not an object"}

        report = await run_suite(MutatingClient(InProcessClient(server), return_nonsense))
        assert not report.green
        assert all(outcome.detail for outcome in report.outcomes if not outcome.passed)
