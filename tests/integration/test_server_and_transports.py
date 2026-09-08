"""Dispatch, and both transports carrying it."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_devserver.config import Settings
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import PAGE_SIZE, Server
from mcp_devserver.transport.http import PROTOCOL_VERSION_HEADER, build_application
from mcp_devserver.transport.stdio import StdioTransport, read_line
from tests.conftest import call, rpc

pytestmark = pytest.mark.integration


async def result_of(server: Server, payload: dict[str, Any]) -> dict[str, Any]:
    response = await server.handle_payload(payload)
    assert response is not None
    assert "error" not in response, response.get("error")
    return dict(response["result"])


async def error_of(server: Server, payload: dict[str, Any]) -> dict[str, Any]:
    response = await server.handle_payload(payload)
    assert response is not None
    assert "error" in response, response
    return dict(response["error"])


class TestDiscover:
    async def test_discover_reports_the_server(self, server: Server):
        result = await result_of(server, rpc(spec.DISCOVER))
        assert result["supportedVersions"] == list(spec.SUPPORTED_VERSIONS)
        assert result["capabilities"]["tools"]["count"] == len(server.registry)
        assert result["instructions"]
        assert result["cacheScope"] == "server"

    async def test_the_instructions_warn_about_untrusted_content(self, server: Server):
        # The instructions are how a client learns what the fences mean; a
        # server that fenced content but never explained it would be marking
        # for nobody.
        result = await result_of(server, rpc(spec.DISCOVER))
        assert "untrusted" in result["instructions"].lower()


class TestToolsList:
    async def test_the_first_page_and_a_cursor(self, server: Server):
        result = await result_of(server, rpc(spec.TOOLS_LIST))
        assert len(result["tools"]) == PAGE_SIZE
        assert result["nextCursor"]

    async def test_paging_reaches_every_tool_exactly_once(self, server: Server):
        seen: list[str] = []
        cursor: str | None = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = await result_of(server, rpc(spec.TOOLS_LIST, params))
            seen.extend(tool["name"] for tool in result["tools"])
            cursor = result.get("nextCursor")
            if cursor is None:
                break
        assert seen == list(server.registry.names())

    async def test_a_cursor_the_server_did_not_issue(self, server: Server):
        error = await error_of(server, rpc(spec.TOOLS_LIST, {"cursor": "AAAA"}))
        assert error["code"] == spec.INVALID_PARAMS

    async def test_a_cursor_past_the_end(self, server: Server):
        from mcp_devserver.protocol.server import _encode_cursor

        error = await error_of(server, rpc(spec.TOOLS_LIST, {"cursor": _encode_cursor(999)}))
        assert error["code"] == spec.INVALID_PARAMS

    async def test_a_non_string_cursor(self, server: Server):
        error = await error_of(server, rpc(spec.TOOLS_LIST, {"cursor": 3}))
        assert error["code"] == spec.INVALID_PARAMS


class TestToolsCall:
    async def test_a_successful_call(self, server: Server):
        result = await result_of(server, call("project_overview"))
        assert result["isError"] is False
        assert result["structuredContent"]["total_files"] > 0
        assert result["_meta"][spec.META_SERVER_INFO]["name"] == "mcp-devserver"

    async def test_a_missing_name(self, server: Server):
        error = await error_of(server, rpc(spec.TOOLS_CALL, {"arguments": {}}))
        assert error["code"] == spec.INVALID_PARAMS

    async def test_arguments_must_be_an_object(self, server: Server):
        error = await error_of(server, rpc(spec.TOOLS_CALL, {"name": "read_file", "arguments": []}))
        assert error["code"] == spec.INVALID_PARAMS

    async def test_missing_arguments_default_to_empty(self, server: Server):
        result = await result_of(server, rpc(spec.TOOLS_CALL, {"name": "project_overview"}))
        assert result["isError"] is False

    async def test_a_sandbox_denial_is_a_result(self, server: Server):
        result = await result_of(server, call("read_file", {"path": "../../etc/passwd"}))
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == "outside_workspace"


class TestDispatchErrors:
    async def test_an_unknown_method(self, server: Server):
        error = await error_of(server, rpc("does/not/exist"))
        assert error["code"] == spec.METHOD_NOT_FOUND

    async def test_a_legacy_initialize_names_the_supported_revisions(self, server: Server):
        error = await error_of(
            server,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}},
            },
        )
        assert error["code"] == spec.UNSUPPORTED_PROTOCOL_VERSION
        assert error["data"]["supported"] == list(spec.SUPPORTED_VERSIONS)

    async def test_a_malformed_payload_keeps_the_id(self, server: Server):
        response = await server.handle_payload({"jsonrpc": "1.0", "id": 42, "method": "x"})
        assert response is not None
        assert response["id"] == 42
        assert response["error"]["code"] == spec.INVALID_REQUEST

    async def test_a_notification_is_never_answered(self, server: Server):
        assert await server.handle_payload(rpc(spec.DISCOVER, identifier=None)) is None

    async def test_a_notification_that_fails_is_still_not_answered(self, server: Server):
        payload = rpc("nope/nope", identifier=None)
        assert await server.handle_payload(payload) is None

    async def test_an_unexpected_failure_becomes_an_internal_error_without_detail(
        self, server: Server, monkeypatch: pytest.MonkeyPatch
    ):
        def explode(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("/home/someone/private/path leaked in the traceback")

        monkeypatch.setattr(server.registry, "invoke", explode)
        error = await error_of(server, call("project_overview"))
        assert error["code"] == spec.INTERNAL_ERROR
        # A traceback names absolute paths outside the workspace, which is the
        # information the sandbox exists to withhold.
        assert "private/path" not in json.dumps(error)


class TestStatelessness:
    async def test_interleaved_requests_do_not_influence_each_other(self, server: Server):
        first = await result_of(server, rpc(spec.TOOLS_LIST, identifier="a"))
        await server.handle_payload(call("project_overview", identifier="b"))
        await server.handle_payload(rpc(spec.DISCOVER, identifier="c"))
        second = await result_of(server, rpc(spec.TOOLS_LIST, identifier="d"))
        assert first["tools"] == second["tools"]

    async def test_concurrent_calls_return_independent_results(self, server: Server):
        payloads = [
            call("read_file", {"path": "README.md"}, identifier=1),
            call("read_file", {"path": "pyproject.toml"}, identifier=2),
            call("project_overview", identifier=3),
        ]
        responses = await asyncio.gather(*(server.handle_payload(p) for p in payloads))
        assert [response["id"] for response in responses if response] == [1, 2, 3]

    async def test_each_call_gets_its_own_fence_nonce(self, server: Server):
        first = await result_of(server, call("read_file", {"path": "README.md"}))
        second = await result_of(server, call("read_file", {"path": "README.md"}))
        assert first["content"][1]["text"] != second["content"][1]["text"]


class TestStdioTransport:
    def test_reading_a_line(self):
        stream = io.BytesIO(b'{"a":1}\n{"b":2}\n')
        assert read_line(stream, 1024).data == b'{"a":1}\n'
        assert read_line(stream, 1024).data == b'{"b":2}\n'
        assert read_line(stream, 1024).at_end

    def test_an_oversized_line_is_reported_and_the_stream_resynchronises(self):
        stream = io.BytesIO(b"x" * 100 + b"\n" + b'{"next":1}\n')
        first = read_line(stream, 10)
        assert first.oversized
        # The next read must start at a request boundary, not mid-request.
        assert read_line(stream, 1024).data == b'{"next":1}\n'

    async def test_a_request_round_trips_over_the_transport(self, server: Server):
        request = json.dumps(rpc(spec.DISCOVER)).encode("utf-8") + b"\n"
        output = io.BytesIO()
        transport = StdioTransport(server, stdin=io.BytesIO(request), stdout=output)
        await transport.serve()
        response = json.loads(output.getvalue().decode("utf-8"))
        assert response["result"]["resultType"] == "complete"

    async def test_a_notification_produces_no_output(self, server: Server):
        request = json.dumps(rpc(spec.DISCOVER, identifier=None)).encode("utf-8") + b"\n"
        output = io.BytesIO()
        await StdioTransport(server, stdin=io.BytesIO(request), stdout=output).serve()
        assert output.getvalue() == b""

    async def test_blank_lines_are_ignored(self, server: Server):
        request = b"\n\n" + json.dumps(rpc(spec.DISCOVER)).encode("utf-8") + b"\n"
        output = io.BytesIO()
        await StdioTransport(server, stdin=io.BytesIO(request), stdout=output).serve()
        assert len(output.getvalue().splitlines()) == 1

    async def test_unparseable_input_gets_a_parse_error_not_a_crash(self, server: Server):
        output = io.BytesIO()
        await StdioTransport(server, stdin=io.BytesIO(b"{oops\n"), stdout=output).serve()
        response = json.loads(output.getvalue())
        assert response["error"]["code"] == spec.PARSE_ERROR
        assert response["id"] is None

    async def test_an_oversized_request_is_answered_over_the_wire(self, server: Server):
        output = io.BytesIO()
        transport = StdioTransport(
            server, max_bytes=64, stdin=io.BytesIO(b"x" * 500 + b"\n"), stdout=output
        )
        await transport.serve()
        response = json.loads(output.getvalue())
        assert response["error"]["code"] == spec.PARSE_ERROR
        assert "64-byte line limit" in response["error"]["message"]

    async def test_every_response_is_one_line(self, server: Server):
        requests = b"".join(
            json.dumps(rpc(spec.TOOLS_LIST, identifier=index)).encode("utf-8") + b"\n"
            for index in range(5)
        )
        output = io.BytesIO()
        await StdioTransport(server, stdin=io.BytesIO(requests), stdout=output).serve()
        lines = output.getvalue().decode("utf-8").strip().split("\n")
        assert len(lines) == 5
        for line in lines:
            json.loads(line)


@pytest.fixture
def http_client(server: Server) -> httpx.AsyncClient:
    """An HTTP client bound to the server's ASGI application."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_application(server)),
        base_url="http://testserver",
    )


class TestHttpTransport:
    async def test_health_and_readiness(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            assert (await client.get("/healthz")).json()["status"] == "ok"
            ready = await client.get("/readyz")
            assert ready.status_code == 200
            assert ready.json()["tools"] > 0

    async def test_readiness_fails_when_the_workspace_disappears(
        self, server: Server, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(type(server.workspace.root), "is_dir", lambda self: False)
        transport = httpx.ASGITransport(app=build_application(server))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.get("/readyz")
        assert response.status_code == 503

    async def test_a_request_round_trips(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post("/mcp", json=rpc(spec.DISCOVER))
        assert response.status_code == 200
        assert response.json()["result"]["resultType"] == "complete"

    async def test_a_notification_is_accepted_with_no_body(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post("/mcp", json=rpc(spec.DISCOVER, identifier=None))
        assert response.status_code == 202
        assert response.content == b""

    async def test_an_unknown_method_maps_to_404(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post("/mcp", json=rpc("no/such/method"))
        assert response.status_code == 404
        assert response.json()["error"]["code"] == spec.METHOD_NOT_FOUND

    async def test_a_bad_request_maps_to_400(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post("/mcp", json={"jsonrpc": "1.0", "id": 1, "method": "x"})
        assert response.status_code == 400

    async def test_unparseable_json_maps_to_400(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post(
                "/mcp", content=b"{oops", headers={"content-type": "application/json"}
            )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == spec.PARSE_ERROR

    async def test_a_batch_is_refused(self, http_client: httpx.AsyncClient):
        # Batching is not part of this revision, and accepting it would let one
        # HTTP request start an unbounded number of tool runs.
        async with http_client as client:
            response = await client.post("/mcp", json=[rpc(spec.DISCOVER)])
        assert response.status_code == 400
        assert "batch" in response.json()["error"]["message"]

    async def test_a_matching_version_header_is_accepted(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post(
                "/mcp",
                json=rpc(spec.DISCOVER),
                headers={PROTOCOL_VERSION_HEADER: spec.PROTOCOL_VERSION},
            )
        assert response.status_code == 200

    async def test_a_disagreeing_version_header_is_refused(self, http_client: httpx.AsyncClient):
        async with http_client as client:
            response = await client.post(
                "/mcp",
                json=rpc(spec.DISCOVER),
                headers={PROTOCOL_VERSION_HEADER: "2025-11-25"},
            )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == spec.HEADER_MISMATCH

    async def test_a_body_over_the_limit_is_refused(self, workspace_root: Path):
        settings = Settings(
            sandbox={"workspace": workspace_root},
            http={"max_request_bytes": 2_048},
        )
        application = build_application(Server(settings))
        transport = httpx.ASGITransport(app=application)
        payload = rpc(spec.TOOLS_CALL, {"name": "read_file", "arguments": {"path": "x" * 4_000}})
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post("/mcp", json=payload)
        assert response.status_code == 413


class TestHttpAuthorisation:
    @pytest.fixture
    def secured(self, workspace_root: Path) -> Server:
        settings = Settings(
            sandbox={"workspace": workspace_root},
            http={
                "bearer_token": "correct-horse-battery-staple",
                "allowed_origins": ["https://editor.example"],
            },
        )
        return Server(settings)

    async def test_a_missing_token_is_rejected(self, secured: Server):
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post("/mcp", json=rpc(spec.DISCOVER))
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    async def test_a_wrong_token_is_rejected(self, secured: Server):
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post(
                "/mcp", json=rpc(spec.DISCOVER), headers={"authorization": "Bearer wrong"}
            )
        assert response.status_code == 401

    async def test_the_right_token_is_accepted(self, secured: Server):
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post(
                "/mcp",
                json=rpc(spec.DISCOVER),
                headers={"authorization": "Bearer correct-horse-battery-staple"},
            )
        assert response.status_code == 200

    async def test_probes_do_not_require_a_token(self, secured: Server):
        # A liveness probe that needs a credential reports the wrong thing when
        # the credential is wrong.
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/healthz")).status_code == 200

    async def test_an_unknown_origin_is_refused(self, secured: Server):
        # DNS-rebinding defence: a page in the developer's browser can POST JSON
        # to a loopback port without a preflight.
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post(
                "/mcp", json=rpc(spec.DISCOVER), headers={"origin": "https://evil.example"}
            )
        assert response.status_code == 403

    async def test_a_known_origin_is_allowed(self, secured: Server):
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post(
                "/mcp",
                json=rpc(spec.DISCOVER),
                headers={
                    "origin": "https://editor.example",
                    "authorization": "Bearer correct-horse-battery-staple",
                },
            )
        assert response.status_code == 200

    async def test_the_origin_check_runs_before_authentication(self, secured: Server):
        # Otherwise the endpoint is an oracle for whether a token is valid, from
        # any page the developer visits.
        transport = httpx.ASGITransport(app=build_application(secured))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.post(
                "/mcp",
                json=rpc(spec.DISCOVER),
                headers={"origin": "https://evil.example", "authorization": "Bearer wrong"},
            )
        assert response.status_code == 403
