"""Bounds: what stops a request from consuming the process.

An MCP server runs inside the developer's editor session. A request that pins a
core, allocates a gigabyte or never returns is not a crash somebody else deals
with — it is the developer's machine.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from mcp_devserver.config import Settings
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import Server
from mcp_devserver.sandbox.workspace import Workspace
from mcp_devserver.security.redaction import Redactor
from mcp_devserver.security.untrusted import UntrustedContentScanner
from mcp_devserver.tools import build_registry
from mcp_devserver.tools.base import Limits, ToolContext
from mcp_devserver.tools.search import SEARCH_FILE_LIMIT
from tests.conftest import call, rpc

pytestmark = pytest.mark.security


async def invoke(server: Server, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = await server.handle_payload(call(name, arguments))
    assert response is not None
    if "error" in response:
        return {"protocol_error": response["error"]}
    return dict(response["result"])


class TestFileSize:
    async def test_a_file_over_the_limit_is_refused_rather_than_read(self, workspace_root: Path):
        (workspace_root / "huge.txt").write_text("y" * 200_000, encoding="utf-8")
        settings = Settings(
            sandbox={
                "workspace": workspace_root,
                "max_file_bytes": 4_096,
            }
        )
        result = await invoke(Server(settings), "read_file", {"path": "huge.txt"})
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == "too_large"

    async def test_a_large_file_is_skipped_by_search_not_loaded(
        self, workspace_root: Path, server: Server
    ):
        (workspace_root / "bundle.min.js").write_text(
            "needle" + "z" * (SEARCH_FILE_LIMIT + 1_000), encoding="utf-8"
        )
        result = await invoke(server, "search_code", {"pattern": "needle"})
        assert result["structuredContent"]["files_skipped"] >= 1
        assert all(
            match["path"] != "bundle.min.js" for match in result["structuredContent"]["matches"]
        )


class TestResultSize:
    async def test_search_output_is_capped_by_bytes(self, workspace_root: Path):
        # Under the per-file search limit, so the file is scanned rather than
        # skipped, and far over the result byte cap once every line matches.
        (workspace_root / "wide.txt").write_text(
            "\n".join("match " + "w" * 300 for _ in range(1_000)), encoding="utf-8"
        )
        settings = Settings(
            sandbox={
                "workspace": workspace_root,
                "max_result_bytes": 4_096,
                "max_search_results": 1_000,
            }
        )
        result = await invoke(Server(settings), "search_code", {"pattern": "match"})
        assert result["structuredContent"]["truncated"] is True
        assert len(result["content"][1]["text"]) < 20_000

    async def test_a_directory_listing_is_capped(self, workspace_root: Path):
        for index in range(300):
            (workspace_root / f"file{index:03d}.txt").write_text("x", encoding="utf-8")
        settings = Settings(
            sandbox={
                "workspace": workspace_root,
                "max_directory_entries": 50,
            }
        )
        result = await invoke(Server(settings), "list_directory", {})
        assert result["structuredContent"]["truncated"] is True
        assert len(result["structuredContent"]["entries"]) == 50

    async def test_read_output_is_capped_by_lines(self, workspace_root: Path):
        (workspace_root / "many.txt").write_text(
            "\n".join(str(number) for number in range(5_000)), encoding="utf-8"
        )
        settings = Settings(sandbox={"workspace": workspace_root, "max_read_lines": 25})
        result = await invoke(Server(settings), "read_file", {"path": "many.txt"})
        assert result["structuredContent"]["truncated"] is True
        assert result["structuredContent"]["end_line"] == 25


class TestTimeBudget:
    def test_a_search_stops_at_the_deadline(self, workspace: Workspace):
        # The budget is checked between files, so a large tree cannot hold the
        # process past it.
        context = ToolContext(
            workspace=workspace,
            limits=Limits(tool_timeout_seconds=0.0),
            redactor=Redactor(),
            scanner=UntrustedContentScanner(),
        )
        result = build_registry().invoke("search_code", {"pattern": "e"}, context)
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == "timed_out"

    async def test_a_pathological_pattern_costs_one_budget_not_the_process(
        self, workspace_root: Path
    ):
        # Catastrophic backtracking on a nested quantifier. The wall-clock bound
        # is what makes this survivable.
        (workspace_root / "bait.txt").write_text("a" * 40 + "!", encoding="utf-8")
        settings = Settings(
            sandbox={
                "workspace": workspace_root,
                "tool_timeout_seconds": 2.0,
            }
        )
        started = time.monotonic()
        result = await invoke(
            Server(settings),
            "search_code",
            {"pattern": "(a+)+b", "regex": True, "path": "bait.txt"},
        )
        elapsed = time.monotonic() - started
        assert elapsed < 30.0, f"the search ran for {elapsed:.1f}s"
        assert "protocol_error" not in result


class TestRequestSize:
    async def test_an_overlong_search_pattern_is_refused_by_the_schema(self, server: Server):
        response = await server.handle_payload(call("search_code", {"pattern": "a" * 5_000}))
        assert response is not None
        assert response["error"]["code"] == spec.INVALID_PARAMS

    async def test_an_overlong_path_is_refused_by_the_schema(self, server: Server):
        response = await server.handle_payload(call("read_file", {"path": "a" * 9_000}))
        assert response is not None
        assert response["error"]["code"] == spec.INVALID_PARAMS

    async def test_a_deeply_nested_argument_object_is_refused(self, server: Server):
        nested: dict[str, Any] = {"x": 1}
        for _ in range(50):
            nested = {"x": nested}
        response = await server.handle_payload(call("read_file", {"path": nested}))
        assert response is not None
        assert response["error"]["code"] == spec.INVALID_PARAMS

    async def test_a_huge_arguments_object_does_not_reach_a_handler(self, server: Server):
        # additionalProperties: false means every one of these is rejected by
        # name before anything runs.
        arguments = {f"key{index}": index for index in range(5_000)}
        response = await server.handle_payload(call("project_overview", arguments))
        assert response is not None
        assert response["error"]["code"] == spec.INVALID_PARAMS


class TestWalkBounds:
    async def test_the_walk_stops_at_the_file_cap(self, workspace_root: Path):
        for index in range(200):
            (workspace_root / f"gen{index:03d}.py").write_text("x = 1\n", encoding="utf-8")
        settings = Settings(sandbox={"workspace": workspace_root, "max_search_files": 20})
        result = await invoke(Server(settings), "project_overview", {})
        assert result["structuredContent"]["total_files"] <= 20

    async def test_discovery_still_answers_under_load(self, server: Server):
        # The dispatcher must not be blocked by tool work; discovery is what a
        # client retries with when it thinks a server has stalled.
        response = await server.handle_payload(rpc(spec.DISCOVER))
        assert response is not None
        assert response["result"]["resultType"] == "complete"
