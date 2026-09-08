"""A real server process, driven the way an editor drives one.

Everything else in this suite runs the server in the test process. That cannot
catch the failures that only appear when there is a process: a library writing
to stdout and corrupting the wire, an import that only fails under the installed
entry point, a configuration read from the environment rather than passed in.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_devserver.conformance.client import StdioClient
from mcp_devserver.conformance.runner import run_suite
from mcp_devserver.protocol import spec
from tests.conftest import call, rpc

pytestmark = pytest.mark.e2e


@pytest.fixture
def environment(workspace_root: Path) -> dict[str, str]:
    """An environment that points a child process at the fixture workspace."""
    return {
        **os.environ,
        "MCP_SANDBOX__WORKSPACE": str(workspace_root),
        "MCP_OBSERVABILITY__LOG_LEVEL": "error",
        "PYTHONPATH": str(Path.cwd() / "src"),
    }


@pytest.fixture
def stdio_command(server_command: list[str]) -> list[str]:
    """The command that starts the server over stdio."""
    return server_command


async def run(
    command: list[str], environment: dict[str, str], payloads: list[dict[str, Any]]
) -> tuple[bytes, bytes, int | None]:
    import asyncio

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    body = "".join(json.dumps(payload) + "\n" for payload in payloads).encode("utf-8")
    stdout, stderr = await asyncio.wait_for(process.communicate(body), timeout=120)
    return stdout, stderr, process.returncode


class TestStdioProcess:
    async def test_the_conformance_suite_passes_over_a_real_pipe(
        self, stdio_command: list[str], environment: dict[str, str], monkeypatch
    ):
        for key, value in environment.items():
            monkeypatch.setenv(key, value)
        async with StdioClient(stdio_command) as client:
            report = await run_suite(client, strict=True)
        failures = [outcome for outcome in report.outcomes if not outcome.passed]
        assert failures == [], "\n".join(
            f"{outcome.identifier}: {outcome.detail}" for outcome in failures
        )

    async def test_stdout_carries_nothing_but_responses(
        self, stdio_command: list[str], environment: dict[str, str]
    ):
        # The failure this catches: a library printing a warning to stdout,
        # which is the JSON-RPC wire. The client then sees a parse error it
        # cannot explain.
        payloads = [rpc(spec.DISCOVER), rpc(spec.TOOLS_LIST, identifier=2)]
        stdout, _stderr, code = await run(stdio_command, environment, payloads)
        assert code == 0
        lines = stdout.decode("utf-8").strip().splitlines()
        assert len(lines) == 2
        for line in lines:
            decoded = json.loads(line)
            assert decoded["jsonrpc"] == "2.0"

    async def test_logs_go_to_stderr(self, stdio_command: list[str], environment: dict[str, str]):
        loud = {**environment, "MCP_OBSERVABILITY__LOG_LEVEL": "info"}
        stdout, stderr, _code = await run(stdio_command, loud, [rpc(spec.DISCOVER)])
        assert len(stdout.decode("utf-8").strip().splitlines()) == 1
        assert b"stdio.started" in stderr

    async def test_the_process_exits_cleanly_when_stdin_closes(
        self, stdio_command: list[str], environment: dict[str, str]
    ):
        _stdout, _stderr, code = await run(stdio_command, environment, [])
        assert code == 0

    async def test_a_tool_call_reaches_the_configured_workspace(
        self, stdio_command: list[str], environment: dict[str, str]
    ):
        stdout, _stderr, _code = await run(
            stdio_command, environment, [call("read_file", {"path": "README.md"})]
        )
        response = json.loads(stdout.decode("utf-8").strip())
        assert response["result"]["isError"] is False
        assert "A fixture project." in json.dumps(response)

    async def test_a_sandbox_denial_survives_the_round_trip(
        self, stdio_command: list[str], environment: dict[str, str]
    ):
        stdout, _stderr, _code = await run(
            stdio_command, environment, [call("read_file", {"path": "../../etc/passwd"})]
        )
        response = json.loads(stdout.decode("utf-8").strip())
        assert response["result"]["isError"] is True
        assert response["result"]["structuredContent"]["error"] == "outside_workspace"

    async def test_secrets_do_not_leave_the_process(
        self, stdio_command: list[str], environment: dict[str, str]
    ):
        from tests.conftest import FAKE_AWS_KEY

        stdout, stderr, _code = await run(
            stdio_command, environment, [call("read_file", {"path": "src/demo/settings.py"})]
        )
        assert FAKE_AWS_KEY.encode() not in stdout
        assert FAKE_AWS_KEY.encode() not in stderr

    async def test_several_requests_on_one_process_are_independent(
        self, stdio_command: list[str], environment: dict[str, str]
    ):
        payloads = [
            rpc(spec.TOOLS_LIST, identifier="first"),
            call("project_overview", identifier="middle"),
            rpc(spec.TOOLS_LIST, identifier="last"),
        ]
        stdout, _stderr, _code = await run(stdio_command, environment, payloads)
        responses = {
            json.loads(line)["id"]: json.loads(line)
            for line in stdout.decode("utf-8").strip().splitlines()
        }
        assert responses["first"]["result"]["tools"] == responses["last"]["result"]["tools"]


class TestCommandLine:
    async def test_the_doctor_reports_a_usable_configuration(self, environment: dict[str, str]):
        import asyncio

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_devserver",
            "doctor",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        assert process.returncode == 0
        text = stdout.decode("utf-8")
        assert f"protocol           {spec.PROTOCOL_VERSION}" in text
        assert "tools              7" in text
        assert "ready" in text

    async def test_the_doctor_refuses_a_broken_production_configuration(
        self, environment: dict[str, str]
    ):
        import asyncio

        broken = {**environment, "MCP_ENVIRONMENT": "production"}
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_devserver",
            "doctor",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=broken,
        )
        _stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        assert process.returncode != 0
        assert b"BEARER_TOKEN" in stderr

    async def test_conform_exits_zero_against_this_server(self, environment: dict[str, str]):
        import asyncio

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_devserver",
            "conform",
            "--strict",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=180)
        assert process.returncode == 0
        assert b"CONFORMANT" in stdout

    async def test_call_prints_a_tool_result(self, environment: dict[str, str]):
        import asyncio

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_devserver",
            "call",
            "project_overview",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        assert process.returncode == 0
        assert b"Languages:" in stdout

    async def test_call_exits_non_zero_on_a_tool_error(self, environment: dict[str, str]):
        import asyncio

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_devserver",
            "call",
            "read_file",
            '{"path": "../../etc/passwd"}',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        _stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        assert process.returncode == 1

    async def test_tools_lists_the_published_set(self, environment: dict[str, str]):
        import asyncio

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_devserver",
            "tools",
            "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        declarations = json.loads(stdout.decode("utf-8"))
        assert [tool["name"] for tool in declarations] == [
            "find_symbol",
            "git_diff",
            "git_log",
            "list_directory",
            "project_overview",
            "read_file",
            "search_code",
        ]
