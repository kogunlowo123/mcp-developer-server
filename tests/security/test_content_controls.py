"""Secrets on the way out, untrusted content on the way in, and the git subprocess.

Three separate claims, each asserted end to end through the server rather than
against the helper that implements it — because the interesting failure is a
control that exists and is not wired up.
"""

from __future__ import annotations

import json
import pathlib
from pathlib import Path
from typing import Any

import pytest

from mcp_devserver.errors import ToolExecutionError
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import Server
from mcp_devserver.tools import BUILTIN_TOOLS, build_registry
from mcp_devserver.tools.base import ToolContext
from mcp_devserver.tools.git import (
    ALLOWED_SUBCOMMANDS,
    _git_environment,
    _validate_revision,
    git_diff,
    git_log,
)
from tests.conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, call

pytestmark = pytest.mark.security

#: A path used only as attack-payload text. Nothing writes to it, and the
#: tests assert that nothing does.
_SENTINEL = "/tmp/mcp-devserver-should-never-exist"  # noqa: S108


async def invoke(server: Server, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = await server.handle_payload(call(name, arguments))
    assert response is not None
    assert "error" not in response, response["error"]
    return dict(response["result"])


class TestSecretsDoNotLeave:
    async def test_reading_a_file_redacts_a_hard_coded_credential(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/settings.py"})
        rendered = json.dumps(result)
        assert FAKE_AWS_KEY not in rendered
        assert FAKE_GITHUB_TOKEN not in rendered
        assert "[redacted:aws-access-key-id]" in rendered

    async def test_the_variable_name_survives_so_the_answer_is_still_useful(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/settings.py"})
        assert "AWS_ACCESS_KEY_ID" in json.dumps(result)

    async def test_searching_for_a_secret_returns_its_location_not_its_value(self, server: Server):
        # "Do we leak keys anywhere?" is a real question, and the useful answer
        # is the file and line — not the key.
        result = await invoke(server, "search_code", {"pattern": "AWS_ACCESS_KEY_ID"})
        rendered = json.dumps(result)
        assert "src/demo/settings.py" in rendered
        assert FAKE_AWS_KEY not in rendered

    async def test_a_connection_string_password_is_redacted(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/settings.py"})
        rendered = json.dumps(result)
        assert "hunter2" not in rendered
        assert "db.internal" in rendered

    async def test_redaction_is_reported_so_it_is_auditable(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/settings.py"})
        redaction = result["structuredContent"]["redaction"]
        assert redaction["applied"] is True
        assert redaction["count"] >= 3
        assert "aws-access-key-id" in redaction["rules"]

    async def test_a_documented_placeholder_is_not_redacted(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/settings.py"})
        assert "REPLACE_ME" in json.dumps(result)

    async def test_every_result_reports_its_redaction_state(self, server: Server):
        # Including when nothing was redacted: a client cannot tell whether the
        # control ran unless it always says so.
        result = await invoke(server, "read_file", {"path": "README.md"})
        assert result["structuredContent"]["redaction"]["applied"] is False

    async def test_no_part_of_a_result_carries_a_credential(self, server: Server):
        # The whole envelope, not one member of it. An earlier version redacted
        # the prose and not the structured half; the version after that redacted
        # both and then attached a scanner excerpt taken from the raw content.
        result = await invoke(server, "read_file", {"path": "src/demo/settings.py"})
        rendered = json.dumps(result)
        assert FAKE_AWS_KEY not in rendered
        assert FAKE_GITHUB_TOKEN not in rendered
        assert "hunter2" not in rendered

    async def test_a_search_result_carries_no_credential_in_either_half(self, server: Server):
        result = await invoke(server, "search_code", {"pattern": "TOKEN"})
        rendered = json.dumps(result)
        assert FAKE_GITHUB_TOKEN not in rendered
        assert FAKE_AWS_KEY not in rendered


class TestUntrustedContentIsMarkedNotRewritten:
    async def test_an_injected_instruction_is_returned_exactly_as_it_is_on_disk(
        self, server: Server, workspace_root: Path
    ):
        # The central design decision of this server, asserted against the real
        # bytes: the developer asked to read this file, so they see this file.
        on_disk = (workspace_root / "src" / "demo" / "vendored.py").read_text(encoding="utf-8")
        result = await invoke(server, "read_file", {"path": "src/demo/vendored.py"})
        body = result["content"][1]["text"]
        for line in on_disk.splitlines():
            if line:
                assert line in body

    async def test_it_is_marked(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/vendored.py"})
        structured = result["structuredContent"]
        assert structured["untrusted_content"] is True
        assessment = structured["content_assessment"]
        assert assessment["level"] == "high"
        signals = {finding["signal"] for finding in assessment["signals"]}
        assert signals >= {"INJ01", "INJ10"}

    async def test_it_is_fenced_with_an_unguessable_nonce(self, server: Server):
        result = await invoke(server, "read_file", {"path": "src/demo/vendored.py"})
        body = result["content"][1]["text"]
        assert body.startswith("<untrusted-file-content id=")
        opening = body.split("\n", 1)[0]
        nonce = opening.removeprefix("<untrusted-file-content id=").removesuffix(">")
        assert len(nonce) >= 16
        assert body.rstrip().endswith(f"</untrusted-file-content id={nonce}>")

    async def test_a_search_hit_on_injected_text_is_marked_too(self, server: Server):
        result = await invoke(server, "search_code", {"pattern": "ignore all previous"})
        assert result["structuredContent"]["untrusted_content"] is True
        assert result["structuredContent"]["content_assessment"]["level"] == "high"

    async def test_finding_injected_content_is_something_this_server_can_do(self, server: Server):
        # A server that neutralised content would destroy the evidence a
        # security review is looking for. This is that review, run as a test.
        result = await invoke(
            server, "search_code", {"pattern": "ignore all previous instructions"}
        )
        assert result["structuredContent"]["match_count"] >= 1
        assert "src/demo/vendored.py" in json.dumps(result)

    async def test_the_summary_names_the_file_without_repeating_the_instruction(
        self, server: Server
    ):
        result = await invoke(server, "read_file", {"path": "src/demo/vendored.py"})
        summary = result["content"][0]["text"]
        assert "src/demo/vendored.py" in summary
        assert "ignore all previous" not in summary.lower()

    async def test_ordinary_documentation_is_not_flagged_as_high_risk(self, server: Server):
        # The negative control. A control that fires on every README is one
        # every client will learn to ignore.
        result = await invoke(server, "read_file", {"path": "docs/guide.md"})
        assert result["structuredContent"]["content_assessment"]["level"] != "high"


class TestTheToolSetIsReadOnly:
    def test_no_published_tool_can_modify_the_workspace(self):
        # A property of the set, checked by inspection, so that adding a write
        # tool cannot happen quietly.
        forbidden = {
            "write",
            "create",
            "delete",
            "remove",
            "move",
            "rename",
            "exec",
            "run",
            "shell",
        }
        for name in build_registry().names():
            assert not any(word in name.split("_") for word in forbidden), name

    def test_every_tool_declares_itself_read_only(self):
        for declaration in build_registry().declarations():
            annotations = declaration["annotations"]
            assert annotations["readOnlyHint"] is True
            assert annotations["destructiveHint"] is False

    def test_the_published_set_is_exactly_the_seven_documented_tools(self):
        assert build_registry().names() == (
            "find_symbol",
            "git_diff",
            "git_log",
            "list_directory",
            "project_overview",
            "read_file",
            "search_code",
        )

    def test_every_tool_that_returns_file_bytes_marks_them(
        self, tool_context: ToolContext, server: Server
    ):
        for tool in BUILTIN_TOOLS:
            if not tool.returns_file_content:
                continue
            assert "untrusted" in tool.description.lower(), tool.name


class TestGitSubprocessHardening:
    def test_only_two_subcommands_are_reachable(self):
        assert {"log", "diff"} == ALLOWED_SUBCOMMANDS

    #: Values a caller might supply hoping they reach git as something other
    #: than a revision. The dashed ones are the dangerous class: git has options
    #: that name a program to run. The shell metacharacters cannot reach a shell
    #: here — there is no shell — but they are refused anyway, because a value
    #: that is not a revision should never be treated as one.
    HOSTILE_REVISIONS = (
        "--upload-pack=touch " + _SENTINEL,
        "-c core.pager=sh",
        "--output=" + _SENTINEL,
        "HEAD; rm -rf /",
        "HEAD && whoami",
        "$(whoami)",
        "`whoami`",
        "HEAD|tee " + _SENTINEL,
    )

    @pytest.mark.parametrize("revision", HOSTILE_REVISIONS)
    async def test_the_published_schema_refuses_an_option_shaped_revision(
        self, git_workspace: Path, server: Server, revision: str
    ):
        # The outer layer. The tool's inputSchema constrains `revision` to a
        # charset that excludes every character below, so the request never
        # reaches the handler.
        response = await server.handle_payload(call("git_log", {"revision": revision}))
        assert response is not None
        assert response["error"]["code"] == spec.INVALID_PARAMS
        assert "revision" in response["error"]["message"]

    @pytest.mark.parametrize("revision", HOSTILE_REVISIONS)
    def test_the_handler_refuses_it_too(self, revision: str):
        # Defence in depth. The schema is one layer; this asserts the second,
        # so that a schema loosened in a future change does not silently remove
        # the only check.
        with pytest.raises(ToolExecutionError) as caught:
            _validate_revision(revision, field="revision")
        assert caught.value.code == "git_failed"

    def test_a_dash_prefixed_revision_is_named_as_the_reason(self):
        with pytest.raises(ToolExecutionError, match="may not begin with"):
            _validate_revision("-c core.pager=sh", field="revision")

    def test_an_empty_revision_is_refused(self):
        with pytest.raises(ToolExecutionError, match="is empty"):
            _validate_revision("   ", field="revision")

    @pytest.mark.parametrize("revision", ["HEAD", "HEAD~1", "main", "HEAD~1..HEAD", "@{0}"])
    async def test_legitimate_revisions_are_accepted(
        self, git_workspace: Path, tool_context: ToolContext, revision: str
    ):
        result = build_registry().invoke("git_log", {"revision": revision}, tool_context)
        # Some of these may not resolve in a two-commit repository; what matters
        # is that they are not refused by the validator.
        if result["isError"]:
            assert "not allowed in a revision" not in result["structuredContent"]["message"]
            assert "may not begin with" not in result["structuredContent"]["message"]

    async def test_a_path_argument_cannot_become_an_option(
        self, git_workspace: Path, tool_context: ToolContext
    ):
        # Paths go after the `--` separator, so git treats even a dash-prefixed
        # value as a path name. The call succeeds and finds nothing, which is
        # exactly right: `--output=/tmp/pwned` is a file that does not exist,
        # not an instruction to write one.
        result = build_registry().invoke("git_log", {"path": "--output=" + _SENTINEL}, tool_context)
        assert result["isError"] is False
        assert result["structuredContent"]["commit_count"] == 0
        assert not pathlib.Path(_SENTINEL).exists()

    def test_the_child_environment_carries_no_program_hooks(self, workspace_root: Path):
        environment = _git_environment(workspace_root)
        # Each of these names a program git would run.
        for hook in ("GIT_EDITOR", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF"):
            assert hook not in environment
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["HOME"] == str(workspace_root)

    def test_the_child_environment_is_built_not_inherited(
        self, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("GIT_EXTERNAL_DIFF", _SENTINEL)
        monkeypatch.setenv("SOMETHING_ELSE", "leaked")
        environment = _git_environment(workspace_root)
        assert "GIT_EXTERNAL_DIFF" not in environment
        assert "SOMETHING_ELSE" not in environment

    async def test_a_user_gitconfig_alias_cannot_run(
        self, git_workspace: Path, tool_context: ToolContext, tmp_path: Path
    ):
        # HOME points at the workspace and global config is disabled, so an
        # alias or pager defined in the developer's ~/.gitconfig is not read.
        result = git_log(tool_context, {"limit": 1})
        assert result.structured["commit_count"] == 1

    async def test_the_output_cap_truncates_rather_than_returning_everything(
        self, git_workspace: Path, tool_context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr("mcp_devserver.tools.git.MAX_OUTPUT_BYTES", 64)
        (git_workspace / "README.md").write_text("x\n" * 5_000, encoding="utf-8")
        result = git_diff(tool_context, {})
        assert result.structured["truncated"] is True
        assert len(result.untrusted) <= 64
