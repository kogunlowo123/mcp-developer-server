"""Attempts to read something the sandbox exists to keep unreachable.

A failure in this file is a security regression, not a bug. Every case is an
attack that would work against one of the obvious wrong implementations
described in ``sandbox/workspace.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_devserver.protocol.server import Server
from tests.conftest import call

pytestmark = pytest.mark.security

#: Every published tool that takes a path, and the argument name it uses.
PATH_TOOLS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("read_file", "path", {}),
    ("list_directory", "path", {}),
    ("search_code", "path", {"pattern": "x"}),
    ("find_symbol", "path", {"symbol": "x"}),
    ("project_overview", "path", {}),
    ("git_log", "path", {}),
    ("git_diff", "path", {}),
)

#: Paths that must never resolve to something the caller can read.
ESCAPES: tuple[str, ...] = (
    "../../etc/passwd",
    "../../../../../../etc/shadow",
    "..",
    "../",
    "docs/../../outside",
    "docs/../../../root/.ssh/id_rsa",
    "./../../..",
    "src/../../..",
)


async def invoke(server: Server, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = await server.handle_payload(call(name, arguments))
    assert response is not None
    if "error" in response:
        return {"protocol_error": response["error"]}
    return dict(response["result"])


class TestPathTraversal:
    @pytest.mark.parametrize(("tool", "argument", "extra"), PATH_TOOLS)
    @pytest.mark.parametrize("escape", ESCAPES)
    async def test_no_tool_accepts_a_traversing_path(
        self, server: Server, tool: str, argument: str, extra: dict[str, Any], escape: str
    ):
        result = await invoke(server, tool, {**extra, argument: escape})
        if "protocol_error" in result:
            return
        assert result["isError"] is True
        assert result["structuredContent"]["error"] in {
            "outside_workspace",
            "denied_path",
            "not_found",
            "not_a_repository",
        }

    async def test_an_absolute_path_outside_the_workspace_is_refused(
        self, server: Server, outside_secret: Path
    ):
        result = await invoke(server, "read_file", {"path": str(outside_secret)})
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == "outside_workspace"

    async def test_the_refusal_does_not_disclose_the_absolute_path(
        self, server: Server, outside_secret: Path
    ):
        # A denial that echoes the path it refused lets a caller map the
        # filesystem outside the sandbox one request at a time.
        result = await invoke(server, "read_file", {"path": "../../../../etc/passwd"})
        rendered = json.dumps(result)
        assert str(outside_secret.parent) not in rendered
        assert str(server.workspace.root.parent) not in rendered

    async def test_a_nul_byte_cannot_truncate_a_path(self, server: Server):
        result = await invoke(server, "read_file", {"path": "README.md\x00/../../.env"})
        assert result["isError"] is True

    @pytest.mark.parametrize("encoded", ["%2e%2e/%2e%2e/etc/passwd", "..%2f..%2fetc%2fpasswd"])
    async def test_url_encoded_traversal_is_not_decoded(self, server: Server, encoded: str):
        # Nothing in this server percent-decodes a path, so these are ordinary
        # file names that do not exist. The assertion is that they stay that
        # way: a future change adding decoding would make them escapes.
        result = await invoke(server, "read_file", {"path": encoded})
        assert result["isError"] is True
        assert result["structuredContent"]["error"] in {"not_found", "outside_workspace"}


class TestSymlinkEscape:
    async def test_a_symlink_out_of_the_workspace_cannot_be_read(
        self, server: Server, escaping_symlink: Path | None
    ):
        if escaping_symlink is None:
            pytest.skip("this platform does not allow creating symbolic links")
        result = await invoke(server, "read_file", {"path": "notes.txt"})
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == "outside_workspace"

    async def test_a_symlinked_directory_is_not_walked(
        self, server: Server, workspace_root: Path, tmp_path: Path
    ):
        target = tmp_path / "elsewhere"
        target.mkdir(exist_ok=True)
        (target / "secret.py").write_text("PASSWORD = 'hunter2'\n", encoding="utf-8")
        try:
            (workspace_root / "linked").symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("this platform does not allow creating symbolic links")
        result = await invoke(server, "search_code", {"pattern": "hunter2"})
        assert result["structuredContent"]["match_count"] == 0

    async def test_a_symlink_created_after_a_listing_is_still_not_followed(
        self, server: Server, workspace_root: Path, outside_secret: Path
    ):
        try:
            (workspace_root / "late.txt").symlink_to(outside_secret)
        except (OSError, NotImplementedError):
            pytest.skip("this platform does not allow creating symbolic links")
        # The server holds no cached view of the tree, so the check happens at
        # the moment of the read rather than against a stale listing.
        result = await invoke(server, "read_file", {"path": "late.txt"})
        assert result["isError"] is True


class TestDenylist:
    @pytest.mark.parametrize(
        "path", [".env", "deploy.pem", ".ssh/config", "docs/../.env", "./.env"]
    )
    async def test_denied_files_cannot_be_read_by_any_spelling(self, server: Server, path: str):
        result = await invoke(server, "read_file", {"path": path})
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == "denied_path"

    async def test_denied_files_do_not_appear_in_search_results(self, server: Server):
        from tests.conftest import FAKE_AWS_KEY

        result = await invoke(server, "search_code", {"pattern": FAKE_AWS_KEY})
        paths = {match["path"] for match in result["structuredContent"]["matches"]}
        assert ".env" not in paths

    async def test_denied_files_do_not_appear_in_a_listing(self, server: Server):
        result = await invoke(server, "list_directory", {"include_hidden": True})
        names = {entry["name"] for entry in result["structuredContent"]["entries"]}
        assert ".env" not in names
        assert "deploy.pem" not in names

    async def test_the_git_directory_is_never_readable(self, git_workspace: Path, server: Server):
        # History reaches git through the binary with a fixed argument vector;
        # nothing needs raw access to the object store, and .git/config
        # routinely holds a credential-bearing remote URL.
        for path in (".git", ".git/config", ".git/HEAD"):
            result = await invoke(server, "read_file", {"path": path})
            assert result["isError"] is True
            assert result["structuredContent"]["error"] == "denied_path"

    async def test_extra_denied_entries_from_configuration_are_enforced(self, workspace_root: Path):
        from mcp_devserver.config import Settings

        settings = Settings(
            sandbox={
                "workspace": workspace_root,
                "deny_extra": ["README.md"],
            }
        )
        result = await invoke(Server(settings), "read_file", {"path": "README.md"})
        assert result["isError"] is True

    async def test_configuration_cannot_remove_a_builtin_denial(self, workspace_root: Path):
        from mcp_devserver.config import Settings

        # deny_extra is additive by construction; there is no setting that
        # shortens the list. This asserts the absence, which is the property
        # that matters.
        settings = Settings(sandbox={"workspace": workspace_root, "deny_extra": []})
        result = await invoke(Server(settings), "read_file", {"path": ".env"})
        assert result["isError"] is True
