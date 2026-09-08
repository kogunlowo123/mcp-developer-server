"""The containment boundary."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from mcp_devserver.errors import (
    ERROR_BINARY,
    ERROR_DENIED_PATH,
    ERROR_NOT_A_DIRECTORY,
    ERROR_NOT_A_FILE,
    ERROR_NOT_FOUND,
    ERROR_OUTSIDE_WORKSPACE,
    ERROR_TOO_LARGE,
    ConfigurationError,
    SandboxError,
)
from mcp_devserver.sandbox.denylist import Denylist
from mcp_devserver.sandbox.workspace import Workspace

pytestmark = pytest.mark.unit


class TestConstruction:
    def test_a_missing_root_is_refused_at_construction(self, tmp_path: Path):
        with pytest.raises(ConfigurationError, match="cannot be resolved"):
            Workspace(tmp_path / "nope")

    def test_a_file_is_not_a_workspace(self, workspace_root: Path):
        with pytest.raises(ConfigurationError, match="not a directory"):
            Workspace(workspace_root / "README.md")

    def test_a_filesystem_root_is_refused(self, workspace_root: Path):
        # Serving `/` or `C:\` would put every readable file on the machine
        # inside the sandbox, which is the same as having no sandbox.
        anchor = Path(workspace_root.anchor)
        with pytest.raises(ConfigurationError, match="filesystem root"):
            Workspace(anchor)

    def test_the_root_is_resolved(self, workspace_root: Path):
        indirect = workspace_root / "src" / ".." / "docs" / ".."
        assert Workspace(indirect).root == workspace_root.resolve()


class TestContainment:
    def test_a_relative_path_inside_resolves(self, workspace: Workspace):
        resolved = workspace.resolve("src/demo/core.py")
        assert resolved.name == "core.py"
        assert workspace.contains(resolved)

    def test_traversal_out_of_the_workspace_is_refused(self, workspace: Workspace):
        with pytest.raises(SandboxError) as caught:
            workspace.resolve("../../etc/passwd")
        assert caught.value.code == ERROR_OUTSIDE_WORKSPACE

    def test_traversal_that_returns_inside_is_allowed(self, workspace: Workspace):
        # `docs/../src/demo/core.py` names a file that really is inside. A
        # sandbox that refused every path containing `..` would be refusing
        # correctness rather than attacks.
        assert workspace.resolve("docs/../src/demo/core.py").name == "core.py"

    def test_an_absolute_path_inside_the_workspace_is_allowed(self, workspace: Workspace):
        target = workspace.root / "README.md"
        assert workspace.resolve(str(target)) == target

    def test_an_absolute_path_outside_the_workspace_is_refused(
        self, workspace: Workspace, outside_secret: Path
    ):
        with pytest.raises(SandboxError) as caught:
            workspace.resolve(str(outside_secret))
        assert caught.value.code == ERROR_OUTSIDE_WORKSPACE

    def test_the_denial_message_does_not_echo_the_resolved_path(
        self, workspace: Workspace, outside_secret: Path
    ):
        # A denial that names the absolute path it refused is an oracle: a
        # caller can map the filesystem outside the sandbox one refusal at a
        # time.
        with pytest.raises(SandboxError) as caught:
            workspace.resolve("../../../../etc/shadow")
        assert str(outside_secret) not in caught.value.message
        assert "etc/shadow" in caught.value.message

    def test_a_nul_byte_in_a_path_is_refused(self, workspace: Workspace):
        # A NUL truncates the path at the operating-system boundary, so the
        # string that is checked and the string that is opened differ.
        with pytest.raises(SandboxError) as caught:
            workspace.resolve("README.md\x00.png")
        assert caught.value.code == ERROR_OUTSIDE_WORKSPACE

    def test_an_empty_path_is_the_root(self, workspace: Workspace):
        assert workspace.resolve("") == workspace.root
        assert workspace.resolve(".") == workspace.root

    def test_a_symlink_escaping_the_workspace_is_refused(
        self, workspace: Workspace, escaping_symlink: Path | None
    ):
        if escaping_symlink is None:
            pytest.skip("this platform does not allow creating symbolic links")
        with pytest.raises(SandboxError) as caught:
            workspace.resolve("notes.txt")
        # The link resolves outside, so containment refuses it before the
        # symlink policy is even consulted.
        assert caught.value.code == ERROR_OUTSIDE_WORKSPACE

    def test_a_symlink_inside_the_workspace_is_still_refused_by_default(self, workspace_root: Path):
        link = workspace_root / "alias.py"
        try:
            link.symlink_to(workspace_root / "src" / "demo" / "core.py")
        except (OSError, NotImplementedError):
            pytest.skip("this platform does not allow creating symbolic links")
        workspace = Workspace(workspace_root)
        with pytest.raises(SandboxError) as caught:
            workspace.resolve("alias.py")
        assert caught.value.code == ERROR_DENIED_PATH

    def test_a_symlink_inside_is_allowed_when_following_is_enabled(self, workspace_root: Path):
        link = workspace_root / "alias.py"
        try:
            link.symlink_to(workspace_root / "src" / "demo" / "core.py")
        except (OSError, NotImplementedError):
            pytest.skip("this platform does not allow creating symbolic links")
        workspace = Workspace(workspace_root, follow_symlinks=True)
        assert workspace.resolve("alias.py").name == "core.py"

    def test_relative_rendering_is_posix(self, workspace: Workspace):
        resolved = workspace.resolve("src/demo/core.py")
        assert workspace.relative(resolved) == PurePosixPath("src/demo/core.py")
        assert "\\" not in str(workspace.relative(resolved))

    def test_the_root_displays_as_its_directory_name(self, workspace: Workspace):
        assert workspace.display(workspace.root) == "demo-project/"


class TestDenylist:
    @pytest.mark.parametrize("path", [".env", "deploy.pem", ".ssh/config"])
    def test_denied_files_are_refused_even_though_they_are_inside(
        self, workspace: Workspace, path: str
    ):
        with pytest.raises(SandboxError) as caught:
            workspace.resolve(path)
        assert caught.value.code == ERROR_DENIED_PATH

    def test_the_denylist_matches_the_resolved_path_not_the_requested_one(
        self, workspace: Workspace
    ):
        # `docs/../.env` contains no denied component until it is resolved.
        with pytest.raises(SandboxError) as caught:
            workspace.resolve("docs/../.env")
        assert caught.value.code == ERROR_DENIED_PATH

    def test_configuration_can_extend_but_not_shorten_the_denylist(self, workspace_root: Path):
        workspace = Workspace(workspace_root, denylist=Denylist.with_extra(["README.md"]))
        with pytest.raises(SandboxError):
            workspace.resolve("README.md")
        # The built-in entries survive the extension.
        with pytest.raises(SandboxError):
            workspace.resolve(".env")


class TestReading:
    def test_reading_a_text_file(self, workspace: Workspace):
        text = workspace.read_text(workspace.resolve("README.md"))
        assert "A fixture project." in text

    def test_a_directory_is_not_a_file(self, workspace: Workspace):
        with pytest.raises(SandboxError) as caught:
            workspace.require_file(workspace.resolve("src"))
        assert caught.value.code == ERROR_NOT_A_FILE

    def test_a_file_is_not_a_directory(self, workspace: Workspace):
        with pytest.raises(SandboxError) as caught:
            workspace.require_directory(workspace.resolve("README.md"))
        assert caught.value.code == ERROR_NOT_A_DIRECTORY

    def test_a_missing_file_reports_not_found(self, workspace: Workspace):
        with pytest.raises(SandboxError) as caught:
            workspace.require_file(workspace.resolve("does-not-exist.py"))
        assert caught.value.code == ERROR_NOT_FOUND

    def test_a_binary_file_is_refused(self, workspace: Workspace):
        with pytest.raises(SandboxError) as caught:
            workspace.read_text(workspace.resolve("logo.bin"))
        assert caught.value.code == ERROR_BINARY

    def test_a_file_over_the_limit_is_refused_before_it_is_read(self, workspace_root: Path):
        big = workspace_root / "big.txt"
        big.write_text("x" * 5_000, encoding="utf-8")
        workspace = Workspace(workspace_root, max_file_bytes=1_024)
        with pytest.raises(SandboxError) as caught:
            workspace.read_text(workspace.resolve("big.txt"))
        assert caught.value.code == ERROR_TOO_LARGE
        assert "1024-byte limit" in caught.value.message

    def test_a_per_call_limit_cannot_exceed_the_workspace_limit(self, workspace_root: Path):
        # A caller asking for more than the deployment allows gets the
        # deployment's answer, not their own.
        big = workspace_root / "big.txt"
        big.write_text("x" * 5_000, encoding="utf-8")
        workspace = Workspace(workspace_root, max_file_bytes=1_024)
        with pytest.raises(SandboxError):
            workspace.read_text(workspace.resolve("big.txt"), max_bytes=1_000_000)


class TestWalking:
    def test_generated_directories_are_skipped(self, workspace: Workspace):
        found = {str(workspace.relative(path)) for path in workspace.walk(workspace.root)}
        assert "src/demo/core.py" in found
        assert not any(name.startswith("node_modules/") for name in found)

    def test_denied_files_never_appear_in_a_walk(self, workspace: Workspace):
        found = {str(workspace.relative(path)) for path in workspace.walk(workspace.root)}
        assert ".env" not in found
        assert "deploy.pem" not in found
        assert ".ssh/config" not in found

    def test_a_walk_stops_at_the_entry_cap(self, workspace: Workspace):
        assert len(list(workspace.walk(workspace.root, max_entries=3))) == 3

    def test_symlinks_are_not_followed_during_a_walk(
        self, workspace: Workspace, escaping_symlink: Path | None
    ):
        if escaping_symlink is None:
            pytest.skip("this platform does not allow creating symbolic links")
        found = {str(workspace.relative(path)) for path in workspace.walk(workspace.root)}
        assert "notes.txt" not in found
