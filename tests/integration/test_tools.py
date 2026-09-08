"""The tools, against a real temporary workspace."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_devserver.errors import (
    ERROR_BAD_PATTERN,
    ERROR_DENIED_PATH,
    ERROR_NOT_A_REPOSITORY,
    ERROR_NOT_FOUND,
    ERROR_OUTSIDE_WORKSPACE,
    ERROR_UNSUPPORTED,
    SandboxError,
    ToolExecutionError,
)
from mcp_devserver.tools import build_registry
from mcp_devserver.tools.base import ToolContext
from mcp_devserver.tools.files import list_directory, read_file
from mcp_devserver.tools.git import git_diff, git_log
from mcp_devserver.tools.overview import project_overview
from mcp_devserver.tools.search import MAX_PATTERN_LENGTH, search_code
from mcp_devserver.tools.symbols import find_symbol

pytestmark = pytest.mark.integration


def structured(context: ToolContext, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Invoke through the registry and return the structured half of the result."""
    result = build_registry().invoke(name, arguments, context)
    return dict(result["structuredContent"])


class TestReadFile:
    def test_reading_a_whole_file(self, tool_context: ToolContext):
        result = read_file(tool_context, {"path": "README.md"})
        assert result.structured["path"] == "README.md"
        assert result.structured["total_lines"] == 3
        assert "A fixture project." in result.untrusted

    def test_lines_are_numbered(self, tool_context: ToolContext):
        result = read_file(tool_context, {"path": "README.md"})
        assert result.untrusted.splitlines()[0].startswith("1  ")

    def test_a_line_range(self, tool_context: ToolContext):
        result = read_file(
            tool_context, {"path": "src/demo/core.py", "start_line": 6, "end_line": 7}
        )
        assert result.structured["start_line"] == 6
        assert result.structured["end_line"] == 7
        assert "class Engine" in result.untrusted
        assert "TIMEOUT" not in result.untrusted

    def test_a_range_past_the_end_of_the_file(self, tool_context: ToolContext):
        with pytest.raises(ToolExecutionError) as caught:
            read_file(tool_context, {"path": "README.md", "start_line": 900})
        assert caught.value.code == ERROR_UNSUPPORTED
        assert "does not exist" in caught.value.message

    def test_an_inverted_range(self, tool_context: ToolContext):
        with pytest.raises(ToolExecutionError, match="before start_line"):
            read_file(tool_context, {"path": "README.md", "start_line": 3, "end_line": 1})

    def test_the_line_budget_truncates_and_says_so(
        self, tool_context: ToolContext, workspace_root: Path
    ):
        (workspace_root / "long.txt").write_text(
            "\n".join(str(number) for number in range(2_000)), encoding="utf-8"
        )
        result = read_file(tool_context, {"path": "long.txt"})
        assert result.structured["truncated"] is True
        assert result.structured["end_line"] == tool_context.limits.max_read_lines

    def test_a_denied_file_is_refused(self, tool_context: ToolContext):
        with pytest.raises(SandboxError) as caught:
            read_file(tool_context, {"path": ".env"})
        assert caught.value.code == ERROR_DENIED_PATH

    def test_a_denial_becomes_an_error_result_not_an_exception(self, tool_context: ToolContext):
        result = build_registry().invoke("read_file", {"path": ".env"}, tool_context)
        assert result["isError"] is True
        assert result["structuredContent"]["error"] == ERROR_DENIED_PATH
        assert result["structuredContent"]["remedy"]


class TestListDirectory:
    def test_listing_the_root(self, tool_context: ToolContext):
        result = list_directory(tool_context, {})
        names = {entry["name"] for entry in result.structured["entries"]}
        assert {"src", "tests", "docs", "README.md"} <= names

    def test_dot_files_are_hidden_by_default(self, tool_context: ToolContext):
        names = {entry["name"] for entry in list_directory(tool_context, {}).structured["entries"]}
        assert ".ssh" not in names

    def test_denied_entries_are_counted_rather_than_named(self, tool_context: ToolContext):
        result = list_directory(tool_context, {"include_hidden": True})
        names = {entry["name"] for entry in result.structured["entries"]}
        assert ".env" not in names
        assert result.structured["hidden_by_denylist"] >= 1

    def test_directories_report_whether_search_will_walk_them(self, tool_context: ToolContext):
        entries = {
            entry["name"]: entry for entry in list_directory(tool_context, {}).structured["entries"]
        }
        assert entries["src"]["walked_by_search"] is True
        assert entries["node_modules"]["walked_by_search"] is False

    def test_listing_a_file_is_refused(self, tool_context: ToolContext):
        with pytest.raises(SandboxError):
            list_directory(tool_context, {"path": "README.md"})


class TestSearchCode:
    def test_a_literal_search(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "class Engine"})
        assert result.structured["match_count"] == 1
        assert result.structured["matches"][0]["path"] == "src/demo/core.py"
        assert result.structured["matches"][0]["line"] == 6

    def test_a_literal_search_does_not_treat_the_pattern_as_a_regular_expression(
        self, tool_context: ToolContext
    ):
        # `Engine()` contains regex metacharacters. Without escaping, this would
        # match `Engine` and mislead.
        result = search_code(tool_context, {"pattern": "build_engine(config)"})
        assert result.structured["match_count"] == 1

    def test_a_regular_expression_search(self, tool_context: ToolContext):
        result = search_code(
            tool_context, {"pattern": r"^def \w+\(", "regex": True, "file_glob": ["*.py"]}
        )
        assert result.structured["match_count"] >= 1

    def test_an_invalid_regular_expression_is_a_tool_error(self, tool_context: ToolContext):
        with pytest.raises(ToolExecutionError) as caught:
            search_code(tool_context, {"pattern": "(unclosed", "regex": True})
        assert caught.value.code == ERROR_BAD_PATTERN
        assert "set regex to false" in caught.value.remedy.lower()

    def test_an_overlong_pattern_is_refused_before_compilation(self, tool_context: ToolContext):
        with pytest.raises(ToolExecutionError) as caught:
            search_code(tool_context, {"pattern": "a" * (MAX_PATTERN_LENGTH + 1)})
        assert caught.value.code == ERROR_BAD_PATTERN

    def test_case_sensitivity(self, tool_context: ToolContext):
        assert search_code(tool_context, {"pattern": "ENGINE"}).structured["match_count"] > 0
        insensitive = search_code(tool_context, {"pattern": "ENGINE", "case_sensitive": True})
        assert insensitive.structured["match_count"] == 0

    def test_a_glob_restricts_the_search(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "Widget", "file_glob": ["*.ts"]})
        assert {match["path"] for match in result.structured["matches"]} == {"src/demo/widget.ts"}

    def test_context_lines_are_returned(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "class Engine", "context_lines": 1})
        match = result.structured["matches"][0]
        assert match["before"]
        assert match["after"]

    def test_generated_trees_are_not_searched(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "left"})
        assert all(
            not match["path"].startswith("node_modules/") for match in result.structured["matches"]
        )

    def test_denied_files_are_never_searched(self, tool_context: ToolContext):
        from tests.conftest import FAKE_AWS_KEY

        result = search_code(tool_context, {"pattern": FAKE_AWS_KEY})
        assert all(match["path"] != ".env" for match in result.structured["matches"])

    def test_binary_files_are_skipped_and_counted(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "z"})
        assert result.structured["files_skipped"] >= 1

    def test_the_result_cap_is_honoured(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "e", "max_results": 3})
        assert result.structured["match_count"] == 3
        assert result.structured["truncated"] is True

    def test_searching_a_single_file(self, tool_context: ToolContext):
        result = search_code(tool_context, {"pattern": "Engine", "path": "src/demo/core.py"})
        assert result.structured["files_scanned"] == 1

    def test_searching_a_missing_path(self, tool_context: ToolContext):
        with pytest.raises(ToolExecutionError) as caught:
            search_code(tool_context, {"pattern": "x", "path": "nowhere"})
        assert caught.value.code == ERROR_NOT_FOUND

    def test_searching_outside_the_workspace(self, tool_context: ToolContext):
        with pytest.raises(SandboxError) as caught:
            search_code(tool_context, {"pattern": "x", "path": "../.."})
        assert caught.value.code == ERROR_OUTSIDE_WORKSPACE


class TestFindSymbol:
    def test_a_python_class_is_found_by_parsing(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "Engine"})
        definition = next(
            item for item in result.structured["definitions"] if item["kind"] == "class"
        )
        assert definition["method"] == "parsed"
        assert definition["path"] == "src/demo/core.py"
        assert definition["line"] == 6

    def test_a_method_is_distinguished_from_a_function(self, tool_context: ToolContext):
        start = find_symbol(tool_context, {"symbol": "start"}).structured["definitions"]
        assert start[0]["kind"] == "method"
        assert start[0]["qualified_name"] == "Engine.start"

        build = find_symbol(tool_context, {"symbol": "build_engine"}).structured["definitions"]
        assert build[0]["kind"] == "function"

    def test_an_async_method_is_found(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "stop"})
        assert "async def stop" in result.structured["definitions"][0]["signature"]

    def test_a_module_level_variable_is_found(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "TIMEOUT"})
        assert result.structured["definitions"][0]["kind"] == "variable"

    def test_a_kind_filter(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "Engine", "kind": "class"})
        assert all(item["kind"] == "class" for item in result.structured["definitions"])

    def test_another_language_is_matched_by_pattern_and_says_so(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "Widget"})
        typescript = [
            item for item in result.structured["definitions"] if item["language"] == "typescript"
        ]
        assert typescript
        assert all(item["method"] == "pattern" for item in typescript)

    def test_parsed_results_are_ranked_above_pattern_results(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "Engine", "exact": False})
        methods = [item["method"] for item in result.structured["definitions"]]
        assert methods == sorted(methods, key=lambda value: value != "parsed")

    def test_a_file_that_does_not_parse_is_reported(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "unfinished"})
        assert "src/demo/broken.py" in result.structured["unparseable_files"]

    def test_an_inexact_search_matches_substrings(self, tool_context: ToolContext):
        exact = find_symbol(tool_context, {"symbol": "engine"}).structured["definition_count"]
        loose = find_symbol(tool_context, {"symbol": "engine", "exact": False}).structured[
            "definition_count"
        ]
        assert loose > exact

    def test_the_counts_add_up(self, tool_context: ToolContext):
        result = find_symbol(tool_context, {"symbol": "Engine", "exact": False}).structured
        assert result["parsed_count"] + result["pattern_count"] == result["definition_count"]


class TestProjectOverview:
    def test_the_language_mix_is_measured(self, tool_context: ToolContext):
        result = project_overview(tool_context, {})
        languages = {item["language"]: item for item in result.structured["languages"]}
        assert languages["python"]["files"] >= 5
        assert languages["python"]["lines"] > 0
        assert "typescript" in languages

    def test_manifests_are_found_and_summarised(self, tool_context: ToolContext):
        result = project_overview(tool_context, {})
        manifests = {item["file"]: item for item in result.structured["manifests"]}
        assert manifests["pyproject.toml"]["declares"]["name"] == "demo"
        assert manifests["pyproject.toml"]["declares"]["version"] == "1.2.3"
        assert manifests["pyproject.toml"]["declares"]["dependencies"] == ["httpx", "structlog"]

    def test_a_malformed_manifest_reports_a_parse_error_rather_than_failing(
        self, tool_context: ToolContext, workspace_root: Path
    ):
        (workspace_root / "package.json").write_text("{not json", encoding="utf-8")
        result = project_overview(tool_context, {})
        manifests = {item["file"]: item for item in result.structured["manifests"]}
        assert "parse_error" in manifests["package.json"]["declares"]

    def test_test_files_are_counted(self, tool_context: ToolContext):
        assert project_overview(tool_context, {}).structured["test_files"] >= 1

    def test_generated_trees_are_excluded_from_the_counts(self, tool_context: ToolContext):
        result = project_overview(tool_context, {})
        assert "javascript" not in {item["language"] for item in result.structured["languages"]}

    def test_version_control_is_detected(self, tool_context: ToolContext):
        assert project_overview(tool_context, {}).structured["version_control"] == "none"

    def test_version_control_is_detected_in_a_repository(
        self, git_workspace: Path, tool_context: ToolContext
    ):
        assert project_overview(tool_context, {}).structured["version_control"] == "git"

    def test_the_summary_is_readable_without_the_structured_half(self, tool_context: ToolContext):
        text = project_overview(tool_context, {}).text
        assert "Languages:" in text
        assert "Manifests:" in text


class TestGit:
    def test_history_needs_a_repository(self, tool_context: ToolContext):
        with pytest.raises(ToolExecutionError) as caught:
            git_log(tool_context, {})
        assert caught.value.code == ERROR_NOT_A_REPOSITORY

    def test_recent_commits_are_returned(self, git_workspace: Path, tool_context: ToolContext):
        result = git_log(tool_context, {"limit": 10})
        subjects = [commit["subject"] for commit in result.structured["commits"]]
        assert subjects == ["Add the demo package", "Add the project skeleton"]
        assert result.structured["commits"][0]["author"] == "Fixture"

    def test_history_can_be_restricted_to_a_path(
        self, git_workspace: Path, tool_context: ToolContext
    ):
        result = git_log(tool_context, {"path": "README.md"})
        assert [commit["subject"] for commit in result.structured["commits"]] == [
            "Add the project skeleton"
        ]

    def test_the_limit_is_capped_by_configuration(
        self, git_workspace: Path, tool_context: ToolContext
    ):
        result = git_log(tool_context, {"limit": 1})
        assert result.structured["commit_count"] == 1

    def test_commit_messages_are_marked_untrusted(
        self, git_workspace: Path, tool_context: ToolContext
    ):
        # Anyone who can open a pull request can write a commit subject.
        rendered = build_registry().invoke("git_log", {}, tool_context)
        assert rendered["structuredContent"]["untrusted_content"] is True

    def test_a_diff_of_an_unchanged_tree_is_empty(
        self, git_workspace: Path, tool_context: ToolContext
    ):
        result = git_diff(tool_context, {})
        assert result.structured["files_changed"] == 0
        assert result.text.startswith("No changes")

    def test_a_diff_reports_what_changed(self, git_workspace: Path, tool_context: ToolContext):
        (git_workspace / "README.md").write_text("# Demo\n\nEdited.\n", encoding="utf-8")
        result = git_diff(tool_context, {})
        assert result.structured["files_changed"] == 1
        assert result.structured["lines_added"] >= 1
        assert "Edited." in result.untrusted

    def test_a_stat_only_diff_omits_the_body(self, git_workspace: Path, tool_context: ToolContext):
        (git_workspace / "README.md").write_text("# Demo\n\nEdited.\n", encoding="utf-8")
        result = git_diff(tool_context, {"stat_only": True})
        assert "Edited." not in result.untrusted
        assert "README.md" in result.untrusted

    def test_a_diff_against_a_revision(self, git_workspace: Path, tool_context: ToolContext):
        result = git_diff(tool_context, {"revision": "HEAD~1"})
        assert result.structured["files_changed"] >= 1

    def test_a_diff_restricted_to_a_path(self, git_workspace: Path, tool_context: ToolContext):
        (git_workspace / "README.md").write_text("# Demo\n\nEdited.\n", encoding="utf-8")
        result = git_diff(tool_context, {"path": "pyproject.toml"})
        assert result.structured["files_changed"] == 0
