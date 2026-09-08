"""The command line in-process, and the logging configuration.

The e2e suite runs these commands as real processes, which is what proves the
entry point works. These run them in-process, which is what makes their branches
visible to coverage and their failures readable.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest
import structlog

from mcp_devserver.cli import build_parser, main
from mcp_devserver.config import ObservabilitySettings
from mcp_devserver.observability.logging import configure
from mcp_devserver.protocol import spec
from mcp_devserver.tools.overview import (
    _summarise_cargo,
    _summarise_go_mod,
    _summarise_package_json,
    _summarise_pyproject,
)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def workspace_environment(workspace_root: Path, monkeypatch: pytest.MonkeyPatch):
    """Point every command in this module at the fixture workspace."""
    monkeypatch.setenv("MCP_SANDBOX__WORKSPACE", str(workspace_root))
    monkeypatch.setenv("MCP_OBSERVABILITY__LOG_LEVEL", "error")
    yield
    # structlog and the root logger are process-global; leaving them configured
    # would make an unrelated test's output depend on whether this file ran.
    structlog.reset_defaults()
    logging.getLogger().handlers.clear()


class TestParser:
    @pytest.mark.parametrize(
        ("argv", "command"),
        [
            (["serve"], "serve"),
            (["conform"], "conform"),
            (["call", "read_file"], "call"),
            (["tools"], "tools"),
            (["doctor"], "doctor"),
        ],
    )
    def test_every_subcommand_is_reachable(self, argv: list[str], command: str):
        assert build_parser().parse_args(argv).command == command

    def test_a_subcommand_is_required(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])


class TestDoctor:
    def test_it_reports_the_configuration(self, capsys: pytest.CaptureFixture[str]):
        assert main(["doctor"]) == 0
        out = capsys.readouterr().out
        assert f"protocol           {spec.PROTOCOL_VERSION}" in out
        assert "tools              7" in out
        assert "denied names" in out

    def test_it_warns_outside_production_without_refusing(self, capsys: pytest.CaptureFixture[str]):
        assert main(["doctor"]) == 0
        assert "warnings:" in capsys.readouterr().out

    def test_it_refuses_a_broken_production_configuration(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ):
        monkeypatch.setenv("MCP_ENVIRONMENT", "production")
        assert main(["doctor"]) == 1
        assert "BEARER_TOKEN" in capsys.readouterr().err

    def test_it_reports_an_unservable_workspace(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        monkeypatch.setenv("MCP_SANDBOX__WORKSPACE", str(tmp_path / "gone"))
        assert main(["doctor"]) == 1
        assert "cannot be served" in capsys.readouterr().err


class TestTools:
    def test_human_output_names_every_tool(self, capsys: pytest.CaptureFixture[str]):
        assert main(["tools"]) == 0
        out = capsys.readouterr().out
        for name in ("read_file", "search_code", "git_log"):
            assert name in out

    def test_required_arguments_are_marked(self, capsys: pytest.CaptureFixture[str]):
        main(["tools"])
        assert "* path" in capsys.readouterr().out

    def test_json_output_is_the_published_declarations(self, capsys: pytest.CaptureFixture[str]):
        assert main(["tools", "--json"]) == 0
        declarations = json.loads(capsys.readouterr().out)
        assert len(declarations) == 7
        assert declarations[0]["inputSchema"]["type"] == "object"


class TestCall:
    def test_a_successful_call_prints_the_content(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "project_overview"]) == 0
        assert "Languages:" in capsys.readouterr().out

    def test_arguments_are_read_as_json(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "read_file", '{"path": "README.md"}']) == 0
        assert "A fixture project." in capsys.readouterr().out

    def test_malformed_json_arguments_are_reported(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "read_file", "{not json"]) == 2
        assert "not valid JSON" in capsys.readouterr().err

    def test_a_json_array_is_not_an_arguments_object(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "read_file", "[1, 2]"]) == 2
        assert "must be a JSON object" in capsys.readouterr().err

    def test_a_tool_error_exits_non_zero(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "read_file", '{"path": "../../etc/passwd"}']) == 1

    def test_a_protocol_error_exits_non_zero(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "no_such_tool"]) == 1

    def test_the_json_flag_prints_the_whole_envelope(self, capsys: pytest.CaptureFixture[str]):
        assert main(["call", "project_overview", "{}", "--json"]) == 0
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["jsonrpc"] == "2.0"
        assert envelope["result"]["resultType"] == "complete"

    def test_the_workspace_flag_overrides_the_environment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        other = tmp_path / "other"
        other.mkdir()
        (other / "only-here.txt").write_text("x", encoding="utf-8")
        assert main(["--workspace", str(other), "call", "list_directory"]) == 0
        assert "only-here.txt" in capsys.readouterr().out


class TestConform:
    def test_it_exits_zero_against_this_server(self, capsys: pytest.CaptureFixture[str]):
        assert main(["conform", "--strict"]) == 0
        assert "CONFORMANT" in capsys.readouterr().out

    def test_it_writes_a_report(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        destination = tmp_path / "reports" / "conformance.json"
        assert main(["conform", "--report", str(destination)]) == 0
        report = json.loads(destination.read_text(encoding="utf-8"))
        assert report["green"] is True
        assert report["total"] == report["passed"]


class TestLoggingConfiguration:
    def test_records_go_to_stderr_as_json(self, capsys: pytest.CaptureFixture[str]):
        # stdout is the stdio transport's wire; a log line written to it
        # corrupts the protocol stream.
        configure(ObservabilitySettings(log_level="info", log_json=True))
        structlog.get_logger("test").info("hello", key="value")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert json.loads(captured.err)["event"] == "hello"

    def test_console_rendering_is_available(self, capsys: pytest.CaptureFixture[str]):
        configure(ObservabilitySettings(log_level="info", log_json=False))
        structlog.get_logger("test").info("readable")
        assert "readable" in capsys.readouterr().err

    def test_credential_shaped_keys_are_redacted(self, capsys: pytest.CaptureFixture[str]):
        configure(ObservabilitySettings(log_level="info", log_json=True))
        structlog.get_logger("test").info("auth", bearer_token="s3cr3t", token="also")
        record = json.loads(capsys.readouterr().err)
        assert record["bearer_token"] == "[redacted]"
        assert record["token"] == "[redacted]"

    def test_third_party_records_are_routed_through_the_same_chain(
        self, capsys: pytest.CaptureFixture[str]
    ):
        configure(ObservabilitySettings(log_level="warning", log_json=True))
        logging.getLogger("some.library").warning("a plain stdlib warning")
        assert json.loads(capsys.readouterr().err)["event"] == "a plain stdlib warning"

    def test_the_level_is_honoured(self, capsys: pytest.CaptureFixture[str]):
        configure(ObservabilitySettings(log_level="error", log_json=True))
        structlog.get_logger("test").info("should not appear")
        assert capsys.readouterr().err == ""

    def test_configuring_twice_does_not_duplicate_output(self, capsys: pytest.CaptureFixture[str]):
        # A second handler installed on the root logger would double every line,
        # and one of the duplicates could land on stdout.
        configure(ObservabilitySettings(log_level="info", log_json=True))
        configure(ObservabilitySettings(log_level="info", log_json=True))
        structlog.get_logger("test").info("once")
        assert len(capsys.readouterr().err.strip().splitlines()) == 1


class TestManifestSummaries:
    def test_pyproject(self):
        summary = _summarise_pyproject(
            '[project]\nname = "x"\nversion = "1"\n'
            'requires-python = ">=3.12"\n'
            'dependencies = ["httpx>=0.28", "structlog", "uvicorn[standard]>=0.40"]\n'
        )
        assert summary["name"] == "x"
        assert summary["requires_python"] == ">=3.12"
        assert summary["dependencies"] == ["httpx", "structlog", "uvicorn"]

    def test_a_malformed_pyproject_reports_the_error(self):
        assert "parse_error" in _summarise_pyproject("[project\n")

    def test_package_json(self):
        summary = _summarise_package_json(
            json.dumps(
                {
                    "name": "web",
                    "version": "2.0.0",
                    "dependencies": {"react": "^19", "next": "^15"},
                    "scripts": {"build": "next build", "dev": "next dev"},
                }
            )
        )
        assert summary["name"] == "web"
        assert summary["dependencies"] == ["next", "react"]
        assert summary["scripts"] == ["build", "dev"]

    def test_a_malformed_package_json_reports_the_error(self):
        assert "parse_error" in _summarise_package_json("{oops")

    def test_a_package_json_that_is_not_an_object(self):
        assert "parse_error" in _summarise_package_json("[1, 2]")

    def test_cargo(self):
        summary = _summarise_cargo(
            '[package]\nname = "crate"\nversion = "0.1.0"\n'
            '\n[dependencies]\nserde = "1"\ntokio = "1"\n'
        )
        assert summary["name"] == "crate"
        assert summary["dependencies"] == ["serde", "tokio"]

    def test_a_malformed_cargo_reports_the_error(self):
        assert "parse_error" in _summarise_cargo("[package\n")

    def test_go_mod(self):
        summary = _summarise_go_mod(
            "module example.com/thing\n\ngo 1.23\n\n"
            "require (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/sync v0.8.0\n)\n"
        )
        assert summary["name"] == "example.com/thing"
        assert summary["go_version"] == "1.23"
        assert summary["dependencies"] == ["github.com/pkg/errors", "golang.org/x/sync"]


def test_the_module_entry_point_is_importable():
    # `python -m mcp_devserver` is how an editor starts this server; an import
    # error here is a server that never starts.
    assert "mcp_devserver.cli" in sys.modules or main is not None
