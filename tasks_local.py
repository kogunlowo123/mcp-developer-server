"""Tasks specific to this repository. Merged into tasks.py's table."""

from __future__ import annotations

import os

UV = "uv"
IMAGE = os.environ.get("IMAGE_NAME", "mcp-developer-server")


def _run(*args: str) -> list[str]:
    return [UV, "run", *args]


TASKS: dict[str, tuple[str, list[list[str]]]] = {
    "test": (
        "Run the whole test suite with the coverage gate.",
        [_run("pytest", "--cov", "--cov-report=term-missing", "--cov-fail-under=88")],
    ),
    "test-e2e": ("Run the end-to-end suite only.", [_run("pytest", "-m", "e2e")]),
    "test-conformance": (
        "Run the conformance test suite, including its negative controls.",
        [_run("pytest", "-m", "conformance")],
    ),
    "serve": (
        "Run the server over stdio, the way an editor would.",
        [_run("mcp-devserver", "serve", "--transport", "stdio")],
    ),
    "serve-http": (
        "Run the server over HTTP on 127.0.0.1:8080.",
        [_run("mcp-devserver", "serve", "--transport", "http")],
    ),
    "doctor": (
        "Report what this configuration would serve, and what it would refuse.",
        [_run("mcp-devserver", "doctor")],
    ),
    "tools": (
        "Print the published tool declarations.",
        [_run("mcp-devserver", "tools")],
    ),
    "conform": (
        "Run the protocol conformance gate in-process.",
        [_run("mcp-devserver", "conform", "--strict", "--report", "reports/conformance.json")],
    ),
    "conform-stdio": (
        "Run the conformance gate against a real server process.",
        [
            _run(
                "mcp-devserver",
                "conform",
                "--strict",
                "--stdio",
                "uv run mcp-devserver serve --transport stdio",
            )
        ],
    ),
    "site": (
        "Build the documentation site into _site/.",
        [_run("python", "scripts/build_site.py", "--output", "_site")],
    ),
    "examples": (
        "Run every example.",
        [
            _run("python", "examples/quickstart.py"),
            _run("python", "examples/sandbox_demo.py"),
            _run("python", "examples/untrusted_demo.py"),
        ],
    ),
    "smoke": (
        "Build the image and exercise it over HTTP.",
        [
            ["docker", "build", "-t", f"{IMAGE}:local", "."],
            ["bash", "scripts/smoke-test.sh", f"{IMAGE}:local"],
        ],
    ),
    "up": ("Start the HTTP deployment.", [["docker", "compose", "up", "--build", "-d"]]),
    "down": ("Stop the HTTP deployment.", [["docker", "compose", "down", "-v"]]),
}
