"""Command line: serve, conform, inspect, and check the configuration.

Four commands, and they exist for four different audiences.

``serve`` is what an editor runs. ``conform`` is what CI runs, and what a person
evaluating any MCP server can run against it. ``call`` is what a developer runs
when they want to see what a tool actually returns without wiring up a client.
``doctor`` is what someone runs when the server will not start, and it answers
the question directly rather than making them read a stack trace.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp_devserver import __version__
from mcp_devserver.config import Settings, load
from mcp_devserver.conformance.client import Client, HttpClient, InProcessClient, StdioClient
from mcp_devserver.conformance.runner import run_suite, write_report
from mcp_devserver.errors import ConfigurationError, McpError
from mcp_devserver.observability.logging import configure
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import Server
from mcp_devserver.transport.stdio import serve_stdio


def _settings(arguments: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if getattr(arguments, "workspace", None):
        overrides["sandbox"] = {"workspace": Path(arguments.workspace)}
    return load(**overrides)


def _server(arguments: argparse.Namespace) -> Server:
    settings = _settings(arguments)
    configure(settings.observability)
    return Server(settings, version=__version__)


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def command_serve(arguments: argparse.Namespace) -> int:
    """Run the server over the requested transport."""
    server = _server(arguments)
    if arguments.transport == "stdio":
        asyncio.run(serve_stdio(server))
        return 0

    # Imported here rather than at module scope so that `serve --transport stdio`
    # — the common case, started by an editor on every session — does not pay
    # for importing uvicorn and starlette.
    import uvicorn

    from mcp_devserver.transport.http import build_application

    settings = server.settings
    if not settings.http.bearer_token:
        print(
            "warning: MCP_HTTP__BEARER_TOKEN is not set, so this endpoint accepts any caller.",
            file=sys.stderr,
        )
    uvicorn.run(
        build_application(server),
        host=settings.http.host,
        port=settings.http.port,
        log_config=None,
        access_log=False,
    )
    return 0


# ---------------------------------------------------------------------------
# conform
# ---------------------------------------------------------------------------


async def _conform(arguments: argparse.Namespace) -> int:
    settings = _settings(arguments)
    configure(settings.observability)

    if arguments.http:
        client: Client = HttpClient(arguments.http, token=arguments.token)
        report = await run_suite(client, strict=arguments.strict)
    elif arguments.stdio:
        async with StdioClient(arguments.stdio.split()) as stdio_client:
            report = await run_suite(stdio_client, strict=arguments.strict)
    else:
        report = await run_suite(
            InProcessClient(Server(settings, version=__version__)), strict=arguments.strict
        )

    print(report.render())
    if arguments.report:
        write_report(report, Path(arguments.report))
        print(f"\nreport written to {arguments.report}")
    return 0 if report.green else 1


def command_conform(arguments: argparse.Namespace) -> int:
    """Run the protocol conformance suite."""
    return asyncio.run(_conform(arguments))


# ---------------------------------------------------------------------------
# call
# ---------------------------------------------------------------------------


async def _call(arguments: argparse.Namespace) -> int:
    settings = _settings(arguments)
    configure(settings.observability)
    server = Server(settings, version=__version__)

    try:
        parsed: Any = json.loads(arguments.arguments)
    except json.JSONDecodeError as exc:
        print(f"arguments is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(parsed, dict):
        print("arguments must be a JSON object", file=sys.stderr)
        return 2

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": spec.TOOLS_CALL,
        "params": {
            "name": arguments.tool,
            "arguments": parsed,
            "_meta": {
                spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION,
                spec.META_CLIENT_CAPABILITIES: {},
                spec.META_CLIENT_INFO: {"name": "mcp-devserver-cli", "version": __version__},
            },
        },
    }

    response = await server.handle_payload(payload)
    if response is None:
        print("no response", file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(response, indent=2))
    else:
        result = response.get("result")
        if not isinstance(result, dict):
            print(json.dumps(response, indent=2), file=sys.stderr)
            return 1
        for block in result.get("content", []):
            if isinstance(block, dict) and block.get("type") == spec.CONTENT_TEXT:
                print(block.get("text", ""))
    error = response.get("error")
    if error is not None:
        return 1
    result = response.get("result")
    return 1 if isinstance(result, dict) and result.get("isError") else 0


def command_call(arguments: argparse.Namespace) -> int:
    """Invoke one tool and print what it returns."""
    return asyncio.run(_call(arguments))


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------


def command_tools(arguments: argparse.Namespace) -> int:
    """Print the published tool declarations."""
    server = _server(arguments)
    declarations = server.registry.declarations()
    if arguments.json:
        print(json.dumps(declarations, indent=2))
        return 0
    for tool in declarations:
        print(f"{tool['name']}")
        print(f"  {tool['title']}")
        properties = tool["inputSchema"].get("properties", {})
        required = set(tool["inputSchema"].get("required", []))
        for name, schema in sorted(properties.items()):
            marker = "*" if name in required else " "
            print(f"    {marker} {name}: {schema.get('type', 'any')}")
        print()
    return 0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def command_doctor(arguments: argparse.Namespace) -> int:
    """Report whether this configuration can serve, and what it would refuse."""
    try:
        settings = _settings(arguments)
    except ConfigurationError as exc:
        print(f"configuration refused:\n{exc}", file=sys.stderr)
        return 1

    try:
        server = Server(settings, version=__version__)
    except ConfigurationError as exc:
        print(f"the workspace cannot be served: {exc}", file=sys.stderr)
        return 1

    workspace = server.workspace
    print(f"environment        {settings.environment}")
    print(f"protocol           {spec.PROTOCOL_VERSION}")
    print(f"workspace          {workspace.root}")
    print(f"tools              {len(server.registry)} ({', '.join(server.registry.names())})")
    print(f"max file bytes     {workspace.max_file_bytes}")
    print(f"follow symlinks    {settings.sandbox.follow_symlinks}")
    print(f"redact secrets     {settings.security.redact_secrets}")
    print(f"scan content       {settings.security.scan_untrusted_content}")
    print(f"denied names       {len(workspace.denylist.names)}")
    print(f"denied patterns    {len(workspace.denylist.patterns)}")
    print(f"http auth          {'set' if settings.http.bearer_token else 'NOT SET'}")

    problems = settings.production_violations()
    if problems:
        label = "refusals" if settings.environment == "production" else "warnings"
        print(f"\n{label}:")
        for problem in problems:
            print(f"  - {problem}")
    if settings.environment == "production" and problems:
        return 1
    print("\nready" if not problems else "\nready, with warnings")
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-devserver",
        description=(
            "A sandboxed Model Context Protocol server for source code "
            f"(protocol revision {spec.PROTOCOL_VERSION})."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--workspace",
        help="Directory to serve. Overrides MCP_SANDBOX__WORKSPACE.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the server.")
    serve.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio for an editor; http for a networked deployment.",
    )
    serve.set_defaults(handler=command_serve)

    conform = subparsers.add_parser(
        "conform", help="Run the protocol conformance suite and exit non-zero on failure."
    )
    conform.add_argument("--http", help="Conform a running server at this URL.")
    conform.add_argument("--stdio", help="Conform a server started by this command.")
    conform.add_argument("--token", default="", help="Bearer token for --http.")
    conform.add_argument("--report", help="Write a JSON report to this path.")
    conform.add_argument(
        "--strict",
        action="store_true",
        help="Fail on SHOULD violations as well as MUST violations.",
    )
    conform.set_defaults(handler=command_conform)

    call = subparsers.add_parser("call", help="Invoke one tool and print the result.")
    call.add_argument("tool", help="Tool name.")
    call.add_argument(
        "arguments", nargs="?", default="{}", help="Arguments as a JSON object. Defaults to {}."
    )
    call.add_argument("--json", action="store_true", help="Print the whole JSON-RPC response.")
    call.set_defaults(handler=command_call)

    tools = subparsers.add_parser("tools", help="List the published tools.")
    tools.add_argument("--json", action="store_true", help="Print the raw declarations.")
    tools.set_defaults(handler=command_tools)

    doctor = subparsers.add_parser(
        "doctor", help="Check the configuration and report what would be refused."
    )
    doctor.set_defaults(handler=command_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        result: int = arguments.handler(arguments)
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except McpError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return result


if __name__ == "__main__":
    raise SystemExit(main())
