"""What a client sees, end to end, with no server process and no editor.

Runs against a throwaway workspace this script writes, so it works on a clean
clone with nothing configured. Everything here goes through the same dispatcher
an editor reaches over stdio — the transport is the only thing missing.

    python examples/quickstart.py
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from mcp_devserver.config import ObservabilitySettings, Settings
from mcp_devserver.observability.logging import configure
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import Server

META: dict[str, Any] = {
    # Revision 2026-07-28 has no handshake: every request carries its own
    # version and capabilities, and a request missing either is refused.
    spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION,
    spec.META_CLIENT_CAPABILITIES: {},
    spec.META_CLIENT_INFO: {"name": "quickstart-example", "version": "1.0"},
}


def build_workspace(root: Path) -> None:
    """Write a small project for the server to serve."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "widgets"\nversion = "0.3.0"\ndependencies = ["httpx"]\n',
        encoding="utf-8",
    )
    (root / "src" / "engine.py").write_text(
        '"""The engine."""\n'
        "\n"
        "RETRIES = 3\n"
        "\n"
        "\n"
        "class Engine:\n"
        '    """Does the work."""\n'
        "\n"
        "    def start(self, name):\n"
        "        return name\n",
        encoding="utf-8",
    )


async def request(server: Server, method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Send one JSON-RPC request and return its result."""
    response = await server.handle_payload(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": META}}
    )
    if response is None:
        raise RuntimeError(f"{method} returned no response")
    if "error" in response:
        raise RuntimeError(f"{method} failed: {response['error']}")
    result: dict[str, Any] = response["result"]
    return result


async def call(server: Server, tool: str, **arguments: Any) -> dict[str, Any]:
    """Invoke one tool."""
    return await request(server, spec.TOOLS_CALL, {"name": tool, "arguments": arguments})


#: Long enough to show a real result, short enough that the walkthrough stays
#: readable in a terminal.
EXCERPT_LIMIT = 700


def show(title: str, result: dict[str, Any]) -> None:
    """Print the readable half of a result."""
    print(f"\n--- {title}")
    for block in result.get("content", []):
        text = block.get("text", "")
        if len(text) < EXCERPT_LIMIT:
            print(text)
        else:
            print(text[:EXCERPT_LIMIT] + "\n  ... truncated for the example")


async def main() -> int:
    """Run the walkthrough."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "widgets"
        root.mkdir()
        build_workspace(root)

        server = Server(Settings(sandbox={"workspace": root}))

        print("=== 1. Discovery: what is this server?")
        discover = await request(server, spec.DISCOVER, {})
        print(f"  protocol      {', '.join(discover['supportedVersions'])}")
        print(f"  tools         {discover['capabilities']['tools']['count']}")
        print(f"  cacheable for {discover['ttlMs'] // 1000}s ({discover['cacheScope']} scope)")
        print(f"  serverInfo    {discover['_meta'][spec.META_SERVER_INFO]['name']}")

        print("\n=== 2. The tool set, paginated")
        cursor: str | None = None
        page = 0
        while True:
            params = {"cursor": cursor} if cursor else {}
            listing = await request(server, spec.TOOLS_LIST, params)
            page += 1
            names = ", ".join(tool["name"] for tool in listing["tools"])
            print(f"  page {page}: {names}")
            cursor = listing.get("nextCursor")
            if cursor is None:
                break

        print("\n=== 3. Orient in an unfamiliar repository with one call")
        show("project_overview", await call(server, "project_overview"))

        print("\n=== 4. Find a definition")
        symbols = await call(server, "find_symbol", symbol="Engine")
        for definition in symbols["structuredContent"]["definitions"]:
            print(
                f"  {definition['path']}:{definition['line']}"
                f"  [{definition['kind']}, {definition['method']}]"
                f"  {definition['signature']}"
            )

        print("\n=== 5. Read it")
        show("read_file", await call(server, "read_file", path="src/engine.py", end_line=8))

        print("\n=== 6. A path outside the workspace")
        denial = await call(server, "read_file", path="../../etc/passwd")
        print(f"  isError  {denial['isError']}")
        print(f"  error    {denial['structuredContent']['error']}")
        print(f"  remedy   {denial['structuredContent']['remedy']}")
        print("  This is a *result*, not a transport error: a model that never")
        print("  sees the refusal cannot learn from it.")

        print("\n=== 7. What a client can branch on")
        overview = await call(server, "project_overview")
        print(json.dumps(overview["structuredContent"]["manifests"], indent=2))

    return 0


# Quiet the request log so the walkthrough reads cleanly. Calling configure
# at all is the point: it sends every record to stderr, which is what keeps
# stdout free for the protocol when this server runs over stdio.
configure(ObservabilitySettings(log_level="error"))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
