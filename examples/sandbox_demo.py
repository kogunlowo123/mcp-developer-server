"""Eight ways to try to leave the workspace, and what happens to each.

The point is not that they fail — it is *where* they fail, and what the caller
is told. Run it and read the reasons.

    python examples/sandbox_demo.py
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from mcp_devserver.config import ObservabilitySettings, Settings
from mcp_devserver.observability.logging import configure
from mcp_devserver.protocol import spec
from mcp_devserver.protocol.server import Server

META: dict[str, Any] = {
    spec.META_PROTOCOL_VERSION: spec.PROTOCOL_VERSION,
    spec.META_CLIENT_CAPABILITIES: {},
}

#: Each entry is a request a client could actually send, and the reason it is
#: interesting. Nothing here is exotic — these are the shapes that appear in
#: any path-traversal cheat sheet.
ATTEMPTS: tuple[tuple[str, dict[str, Any], str], ...] = (
    (
        "read_file",
        {"path": "../../etc/passwd"},
        "the obvious traversal",
    ),
    (
        "read_file",
        {"path": "docs/../../../root/.ssh/id_rsa"},
        "traversal hidden behind a legitimate-looking prefix",
    ),
    (
        "read_file",
        {"path": "/etc/hosts"},
        "an absolute path, resolved and contained like any other",
    ),
    (
        "read_file",
        {"path": "src/../README.md"},
        "traversal that lands back inside — allowed, because it is inside",
    ),
    (
        "read_file",
        {"path": ".env"},
        "a credential file that really is inside the workspace",
    ),
    (
        "read_file",
        {"path": "docs/../.env"},
        "the same file spelled differently: the denylist matches the resolved path",
    ),
    (
        "read_file",
        {"path": "deploy.pem"},
        "denied by pattern rather than by name",
    ),
    (
        "search_code",
        {"pattern": "PRIVATE KEY", "path": ".."},
        "searching the parent directory",
    ),
)


def build_workspace(root: Path) -> None:
    """Write a workspace with something worth protecting in it."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(exist_ok=True)
    (root / "README.md").write_text("# Widgets\n\nA demonstration project.\n", encoding="utf-8")
    (root / "src" / "engine.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / ".env").write_text("DATABASE_PASSWORD=hunter2\n", encoding="utf-8")
    (root / "deploy.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n", encoding="utf-8"
    )


async def attempt(server: Server, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Send one tools/call and return the result or the protocol error."""
    response = await server.handle_payload(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": spec.TOOLS_CALL,
            "params": {"name": tool, "arguments": arguments, "_meta": META},
        }
    )
    if response is None:
        return {"outcome": "no response"}
    if "error" in response:
        return {"outcome": "protocol error", "detail": response["error"]["message"]}
    result: dict[str, Any] = response["result"]
    return result


async def main() -> int:
    """Run every attempt and report what the caller was told."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "widgets"
        root.mkdir()
        build_workspace(root)

        # Something to find if the sandbox fails.
        outside = Path(directory) / "id_ed25519"
        outside.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")

        server = Server(Settings(sandbox={"workspace": root}))
        print(f"workspace: {root.name}/\n")

        escaped = 0
        for tool, arguments, note in ATTEMPTS:
            result = await attempt(server, tool, arguments)
            label = f"{tool}({', '.join(f'{k}={v!r}' for k, v in arguments.items())})"
            print(f"{label}")
            print(f"  why      {note}")

            if result.get("outcome") == "protocol error":
                print(f"  outcome  refused by the schema: {result['detail']}")
            elif result.get("isError"):
                structured = result["structuredContent"]
                print(f"  outcome  refused: {structured['error']}")
                print(f"  told     {structured['message']} {structured.get('remedy', '')}")
            else:
                summary = result["content"][0]["text"].splitlines()[0]
                print(f"  outcome  allowed: {summary}")
                if "README" not in summary and "match(es)" not in summary:
                    escaped += 1
            print()

        # The search in the last attempt is refused, so nothing outside the
        # workspace can appear. Assert it rather than assuming it.
        result = await attempt(server, "search_code", {"pattern": "OPENSSH", "path": "."})
        leaked = "OPENSSH" in str(result.get("structuredContent", {}).get("matches", []))

        print("---")
        print(f"attempts that reached outside the workspace: {escaped}")
        print(f"the key at {outside.name} appeared in a result: {leaked}")
        print()
        print("Every refusal names the workspace and the path as requested,")
        print("never the resolved absolute path — a denial that echoed back where")
        print("it looked would be an oracle for mapping the filesystem.")

    return 0 if escaped == 0 and not leaked else 1


# Quiet the request log so the walkthrough reads cleanly. Calling configure
# at all is the point: it sends every record to stderr, which is what keeps
# stdout free for the protocol when this server runs over stdio.
configure(ObservabilitySettings(log_level="error"))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
