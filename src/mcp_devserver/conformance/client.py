"""Three ways to reach a server, behind one interface.

The conformance suite is only worth having if it can be pointed at a *running*
server — a container, a process an editor spawned, a colleague's deployment —
and not only at objects inside this test process. So the checks are written
against a small protocol with one method, and there are three implementations of
it: in-process, stdio subprocess, and HTTP.

The HTTP client uses the standard library rather than ``httpx``. It runs inside
the shipped package, which a user installs to check a server they are running,
and adding an HTTP dependency to a server that makes no outbound requests would
be a dependency added purely to test the server with.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from types import TracebackType
from typing import Any, Final, Protocol

from mcp_devserver.protocol import jsonrpc
from mcp_devserver.protocol.server import Server

#: How long to wait for one response before declaring the server unresponsive.
TIMEOUT_SECONDS: Final[float] = 30.0

#: The status the HTTP transport returns for a notification: accepted, nothing
#: to read.
_ACCEPTED: Final[int] = 202


class Client(Protocol):
    """Sends one request and returns the decoded response, or ``None``."""

    async def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Send a request payload and return the response payload."""
        ...

    @property
    def label(self) -> str:
        """A short description of what this client is talking to."""
        ...


class InProcessClient:
    """Calls a :class:`Server` directly.

    Used by the unit and integration suites, and by ``conform`` when no target
    is given. It exercises the dispatcher without a transport, which is how a
    transport bug and a dispatch bug stay distinguishable.
    """

    def __init__(self, server: Server) -> None:
        self._server = server

    @property
    def label(self) -> str:
        """Where this client points."""
        return f"in-process ({self._server.workspace.root})"

    async def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch one payload."""
        return await self._server.handle_payload(payload)


class StdioClient:
    """Drives a server subprocess over its stdin and stdout.

    This is the transport an editor uses, so it is the one a conformance run
    should exercise by default. It also proves something the in-process client
    cannot: that the server writes nothing but responses to stdout.
    """

    def __init__(self, command: list[str]) -> None:
        self._command = command
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    @property
    def label(self) -> str:
        """Where this client points."""
        return f"stdio ({' '.join(self._command)})"

    async def __aenter__(self) -> StdioClient:
        """Start the server subprocess."""
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close stdin and wait for the subprocess, killing it if it will not stop."""
        process = self._process
        self._process = None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:
            process.kill()
            await process.wait()

    async def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Write one line and read one line."""
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise RuntimeError("the stdio client is not running; use it as a context manager")

        line = jsonrpc.encode(payload) + "\n"
        # One request at a time. The transport handles concurrency; this client
        # deliberately does not, so that a check reading a response knows which
        # request produced it.
        async with self._lock:
            process.stdin.write(line.encode("utf-8"))
            await process.stdin.drain()
            if payload.get("id") is None:
                return None
            raw = await asyncio.wait_for(process.stdout.readline(), timeout=TIMEOUT_SECONDS)

        if not raw:
            stderr = b""
            if process.stderr is not None:
                stderr = await process.stderr.read(4096)
            raise RuntimeError(
                "the server closed stdout without responding; "
                f"stderr: {stderr.decode('utf-8', errors='replace')[:500]}"
            )
        decoded: Any = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            # RuntimeError, not TypeError: this is a peer sending something the
            # protocol forbids, not a caller passing the wrong Python type.
            raise RuntimeError(f"the server wrote a non-object response: {decoded!r}")  # noqa: TRY004
        return decoded


class HttpClient:
    """Posts to a running server's HTTP endpoint."""

    def __init__(self, url: str, *, token: str = "", version_header: str | None = None) -> None:
        self._url = url
        self._token = token
        self._version_header = version_header

    @property
    def label(self) -> str:
        """Where this client points."""
        return f"http ({self._url})"

    def _post(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        body = jsonrpc.encode(payload).encode("utf-8")
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        if self._version_header:
            headers["mcp-protocol-version"] = self._version_header
        request = urllib.request.Request(  # noqa: S310 - the URL is operator-supplied
            self._url, data=body, headers=headers, method="POST"
        )
        try:
            # The URL comes from an operator typing `conform --http <url>`, not
            # from any MCP request: nothing a client can send reaches this code.
            # A scheme other than http or https would fail at the request above,
            # which was constructed with an explicit POST method.
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                request, timeout=TIMEOUT_SECONDS
            ) as response:
                if response.status == _ACCEPTED:
                    return None
                raw = response.read()
        except urllib.error.HTTPError as error:
            # A 4xx carrying a JSON-RPC error body is a protocol answer, not a
            # transport failure, and the checks need to see it.
            raw = error.read()
            if not raw:
                raise
        decoded: Any = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            # See the note in StdioClient.send.
            raise RuntimeError(f"the server returned a non-object response: {decoded!r}")  # noqa: TRY004
        return decoded

    async def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Post one payload, off the event loop."""
        return await asyncio.to_thread(self._post, payload)
