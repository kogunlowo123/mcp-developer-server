"""Newline-delimited JSON-RPC over stdin and stdout.

This is how an editor talks to a local MCP server: it spawns the process and
speaks over the pipes. Four things about that shape drive the code here.

**stdout is the wire.** Nothing but responses may be written to it. The logging
module sends everything to stderr, and this module holds the only reference to
stdout in the package.

**Reading happens on a thread, not through the event loop.**
``loop.connect_read_pipe`` is the obvious way to read stdin asynchronously and
it does not work on Windows, where the proactor loop cannot attach to a standard
handle. An MCP server whose whole purpose is to be launched by an editor has to
run on the platform the developer is using, so reads go through
``asyncio.to_thread`` around a blocking ``readline``. One extra thread, and the
same code path on every platform.

**A line is attacker-controllable in length.** ``readline`` on a pipe with no
bound will happily allocate whatever arrives. Lines are read against a cap; one
that exceeds it is answered with a parse error and the rest of it is discarded
up to the next newline, so the stream resynchronises instead of the oversized
tail being parsed as a fresh request.

**Requests may overlap.** A client is entitled to send a second request before
the first is answered. Handling them one at a time would make a slow directory
walk block an unrelated ``tools/list``, so each line is dispatched as its own
task and responses are written by a single writer. Because the server is
stateless, concurrent handling cannot change any answer — which is exactly the
property ``tests/conformance`` pins by interleaving requests on one process.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from typing import BinaryIO, Final

import structlog

from mcp_devserver.errors import ParseError
from mcp_devserver.protocol import jsonrpc
from mcp_devserver.protocol.server import Server

_log = structlog.get_logger(__name__)

#: The most requests handled at once. Bounded so that a client that floods the
#: pipe cannot start an unbounded number of directory walks.
MAX_CONCURRENCY: Final[int] = 8


@dataclass(frozen=True, slots=True)
class Line:
    """One line read from the input stream."""

    data: bytes
    #: True when the line hit the size cap before a newline arrived. ``data`` is
    #: then the discarded prefix's length rather than its content.
    oversized: bool = False

    @property
    def at_end(self) -> bool:
        """Whether the stream is finished."""
        return not self.data and not self.oversized


def read_line(stream: BinaryIO, limit: int) -> Line:
    """Read one newline-terminated line, bounded.

    Blocking, and called on a worker thread. When the cap is reached before a
    newline, the remainder of the line is drained so that the next read starts
    at a request boundary rather than in the middle of one.
    """
    chunk = stream.readline(limit)
    if not chunk:
        return Line(data=b"")
    if chunk.endswith(b"\n") or len(chunk) < limit:
        return Line(data=chunk)

    # Over the cap. Drain to the next newline and report the overflow.
    while True:
        tail = stream.readline(limit)
        if not tail or tail.endswith(b"\n"):
            break
    return Line(data=b"", oversized=True)


class StdioTransport:
    """Serves one :class:`Server` over stdin and stdout."""

    def __init__(
        self,
        server: Server,
        *,
        max_bytes: int = jsonrpc.MAX_REQUEST_BYTES,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> None:
        self._server = server
        self._max_bytes = max_bytes
        self._write_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        self._input = stdin if stdin is not None else sys.stdin.buffer
        self._output = stdout if stdout is not None else sys.stdout.buffer

    async def _emit(self, payload: dict[str, object]) -> None:
        line = jsonrpc.encode(payload).encode("utf-8") + b"\n"
        async with self._write_lock:
            # Written under a lock and flushed immediately. Two coroutines
            # interleaving partial writes would produce a line that is neither
            # response, and a buffered response is a response the client waits
            # for forever.
            self._output.write(line)
            self._output.flush()

    async def _handle_line(self, line: str) -> None:
        async with self._semaphore:
            response = await self._server.handle_text(line)
        if response is not None:
            await self._emit(response)

    async def serve(self) -> None:
        """Read requests until stdin closes."""
        tasks: set[asyncio.Task[None]] = set()
        try:
            while True:
                line = await asyncio.to_thread(read_line, self._input, self._max_bytes)
                if line.oversized:
                    await self._emit(
                        jsonrpc.failure(
                            None,
                            ParseError(f"request exceeded the {self._max_bytes}-byte line limit"),
                        )
                    )
                    continue
                if line.at_end:
                    break
                text = line.data.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                task = asyncio.create_task(self._handle_line(text))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        finally:
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            _log.info("stdio.closed")


async def serve_stdio(server: Server) -> None:
    """Run a server over stdio until stdin closes."""
    _log.info(
        "stdio.started",
        workspace=str(server.workspace.root),
        tools=len(server.registry),
    )
    await StdioTransport(server).serve()
