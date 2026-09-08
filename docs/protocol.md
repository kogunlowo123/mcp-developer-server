# The protocol

This server implements Model Context Protocol revision **2026-07-28**. That
revision is a redesign rather than an increment, and this page is the mapping
from what it requires to where that requirement lives in the code.

## What changed, and why it matters here

| | Up to 2025-11-25 | 2026-07-28 |
|---|---|---|
| Negotiation | An `initialize` handshake, once per connection | `_meta` on **every request** |
| State | Per-connection session | None; servers must not rely on prior requests |
| Discovery | Implied by the handshake result | `server/discover`, mandatory |
| Result shape | Method-specific | Every result carries `resultType` |
| Errors | `-32002`, `-32042` in use | Those withdrawn; `-32020`–`-32099` reserved |

The statelessness requirement is the one that shapes the code. `Server` holds
configuration and a tool registry — things fixed at start-up — and nothing
derived from a request. Every per-request value lives in a `RequestContext`
built inside the handler and discarded when it returns. There is no session
table to consult, and therefore none to forget to clear.

## Every request

```jsonc
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": { "path": "src/main.py" },
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",   // required
      "io.modelcontextprotocol/clientCapabilities": {},          // required, may be empty
      "io.modelcontextprotocol/clientInfo": {                    // optional, advisory
        "name": "my-editor", "version": "2.1"
      }
    }
  }
}
```

`clientCapabilities` is **required** and must be an object. A client with no
capabilities sends `{}`, not nothing. Omitting either required field is
`-32602`, and over HTTP that is a `400`.

`clientInfo` is optional and grants nothing. It is parsed leniently — a
non-string member is ignored rather than failing the request — because failing a
request over a field that authorises nothing would be failing it for no benefit.

### `_meta` key rules

Keys are `[prefix/]name`. A prefix whose **second** label is `modelcontextprotocol`
or `mcp` is reserved to the specification: `io.modelcontextprotocol/x` and
`x.mcp/y` are both reserved, `com.example/z` is not. A client inventing a key
under a reserved prefix is refused.

W3C trace context is the explicit exception. `traceparent`, `tracestate` and
`baggage` are bare keys, accepted, and echoed back in the result's `_meta` so a
client correlating a response to a span does not have to hold the request open.

## Methods

### `server/discover`

Mandatory. Replaces the handshake's role.

```jsonc
{
  "resultType": "complete",
  "supportedVersions": ["2026-07-28"],
  "capabilities": { "tools": { "listChanged": false, "count": 7 } },
  "instructions": "Read-only tools over a single contained workspace...",
  "ttlMs": 3600000,
  "cacheScope": "server",
  "_meta": {
    "io.modelcontextprotocol/serverInfo": {
      "name": "mcp-devserver", "version": "0.1.0", "title": "MCP Developer Server"
    }
  }
}
```

`cacheScope: "server"` means the answer is identical for every client — true
here, because there is no per-caller state for it to vary by. `ttlMs` is an hour
because the tool set is fixed at start-up.

The `instructions` field is where the meaning of the `<untrusted-...>` fences is
explained. A server that fenced content but never told anyone what the fence
meant would be marking for nobody.

### `tools/list`

Paginated at five per page, ordered by name. Determinism is a SHOULD with a
stated reason: it lets clients cache the listing, and it keeps a prompt
containing the tool set stable across calls, which is the difference between a
warm prompt cache and a cold one.

Cursors are opaque — base64 of an offset — because a cursor a client can
construct is a cursor a client will construct, and then the paging strategy is
part of the contract. A cursor this server did not issue is `-32602`, not an
ignored parameter.

### `tools/call`

Arguments are validated against the tool's published `inputSchema` before the
handler runs. `additionalProperties: false` on every schema means a typo in an
argument name is refused rather than silently defaulted.

## The two error mechanisms

This is the distinction most often got wrong, and this server's position on it
is [ADR-004](../ARCHITECTURE.md).

**A protocol error** — a JSON-RPC `error` object — means the request itself was
wrong, in a way no argument change would fix:

| Code | Meaning | When |
|---|---|---|
| `-32700` | Parse error | The body was not JSON |
| `-32600` | Invalid request | JSON, but not a JSON-RPC request |
| `-32601` | Method not found | An unknown method |
| `-32602` | Invalid params | Missing `_meta` fields, bad arguments, unknown tool, an unissued cursor |
| `-32603` | Internal error | An unexpected failure, with no detail — a traceback names paths the sandbox exists to withhold |
| `-32020` | Header mismatch | An HTTP protocol-version header disagreeing with `_meta` |
| `-32021` | Missing client capability | Reserved; no tool here requires one, so this server never emits it |
| `-32022` | Unsupported version | With `data.supported` and `data.requested` |

`-32002` and `-32042` were withdrawn by this revision. A test asserts neither
ever leaves the process, and another asserts no code inside `-32099`..`-32020`
is emitted beyond the three defined above.

**A tool error** — a result with `isError: true` — means the call was well
formed and the answer is "no":

```jsonc
{
  "resultType": "complete",
  "isError": true,
  "content": [{ "type": "text", "text": "'..' resolves outside the workspace and cannot be read. Paths must stay inside myproject/." }],
  "structuredContent": {
    "error": "outside_workspace",
    "message": "'..' resolves outside the workspace and cannot be read.",
    "remedy": "Paths must stay inside myproject/."
  }
}
```

The model reads `content` and adapts; a program branches on `error`. A denial
delivered as a transport failure would be invisible to the model that needs to
learn from it.

## Notifications

A request without an `id` is a notification and **must not** be answered — not
even with an error. Over HTTP that is `202` with an empty body; over stdio,
nothing is written. A server that answers a notification desynchronises a client
that is not reading for a response.

## Legacy clients

A client sending `initialize` gets:

```jsonc
{
  "jsonrpc": "2.0", "id": 1,
  "error": {
    "code": -32022,
    "message": "unsupported protocol version '2025-11-25'",
    "data": { "supported": ["2026-07-28"], "requested": "2025-11-25" }
  }
}
```

One round trip, and the client knows exactly what to speak. [ADR-002](../ARCHITECTURE.md)
explains why there is no second protocol era here.

## Transports

**stdio** — newline-delimited JSON, one request per line. What an editor spawns.
Reads happen on a worker thread rather than through `loop.connect_read_pipe`,
which does not work on Windows; an MCP server has to run on the platform the
developer is using. Requests may overlap and are handled concurrently, bounded
at eight; because the server is stateless, that cannot change any answer.

**Streamable HTTP** — `POST /mcp`, plus `/healthz` and `/readyz`. Adds a bearer
token, an `Origin` check (DNS-rebinding defence, checked *before* authentication
so the endpoint is not an oracle for token validity), a body limit enforced on
the stream rather than only on the header, and the protocol-version header
cross-check. JSON-RPC batching is refused: it is not part of this revision, and
accepting it would let one HTTP request start an unbounded number of tool runs.

Both are thin wrappers around the same dispatcher, which is what lets the
conformance suite run identically over either.

## Verifying all of this

Do not take this page's word for it:

```bash
uv run mcp-devserver conform --strict
uv run mcp-devserver conform --stdio "uv run mcp-devserver serve --transport stdio" --strict
uv run mcp-devserver conform --http http://localhost:8080/mcp --strict
```

See [conformance.md](conformance.md).
