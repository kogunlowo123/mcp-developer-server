# Conformance

The conformance suite is 23 executable checks derived from revision 2026-07-28.
It runs against a *running server* — this one, or any other — over stdio, over
HTTP, or in-process, and exits non-zero when a requirement is broken.

That last part is the point. It is a gate, not a report.

## Running it

```bash
# Against the library, in this process. Fastest; no transport involved.
uv run mcp-devserver conform --strict

# Against a real server process over a real pipe. What an editor does.
uv run mcp-devserver conform --strict \
  --stdio "uv run mcp-devserver serve --transport stdio"

# Against something already running.
uv run mcp-devserver conform --strict \
  --http http://localhost:8080/mcp --token "$MCP_HTTP__BEARER_TOKEN"

# Write a machine-readable report as well.
uv run mcp-devserver conform --report reports/conformance.json
```

```
target      stdio (uv run mcp-devserver serve --transport stdio)
checks      23/23 passed
duration    412ms

  ok    C001  [MUST]    server/discover is implemented
  ok    C002  [SHOULD]  results carry serverInfo in _meta
  ok    C003  [SHOULD]  discovery declares a cache lifetime
  ok    C004  [MUST]    every result carries resultType
  ...

CONFORMANT
```

## MUST and SHOULD

Each check names the level of the requirement it tests. A failed `MUST` is
non-conformance and fails the gate. A failed `SHOULD` is reported and, by
default, does not — a recommendation is not a requirement.

`--strict` promotes SHOULD failures to gate failures. **CI uses it**, because
this server has no reason to violate a recommendation, so a new violation is a
regression here even though it would not be non-conformance in general.

## The checks

| | Level | Requirement |
|---|---|---|
| C001 | MUST | `server/discover` is implemented and returns `supportedVersions` and `capabilities` |
| C002 | SHOULD | Results carry `io.modelcontextprotocol/serverInfo` in `_meta` |
| C003 | SHOULD | Discovery declares `ttlMs` so a client can cache it |
| C004 | MUST | Every result carries a valid `resultType` |
| C005 | MUST | `tools/list` returns Tool objects with legal names and object input schemas |
| C006 | SHOULD | `tools/list` order is stable across calls |
| C007 | MUST | `nextCursor` pagination pages forward, terminates, and repeats nothing |
| C008 | MUST | A cursor the server did not issue is rejected, not ignored |
| C009 | MUST | A request without `protocolVersion` is `-32602` |
| C010 | MUST | A request without `clientCapabilities` is `-32602` |
| C011 | MUST | An unsupported version is `-32022` with `data.supported` |
| C012 | MUST | A legacy `initialize` is answered, not silently accepted |
| C013 | MUST | An unknown method is `-32601` |
| C014 | MUST | Calling an unpublished tool is a protocol error, and not a withdrawn code |
| C015 | MUST | A malformed envelope is `-32600` |
| C016 | MUST | No error code invades the reserved range beyond the three defined |
| C017 | MUST | A request without an `id` receives no response at all |
| C018 | MUST | A tool failure is a result with `isError`, not a JSON-RPC error |
| C019 | MUST | A successful call returns both `content` and `structuredContent` |
| C020 | MUST | An argument the schema does not declare is refused |
| C021 | MUST | Interleaved requests on one connection do not influence each other |
| C022 | SHOULD | A reserved `_meta` prefix invented by a client is not honoured |
| C023 | MUST | `traceparent` in `_meta` is accepted, being exempt from the prefix rules |

**Portability caveat, stated plainly.** C018–C020 call tools by name
(`read_file`, `project_overview`), because the behaviours they check cannot be
tested without invoking something. Against a different server those three need
different tool names. Everything else is server-independent.

## The suite is itself tested

A conformance suite that has only ever run against a correct server proves
nothing about whether it would notice an incorrect one. So
`tests/conformance/test_conformance_suite.py` wraps the client in a mutator that
breaks exactly one requirement, and asserts the corresponding check goes red:

| Mutation | Check that must fail |
|---|---|
| Strip `resultType` from every result | C004 |
| Strip `_meta` from every result | C002 |
| Answer notifications | C017 |
| Relabel every error as `-32603` | C011 |
| Emit the withdrawn `-32002` | C016 |
| Convert tool errors into JSON-RPC errors | C018 |
| Reverse the tool order on alternate calls | C006 |
| Swallow the bad-cursor error and return an empty page | C008 |
| Accept `initialize` | C012 |
| Accept a request with no protocol version | C009 |

Plus: a SHOULD failure passes the default gate and fails `--strict`; a MUST
failure fails both; and a check that raises an unexpected exception is recorded
as a failure with the exception type in its detail, rather than crashing the
run — a `JSONDecodeError` there means the server wrote something that is not
JSON, which is exactly what one wants to see.

## Where it runs

| | in-process | stdio | HTTP |
|---|---|---|---|
| `pytest -m conformance` | ✓ | | |
| CI, `conformance` job | ✓ | ✓ | |
| CI, `Container` job | | | ✓ (inside the built image) |
| `python tasks.py conform` | ✓ | | |
| `python tasks.py conform-stdio` | | ✓ | |

Running it inside the container is what proves the *shipped artifact* speaks the
protocol, rather than that the source does. Those are different claims, and the
difference is where container defects live.

## The report

```json
{
  "target": "stdio (uv run mcp-devserver serve --transport stdio)",
  "started_at": "2026-09-08T00:14:02Z",
  "duration_ms": 412.7,
  "strict": true,
  "total": 23,
  "passed": 23,
  "must_failures": 0,
  "should_failures": 0,
  "green": true,
  "checks": [
    { "id": "C001", "level": "MUST", "title": "server/discover is implemented",
      "passed": true, "duration_ms": 1.9, "detail": "" }
  ]
}
```

CI uploads it as an artifact so a change in behaviour is visible in the diff
between two runs, not only in a pass or a fail.

## Conforming your own server

The suite imports nothing from this server's implementation, so:

```bash
uvx --from mcp-devserver mcp-devserver conform \
  --stdio "your-server --stdio" --strict
```

C018–C020 will fail unless your server publishes tools with those names; every
other check applies to any 2026-07-28 server.
