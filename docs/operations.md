# Operations

## The two deployment shapes

**stdio, launched by an editor.** The normal case. Your client spawns the
process, speaks newline-delimited JSON over the pipes, and kills it when the
session ends. There is nothing to deploy: install the package and point a client
at it.

**HTTP, in a container.** For a shared or remote deployment. Adds
authentication, an origin check and health probes, and needs a reverse proxy for
TLS.

## Running it over stdio

```json
{
  "mcpServers": {
    "devserver": {
      "command": "uvx",
      "args": ["--from", "mcp-devserver", "mcp-devserver", "serve", "--transport", "stdio"],
      "env": {
        "MCP_SANDBOX__WORKSPACE": "/absolute/path/to/your/repository",
        "MCP_OBSERVABILITY__LOG_LEVEL": "warning"
      }
    }
  }
}
```

Before wiring it up, check what it would serve:

```bash
MCP_SANDBOX__WORKSPACE=/absolute/path mcp-devserver doctor
```

Then check it speaks the protocol:

```bash
MCP_SANDBOX__WORKSPACE=/absolute/path \
  mcp-devserver conform --stdio "mcp-devserver serve --transport stdio" --strict
```

## Running it over HTTP

```bash
export MCP_WORKSPACE=/absolute/path/to/your/repository
export MCP_HTTP__BEARER_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d

curl -s localhost:8080/readyz | python -m json.tool
```

Or directly:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD:/workspace:ro" \
  -e MCP_HTTP__BEARER_TOKEN="$TOKEN" \
  ghcr.io/kogunlowo123/mcp-developer-server:latest
```

The image serves HTTP by default, binds `0.0.0.0` internally — a loopback bind
inside a container is unreachable from a published port — and reads
`/workspace`. What limits exposure is the port mapping, not the bind address.

Other subcommands still work, because the entry point is the binary and the
command is the argument:

```bash
docker run --rm -v "$PWD:/workspace:ro" mcp-devserver:local doctor
docker run --rm -v "$PWD:/workspace:ro" mcp-devserver:local tools
```

## Probes

| Endpoint | Meaning | Unauthenticated |
|---|---|---|
| `GET /healthz` | The process is up and can serialise a response | Yes |
| `GET /readyz` | The workspace still resolves; returns `503` if not | Yes |

Both answer without a token deliberately: a liveness probe that needs a
credential reports the wrong thing when the credential is wrong.

```json
{
  "status": "ready",
  "workspace_present": true,
  "tools": 7,
  "protocol_versions": ["2026-07-28"]
}
```

## Logs

JSON on stderr. **Never stdout** — on stdio, stdout is the protocol wire, and a
log line written there corrupts the stream for a reason the client cannot
diagnose. Third-party records are routed through the same chain, so a library
warning arrives as JSON on stderr rather than as prose on stdout.

Events worth alerting on:

| Event | Meaning |
|---|---|
| `rpc.error` with `code: -32022` | A client is speaking a revision this server does not serve |
| `rpc.error` with `code: -32602` | Malformed requests; a burst suggests a broken client |
| `rpc.unhandled` | An unexpected failure. The traceback is here and never in the response |
| `tool.hard_timeout` | A handler blocked past its own deadline check |
| `http.origin_rejected` | A browser origin was refused — worth reading, this is the rebinding defence firing |

`MCP_OBSERVABILITY__LOG_TOOL_ARGUMENTS` is off by default. Paths are not secrets
but they are the developer's private directory structure, and a log attached to
a bug report should not carry it.

## What to watch

**Denial rate.** A steady trickle of `outside_workspace` is a client with a bad
path model. A sudden burst is worth looking at.

**Redaction counts.** `structuredContent.redaction.count` non-zero means a
credential is sitting in the workspace. The redaction did its job; the file
still needs fixing.

**High-risk content assessments.** `content_assessment.level == "high"` means a
file in the repository contains text written to steer a model. That is a finding
about the repository, not about this server.

**Timeouts.** Frequent `timed_out` results mean the workspace is larger than the
budget. Raise `MCP_SANDBOX__TOOL_TIMEOUT_SECONDS`, or narrow the workspace.

## Upgrading a protocol revision

`src/mcp_devserver/protocol/spec.py` is a transcription of the specification and
nothing else, so a revision is a diff against one file plus whatever the
conformance suite then reports. The order to work in:

1. Update `PROTOCOL_VERSION` and `SUPPORTED_VERSIONS`.
2. Run `mcp-devserver conform --strict`. Failures name the requirements that
   moved.
3. Add or amend checks in `conformance/checks.py` for anything new, and a
   negative control for each in `tests/conformance/`.
4. Only then change handlers.

## Backup and state

There is none. The server holds no state between requests — that is a
requirement of the protocol revision and a property of the code. Restarting it
loses nothing.

## Common problems

**"the container never became ready"** — the workspace mount is empty or absent.
Check `docker logs`; `readyz` will report `workspace_present: false`.

**Every result is empty and `total_files` is 0** — the bind mount silently
produced an empty directory. On Docker Desktop this happens when the source path
is not one of the shared paths; use a path inside your home directory or the
project tree.

**The client reports a JSON parse error** — something is writing to stdout.
Check for a `print` in a handler, or a library configuring its own logging.
`tests/e2e` asserts the exact line count on stdout for exactly this reason.

**`-32602` on every request** — the client is not sending `_meta`. This revision
has no handshake; every request carries its own version and capabilities.

**A legitimate regular expression is refused** — the ReDoS guard is a heuristic.
Rewrite without a repetition inside a repeated group, or set `regex: false`.
