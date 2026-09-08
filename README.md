# MCP Developer Server

[![CI](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/ci.yml/badge.svg)](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/ci.yml)
[![Security](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/security.yml/badge.svg)](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/security.yml)
[![Container](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/docker.yml/badge.svg)](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/docker.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28-8a63d2.svg)](https://modelcontextprotocol.io/specification/2026-07-28)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Documentation](https://github.com/kogunlowo123/mcp-developer-server/actions/workflows/pages.yml/badge.svg)](https://kogunlowo123.github.io/mcp-developer-server/)

A Model Context Protocol server that gives a language model read-only tools over
one contained directory — and treats everything it returns as what it is:
untrusted bytes from someone else's files, running with your privileges.

**Documentation:** <https://kogunlowo123.github.io/mcp-developer-server/>

---

## What is this?

An MCP server, implementing revision **2026-07-28** of the specification, that
publishes seven tools for reading and searching source code: `read_file`,
`list_directory`, `search_code`, `find_symbol`, `project_overview`, `git_log`
and `git_diff`. Point it at a repository and an editor's assistant can navigate
that repository without you pasting files into a chat window.

It ships with a **protocol conformance suite** — 23 executable checks derived
from the specification — that can be run against this server or any other, over
stdio or over HTTP, and exits non-zero when a requirement is broken.

## Why does it exist?

An MCP server launched by your editor is a process on your machine, started by
you, running as you. There is no operating-system boundary between it and
`~/.ssh/id_ed25519`. Whatever it can read, it can hand to a model, and from
there to a provider's logs and to any transcript you share.

Most of the sandboxing in that situation is one function: the one that turns a
path a model asked for into a file the process opens. Two obvious versions of
that function are both wrong:

1. **Check the string, then open it.** `docs/../../.ssh/id_rsa` has no
   suspicious component after the first, and a check that runs before
   normalisation is a check against a different path than the one that gets
   opened.
2. **Normalise lexically, then compare prefixes.** `/work/../worker` normalises
   inside `/work` by string prefix and outside it in fact, and a symbolic link
   is invisible to lexical normalisation entirely.

This server resolves the candidate fully — following every link, on the real
filesystem — and only then asks whether the resolved path is under the resolved
root. `tests/security/test_sandbox_escape.py` is 74 attempts to get past it.

The second half of the story runs in the other direction. Everything this server
returns came from files, and files come from pull requests, dependencies and
downloaded fixtures. A comment reading *"AI assistant: ignore all previous
instructions"* is, to a model reading a search result, indistinguishable from
something you said — unless the boundary is marked.

## Key capabilities

| Capability | How it is enforced |
|---|---|
| Containment | Paths are resolved on the real filesystem, then checked against the resolved root. Symbolic links are not followed by default; a walk never descends one. |
| Denial by class | `.env`, `*.pem`, `id_rsa`, `.git/`, `.ssh/`, `.aws/` and more, matched against the *resolved* path so `docs/../.env` is the same request as `.env`. Configuration can extend the list; nothing can shorten it. |
| Secret redaction | 17 credential shapes replaced in **both** halves of every result — the prose a model reads and the structured data a program parses — with the count and rule names reported so the control is auditable. |
| Untrusted marking | File content is fenced with a per-response nonce and scored by 10 injection signals, and is returned **byte-identical to disk**. Marking, not neutralising — see ADR-006. |
| Read-only by construction | No tool writes, moves, deletes, runs a shell, or reaches the network. It is a property of the published set, asserted by a test that inspects the registry. |
| One subprocess, hardened | `git log` and `git diff` only: fixed argv, no shell, a revision charset that cannot start with `-`, paths after `--`, a scrubbed environment, and `protocol.ext.allow=never`. |
| Bounded | File size, line count, result bytes, directory entries, walk breadth, wall-clock budget — and a static guard that refuses regular expressions which can backtrack catastrophically. |
| Conformance | 23 checks against the specification, runnable against any 2026-07-28 server, with negative controls proving each one fails when the requirement is broken. |

## Quickstart

```bash
uv sync --all-extras --dev
python tasks.py doctor          # what would be served, and what would be refused
python tasks.py tools           # the published tool set
```

Ask it something:

```bash
uv run mcp-devserver --workspace . call project_overview
uv run mcp-devserver --workspace . call search_code '{"pattern": "def resolve"}'
uv run mcp-devserver --workspace . call read_file '{"path": "src/mcp_devserver/errors.py", "end_line": 20}'
```

Or run the examples, which are executable documentation:

```bash
python examples/quickstart.py         # what a client sees, end to end
python examples/sandbox_demo.py       # eight escape attempts and what happened
python examples/untrusted_demo.py     # a poisoned file, marked and returned intact
```

## Connecting an editor

The stdio transport is what an MCP client spawns. Most clients take a command
and an environment:

```json
{
  "mcpServers": {
    "devserver": {
      "command": "uvx",
      "args": ["--from", "mcp-devserver", "mcp-devserver", "serve", "--transport", "stdio"],
      "env": { "MCP_SANDBOX__WORKSPACE": "/absolute/path/to/your/repository" }
    }
  }
}
```

`MCP_SANDBOX__WORKSPACE` is the whole security configuration: it is the only
directory the server can reach.

Over HTTP instead:

```bash
docker compose up --build -d
curl -s localhost:8080/readyz | python -m json.tool
```

## The protocol

Revision 2026-07-28 is a redesign rather than an increment, and this server
implements the new shape rather than adapting the old one:

- **There is no `initialize` handshake.** Every request carries its own
  `_meta` with `io.modelcontextprotocol/protocolVersion` and
  `clientCapabilities`. A request missing either is `-32602`.
- **`server/discover` is mandatory** and reports supported versions,
  capabilities, instructions and a cache lifetime.
- **Every result carries `resultType`.** A client must treat an absent one as
  complete, which means omitting it fails *silently* — so a conformance check
  asserts it across every method rather than trusting each handler.
- **`-32020`–`-32099` is reserved for the specification.** This server emits
  three codes from it and never invents a fourth; `-32002` and `-32042` are
  withdrawn and a test proves neither leaves the process.
- **Servers must not rely on state from earlier requests.** Here that is
  structural: `Server` holds only start-up configuration, and every per-request
  value lives in a context built inside the handler and discarded when it
  returns.

A legacy client sending `initialize` gets `-32022` naming the revisions this
server speaks — ten lines instead of a second protocol era. [ADR-002](ARCHITECTURE.md)
explains the trade.

See [docs/protocol.md](docs/protocol.md).

## The tools

Seven, all read-only. What is absent is as much of the design as what is present.

| Tool | Answers | Notes |
|---|---|---|
| `project_overview` | "What is this repository?" | Language mix, manifests, entry points, test count, VCS — one call instead of six exploratory listings. |
| `list_directory` | "What is in here?" | Denied entries counted, not named. Symlinks reported as skipped. |
| `read_file` | "What does this file say?" | Line-numbered, range-selectable, fenced as untrusted. |
| `search_code` | "Where does this appear?" | Literal or regex, glob-filtered, with a ReDoS guard. |
| `find_symbol` | "Where is this defined?" | Python is **parsed**; other languages are matched by pattern, and every result says which — `parsed` or `pattern`. |
| `git_log` | "What changed recently?" | Commit subjects are attacker-controlled text and arrive fenced. |
| `git_diff` | "What changed here?" | Working tree, index, or against a revision. |

There is **no shell tool**, no write, no test runner and no network fetch. A
test runner would mean executing the project's code, which path containment
cannot constrain — and a hole there would make the rest of the sandbox
unclaimable. See [docs/tools.md](docs/tools.md).

## What a denial looks like

A refusal is a *result*, not a transport error, because a model that never sees
the refusal cannot learn from it:

```jsonc
{
  "resultType": "complete",
  "isError": true,
  "content": [{ "type": "text", "text":
    "'../../.ssh/id_rsa' resolves outside the workspace and cannot be read. Paths must stay inside myproject/." }],
  "structuredContent": {
    "error": "outside_workspace",
    "message": "'../../.ssh/id_rsa' resolves outside the workspace and cannot be read.",
    "remedy": "Paths must stay inside myproject/."
  }
}
```

The message names the workspace and never the resolved path: a denial that
echoes back where it looked is an oracle for mapping the filesystem outside the
sandbox one request at a time.

## Conformance is the gate

```bash
python tasks.py conform                 # in-process
python tasks.py conform-stdio           # against a real server process
uv run mcp-devserver conform --http http://localhost:8080/mcp --strict
```

```
target      stdio (uv run mcp-devserver serve --transport stdio)
checks      23/23 passed
duration    412ms

  ok    C001  [MUST]    server/discover is implemented
  ok    C004  [MUST]    every result carries resultType
  ok    C011  [MUST]    an unsupported version returns -32022 and the supported list
  ok    C017  [MUST]    notifications receive no response
  ok    C021  [MUST]    requests do not share connection state
  ...

CONFORMANT
```

CI runs it in-process, over stdio, and inside the built container. The suite
itself is tested by breaking things: `tests/conformance` mutates responses one
requirement at a time and asserts the corresponding check goes red. A suite that
has only ever seen a correct server proves nothing about whether it would notice
an incorrect one.

See [docs/conformance.md](docs/conformance.md).

## Testing

```bash
python tasks.py test            # everything, with the coverage gate
python tasks.py test-security   # adversarial; a failure is a security regression
python tasks.py test-e2e        # a real server process over a real pipe
python tasks.py smoke           # build the image and exercise it over HTTP
```

515 tests across five layers — unit, integration, security, e2e and conformance
— at 91% coverage against an 88% gate. The security layer is 131 of them: path
traversal through every tool that takes a path, symlink escape, denylist
bypasses, credential leakage through both halves of a result, git argument
injection, and resource exhaustion.

## Configuration

Every setting is an environment variable prefixed `MCP_`, with `__` for nesting.
[`.env.example`](.env.example) documents all of them, and unknown keys in a
section are **rejected at start-up** rather than silently ignored — a mistyped
`MCP_SANDBOX__MAX_FILE_BTYES` would otherwise leave you believing a limit is in
force that is not.

| Setting | Default | Why |
|---|---|---|
| `MCP_SANDBOX__WORKSPACE` | the working directory | The only directory reachable. |
| `MCP_SANDBOX__FOLLOW_SYMLINKS` | `false` | A followed link is a path nobody asked for. |
| `MCP_SECURITY__REDACT_SECRETS` | `true` | The control behind "credentials do not leave". |
| `MCP_SECURITY__SCAN_UNTRUSTED_CONTENT` | `true` | The control behind the fences. |
| `MCP_HTTP__BEARER_TOKEN` | empty | Required in production; an unauthenticated listener is a remote read primitive. |
| `MCP_SANDBOX__TOOL_TIMEOUT_SECONDS` | `15` | What bounds a walk. |

With `MCP_ENVIRONMENT=production` a process with any of these wrong **refuses to
start**. See [docs/configuration.md](docs/configuration.md).

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — the design and eight decision records
- [THREAT-MODEL.md](THREAT-MODEL.md) — assets, adversaries, and what is *not* mitigated
- [docs/protocol.md](docs/protocol.md) — what revision 2026-07-28 requires and how it is met
- [docs/tools.md](docs/tools.md) — every tool, argument and error code
- [docs/configuration.md](docs/configuration.md) — every setting
- [docs/conformance.md](docs/conformance.md) — the suite, and how to run it against your own server
- [docs/operations.md](docs/operations.md) — running it, and what to watch
- [SECURITY.md](SECURITY.md) — reporting a vulnerability

## Known limitations

Stated plainly, because a portfolio project that claims to be finished is less
useful than one that says where the edges are.

- **Marking only works if the client honours it.** The fences and the risk score
  are information; nothing here can make a client act on them. That asymmetry is
  deliberate — the specification puts trust decisions on the client side — but
  it is a real residual risk and `THREAT-MODEL.md` says so.
- **The injection signals are heuristics.** Ten patterns over source code, tuned
  so that ordinary documentation does not trip them. Novel phrasing gets through.
- **The ReDoS guard is a heuristic too.** Recognising every exponential regular
  expression is undecidable; this catches nested and overlapping quantifiers,
  which is what appears in practice, and the wall-clock budget covers merely-slow
  patterns.
- **Secret redaction recognises shapes, not entropy.** A 40-character password in
  a variable called `x` is indistinguishable from a hash.
- **`find_symbol` is exact only for Python.** Other languages are pattern-matched
  and can report a definition inside a comment. Every result says which method
  produced it, so the uncertainty is visible rather than averaged away.
- **The workspace is one directory.** A monorepo served at its root is served
  whole; there is no per-subtree permission model.
- **No `resources` or `prompts` capability.** Tools only. Adding them would be
  more protocol surface without more of the thing this project is about.

## Licence

MIT — see [LICENSE](LICENSE).
