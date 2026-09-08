# Configuration

Every setting is an environment variable: `MCP_` + section + `__` + field.
[`.env.example`](../.env.example) lists all of them with their defaults.

Two properties are worth knowing before anything else.

**Unknown keys are errors.** Every section sets `extra="forbid"`. A mistyped
`MCP_SANDBOX__MAX_FILE_BTYES` fails at start-up rather than being ignored — a
settings object that silently discards what it does not recognise turns
configuration into a suggestion.

**`doctor` tells you what you actually configured:**

```
$ mcp-devserver doctor
environment        local
protocol           2026-07-28
workspace          /home/dev/widgets
tools              7 (find_symbol, git_diff, git_log, list_directory, project_overview, read_file, search_code)
max file bytes     1048576
follow symlinks    False
redact secrets     True
scan content       True
denied names       19
denied patterns    14
http auth          NOT SET

warnings:
  - MCP_HTTP__BEARER_TOKEN is empty: the HTTP transport would accept any caller

ready, with warnings
```

## Sandbox

### `MCP_SANDBOX__WORKSPACE`

The one directory this server can reach. This is the whole of the access-control
configuration: there is no allowlist of subpaths and no per-caller scoping. If
different callers should see different subtrees, run a server per subtree.

Defaults to the working directory, which is convenient locally and wrong almost
everywhere else. The container sets it to `/workspace` so
`docker run -v $PWD:/workspace` needs no further flags.

Refused at start-up if it does not exist, is not a directory, or is a filesystem
root — serving `/` would place every readable file inside the sandbox, which is
the same as having no sandbox.

### `MCP_SANDBOX__FOLLOW_SYMLINKS`

Default `false`. A link that leaves the workspace is refused by containment
regardless; this setting governs links that stay *inside* it. Off means such a
link is refused with `denied_path` and a suggestion to read the target directly,
because a followed link is an indirection the caller did not ask for.

Turning it on is refused in production.

### `MCP_SANDBOX__DENY_EXTRA`

Comma-separated names or globs added to the built-in denylist. An entry
containing `*`, `?` or `[` becomes a pattern; anything else becomes an exact
name — splitting it here removes a configuration mistake in which a pattern is
registered as a literal and silently matches nothing.

**The list can only grow.** There is no setting that removes a built-in entry.
An allowlist that could be emptied by an environment variable would be a lock
with the key taped to it.

Built in: `.env`, `.env.*`, `.envrc`, `.netrc`, `.pgpass`, `.git-credentials`,
`.npmrc`, `.pypirc`, `credentials`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`,
`known_hosts`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.jks`, `*.kdbx`, `*.ppk`,
`*.asc`, `*.tfstate`, and the directories `.git`, `.ssh`, `.aws`, `.azure`,
`.gnupg`, `.kube`, `.docker`.

### Bounds

| Setting | Default | Bounds what |
|---|---|---|
| `MAX_FILE_BYTES` | 1 MiB | The largest file `read_file` will return |
| `MAX_READ_LINES` | 4000 | Lines per read |
| `MAX_SEARCH_RESULTS` | 200 | Matches per search |
| `MAX_SEARCH_FILES` | 20000 | Files visited by one walk |
| `MAX_RESULT_BYTES` | 256 KiB | Rendered size of a search result |
| `MAX_DIRECTORY_ENTRIES` | 1000 | Entries in one listing |
| `MAX_GIT_ENTRIES` | 200 | Commits per `git_log` |
| `TOOL_TIMEOUT_SECONDS` | 15.0 | Wall clock for one call |

A caller can ask for less than these but never more: a request for 500 matches
against a cap of 200 gets 200 and `truncated: true`.

## Security

| Setting | Default | Effect when false |
|---|---|---|
| `MCP_SECURITY__REDACT_SECRETS` | `true` | A hard-coded key in a source file is returned verbatim to a language model |
| `MCP_SECURITY__SCAN_UNTRUSTED_CONTENT` | `true` | File contents arrive with no indication that they are untrusted |
| `MCP_SECURITY__INCLUDE_SIGNAL_EXCERPTS` | `true` | Findings report the signal and line but not the matched text |

The first two are refused in production.

## HTTP

Only used with `serve --transport http`.

| Setting | Default | Notes |
|---|---|---|
| `HOST` | `127.0.0.1` | The container overrides to `0.0.0.0`; a loopback bind inside a container is unreachable from the published port |
| `PORT` | `8080` | |
| `BEARER_TOKEN` | empty | Required in the `Authorization` header when set. Compared in constant time |
| `ALLOWED_ORIGINS` | empty | Browser origins permitted. A request with no `Origin` did not come from a browser and is allowed |
| `MAX_REQUEST_BYTES` | 1 MiB | Enforced on the stream, not only on `Content-Length` |

An empty `BEARER_TOKEN` means any process on the machine — and any page the
developer visits — can reach the endpoint. The server warns loudly at start-up
and production refuses to start.

## Observability

| Setting | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `info` | |
| `LOG_JSON` | `true` | Always to **stderr**: on stdio, stdout is the wire |
| `LOG_TOOL_ARGUMENTS` | `false` | Paths are not secrets but are the developer's private directory structure |
| `TRACING_ENABLED` | `false` | Needs the `otel` extra |
| `OTLP_ENDPOINT` | empty | |

## Production invariants

With `MCP_ENVIRONMENT=production`, the process **refuses to start** if:

- `MCP_SECURITY__REDACT_SECRETS` is false
- `MCP_SECURITY__SCAN_UNTRUSTED_CONTENT` is false
- `MCP_SANDBOX__FOLLOW_SYMLINKS` is true
- `MCP_HTTP__BEARER_TOKEN` is empty
- `MCP_SANDBOX__WORKSPACE` is a home directory or a filesystem root

Outside production the same list is reported as warnings by `doctor` and at
start-up.

### A note on the bearer-token rule and stdio

The token requirement applies in production **even when serving over stdio**,
where no port is opened and the check is therefore not protecting anything.

That is deliberate but worth stating plainly, because it is the one place the
invariants are cruder than the deployment shapes. `production` here means
"assume the strictest posture for every transport this process could serve",
not "detect which transport is running and relax accordingly" — a check that
weakened itself based on how the process happened to be invoked would be a check
that a misconfiguration could switch off.

The consequence: an editor-launched stdio server is normally run with
`MCP_ENVIRONMENT=local`. To harden one, set the other invariants explicitly and
confirm with `doctor`, which lists them regardless of environment:

```bash
MCP_SANDBOX__WORKSPACE=/srv/code \
MCP_SANDBOX__FOLLOW_SYMLINKS=false \
MCP_SECURITY__REDACT_SECRETS=true \
MCP_SECURITY__SCAN_UNTRUSTED_CONTENT=true \
  mcp-devserver doctor
```

Anything that still appears under `warnings:` is a real gap; the token line is
the one to ignore for a stdio deployment.

## Precedence

1. `--workspace` on the command line
2. Environment variables
3. `.env` in the working directory
4. Defaults

`.env` is for local development. It is git-ignored, and a production deployment
should use its platform's secret mechanism instead.
