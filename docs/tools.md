# The tools

Seven, all read-only. `GET`-shaped, in the sense that calling any of them twice
changes nothing.

Every declaration is published by `tools/list` and printable locally:

```bash
uv run mcp-devserver tools
uv run mcp-devserver tools --json
```

## What is absent, and why

**No shell tool.** A general-purpose command tool hands the model every
privilege the process has, and no sandbox above it can constrain what the
command does.

**No write, move or delete.** The server never opens a file for writing. A
confused or compromised client cannot damage the workspace through it — a
property of the code, not of a permission prompt. `tests/security` asserts it by
inspecting the registry, so adding a write tool cannot happen quietly.

**No test runner.** Running a project's tests means executing that project's
code, which is not containable by path rules — the very thing this server's
sandbox is built on. A tool that broke that guarantee would make every other
claim unclaimable.

**No network fetch.** The one subprocess is `git`, with `protocol.ext.allow=never`
and two subcommands that do not contact a remote.

## Common behaviour

**Paths** are relative to the workspace root, POSIX-style. An absolute path is
not refused out of hand — it may name something legitimately inside — it is
resolved and contained like any other.

**Refusals are results**, with `isError: true`, a stable `error` code and a
`remedy` naming what would have worked:

| Code | Meaning |
|---|---|
| `outside_workspace` | The resolved path is not under the workspace root |
| `denied_path` | On the denylist, or a symbolic link with following disabled |
| `not_found` | Nothing at that path |
| `not_a_file` / `not_a_directory` | Right path, wrong kind |
| `too_large` | Over the configured byte limit |
| `binary_file` | Contains a NUL byte in its first 8 KB |
| `bad_pattern` | Not a valid regular expression, too long, or catastrophic |
| `timed_out` | The wall-clock budget was spent |
| `not_a_repository` | No `.git` at the workspace root |
| `git_failed` | git exited non-zero, or a revision was refused |
| `unsupported` | A line range that cannot exist |

**Every result carries** `structuredContent.redaction` — whether credentials
were replaced, how many, and under which rules — so the control is auditable
rather than invisible.

**Tools returning file bytes** additionally carry `untrusted_content: true` and
`content_assessment`, and wrap the bytes in an `<untrusted-...>` fence with a
per-response nonce. The bytes themselves are exactly what is on disk.

---

## `project_overview`

Summarise the workspace in one call: language mix by file and line count, the
dependency manifests present and what they declare, likely entry points, test
file count, and whether the tree is under version control.

Call it first on an unfamiliar repository. It replaces the six or seven
exploratory listings an agent otherwise issues, and everything it reports is
measured from the filesystem rather than inferred.

| Argument | Type | Default |
|---|---|---|
| `path` | string | the workspace root |

Manifests understood in detail: `pyproject.toml`, `package.json`, `Cargo.toml`,
`go.mod`. Parsing is shallow on purpose — names, versions and *direct dependency
names*, not a resolved graph, because resolving means reaching the network.
A manifest that does not parse reports `parse_error` rather than failing the call.

## `list_directory`

The immediate contents of one directory.

| Argument | Type | Default |
|---|---|---|
| `path` | string | the workspace root |
| `include_hidden` | boolean | `false` (`.github` is always shown) |

Denied entries are **counted, not named**, in `hidden_by_denylist`. Symbolic
links are reported in `symlinks_skipped` rather than silently omitted — a link
is a real thing in the tree, and a listing that drops it without saying so
misleads. Each directory reports `walked_by_search`, so a caller can tell in
advance that `node_modules` will not be searched.

## `read_file`

One UTF-8 text file, or a line range of it. Returned lines are numbered, so a
model can cite a real line rather than counting.

| Argument | Type | Default |
|---|---|---|
| `path` | string | — (required) |
| `start_line` | integer ≥ 1 | 1 |
| `end_line` | integer ≥ 1 | end of file |

Bounded twice: the size is checked before the file is opened, and again while it
is read, because a cap applied after `read_bytes` has returned is not a cap.
Decoding uses `errors="replace"`, so a mostly-text file with one bad byte stays
readable.

## `search_code`

Literal or regular-expression search across the workspace.

| Argument | Type | Default |
|---|---|---|
| `pattern` | string, 1–512 chars | — (required) |
| `path` | string | the workspace root; a file is a valid target |
| `regex` | boolean | `false` |
| `case_sensitive` | boolean | `false` |
| `file_glob` | array of strings, ≤ 20 | all files |
| `context_lines` | integer 0–5 | 0 |
| `max_results` | integer 1–500 | the configured cap |

Generated and vendored trees are skipped. Files over 512 KB are skipped rather
than read — a minified bundle has no useful line structure and would dominate
the budget — and counted in `files_skipped`.

Patterns that can backtrack catastrophically are **refused before compilation**:

```
$ mcp-devserver call search_code '{"pattern": "(a+)+b", "regex": true}'
the pattern can take unbounded time to match: the group '(a+)' is repeated
with '+' and already contains a repetition. Rewrite it without a repetition
inside a repeated group, or set regex to false to search for the text literally.
```

This is a heuristic, and the negative half of its test suite is as large as the
positive half: a guard that refused `(foo|bar)+` would make the tool useless.
See [ADR-008](../ARCHITECTURE.md).

## `find_symbol`

Where a class, function, method or variable is defined.

| Argument | Type | Default |
|---|---|---|
| `symbol` | string | — (required) |
| `path` | string | the workspace root |
| `kind` | `class`/`function`/`method`/`variable`/`type`/`binding`/`any` | `any` |
| `exact` | boolean | `true` |

Two mechanisms, and **every result says which produced it**:

- `method: "parsed"` — Python, via `ast`. Exact line numbers, qualified names
  (`Engine.start`, not `start`), a class distinguished from a function from an
  assignment, and a name inside a string correctly not counted as a definition.
- `method: "pattern"` — every other language, by regular expression. Finds real
  definitions most of the time and cannot tell a definition inside a comment
  from one in code.

Parsed results sort first. A Python file with a syntax error is listed in
`unparseable_files` and falls back to patterns — reported rather than swallowed,
because falling back silently would misreport confidence.

## `git_log`

Recent commits: hash, short hash, author, ISO date, subject.

| Argument | Type | Default |
|---|---|---|
| `limit` | integer 1–200 | 20 |
| `revision` | string matching `^[A-Za-z0-9._/@^~{}-]+$` | `HEAD` |
| `path` | string | the whole repository |

Commit subjects and author names are fenced as untrusted: anyone who can open a
pull request can write them.

## `git_diff`

A unified diff of the working tree, the index, or against a revision.

| Argument | Type | Default |
|---|---|---|
| `revision` | string, same charset as above | working tree vs. index |
| `staged` | boolean | `false` |
| `stat_only` | boolean | `false` |
| `path` | string | the whole repository |
| `context_lines` | integer 0–10 | git's default of 3 |

Set `stat_only` when the full diff would be large; output over 256 KB is
truncated and says so.

### How the git tools are constrained

Four layers, described fully in [THREAT-MODEL.md](../THREAT-MODEL.md) T6:

1. The published schema restricts `revision` to a charset with no leading `-`
   and no shell metacharacters, so a hostile value never reaches the handler.
2. The handler validates again, so a loosened schema does not remove the only
   check.
3. `subprocess.run` with a list and `shell=False`; paths after the `--`
   separator, where git treats every remaining token as a path.
4. A **built, not inherited** environment: `GIT_EDITOR`, `GIT_SSH` and
   `GIT_EXTERNAL_DIFF` all name programs git would run, `HOME` points at the
   workspace so `~/.gitconfig` is not read, and `protocol.ext.allow=never` makes
   "no network" structural.

## Reading a result

```jsonc
{
  "resultType": "complete",
  "isError": false,
  "content": [
    { "type": "text", "text": "src/engine.py: lines 1-12 of 12, 190 bytes." },
    { "type": "text", "text": "<untrusted-file-content id=8ad53a1c9dc39957>\n 1  ...\n</untrusted-file-content id=8ad53a1c9dc39957>" }
  ],
  "structuredContent": {
    "path": "src/engine.py",
    "total_lines": 12,
    "truncated": false,
    "untrusted_content": true,
    "content_assessment": { "level": "none", "risk": 0.0, "signals": [] },
    "redaction": { "applied": false, "count": 0, "rules": [] }
  }
}
```

The first block is this server speaking. The second is the file speaking, and
the fence says so. Anything inside it is data to report on, never instructions
to follow.
