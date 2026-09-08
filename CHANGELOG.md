# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-09-08

First release. A Model Context Protocol server implementing revision
**2026-07-28**, publishing seven read-only tools over one contained workspace.

### Added

**Protocol**

- The stateless per-request model of revision 2026-07-28: no `initialize`
  handshake, `_meta` validation on every request, `server/discover` as a
  mandatory method, `resultType` on every result, and the `-32020`/`-32021`/`-32022`
  error family.
- `tools/list` with opaque cursor pagination, deterministic ordering, and
  `ttlMs`/`cacheScope` caching hints.
- `-32022` in answer to a legacy `initialize`, naming the revisions this server
  serves, so an older client learns what to speak in one round trip.
- Two transports over one dispatcher: newline-delimited stdio, and streamable
  HTTP with a bearer token, an `Origin` check, a streamed body limit and a
  protocol-version header cross-check.

**Sandbox**

- Workspace containment that resolves a path on the real filesystem — following
  every symlink — before checking it against the resolved root, using
  case-normalised path parts rather than string prefixes.
- A denylist of names, glob patterns and directories matched against the
  *resolved* path, extensible by configuration and impossible to shorten.
- Bounds on file size, read lines, search results, result bytes, directory
  entries, walked files and wall-clock time.

**Security**

- Credential redaction across 17 shapes, applied to the assembled result so both
  the prose and the structured half are covered, with the count and rule names
  reported on every result.
- Untrusted-content marking: a per-response nonce fence, 10 injection signals
  combined with noisy-OR, NFKC folding for detection, invisible-character
  counting — and content returned byte-identical to disk.
- A static ReDoS guard that refuses catastrophically-backtracking patterns
  before compilation.
- Git subprocess hardening: two allowlisted subcommands, a revision charset that
  cannot begin with `-`, paths after `--`, a built-not-inherited environment,
  and `protocol.ext.allow=never`.
- Production start-up invariants, and `extra="forbid"` on every settings section
  so a mistyped variable is an error rather than a silently ignored one.

**Tools**

- `project_overview`, `list_directory`, `read_file`, `search_code`,
  `find_symbol`, `git_log`, `git_diff`. All read-only; the property is asserted
  by a test that inspects the registry.
- `find_symbol` parses Python with `ast` and pattern-matches other languages,
  reporting which method produced each result.

**Conformance**

- 23 checks derived from the specification, runnable against any 2026-07-28
  server over stdio, HTTP or in-process, exiting non-zero on a failure.
- Negative controls: the suite is run against deliberately broken servers, one
  requirement at a time, asserting the corresponding check fails.

**Command line**

- `serve`, `conform`, `call`, `tools`, `doctor`.

**Project**

- 515 tests across five layers at 91% coverage against an 88% gate.
- CI: lint, format, mypy strict, a five-suite test matrix, a coverage gate, a
  conformance gate run both in-process and over stdio, executable examples, and
  a distribution build.
- Security workflow: gitleaks over tree and full history, bandit, pip-audit
  against the locked set, CodeQL `security-extended`, Trivy over filesystem and
  image. No `continue-on-error`.
- Container workflow: build, Trivy image scan, a non-root assertion, and a smoke
  test that runs the conformance suite *inside* the running image.
- A documentation site generated from the repository's own Markdown, failing the
  build on a broken internal link.

### Notes on decisions

Three choices are recorded in [ARCHITECTURE.md](ARCHITECTURE.md) because they
are the ones a reader is most likely to question:

- **The protocol layer is hand-written rather than built on an SDK** (ADR-001),
  because the specification's conformance requirements are the subject and an
  SDK would own exactly the code the tests need to exercise.
- **Only revision 2026-07-28 is served** (ADR-002). Legacy clients get a precise
  error instead of a second protocol era.
- **Untrusted content is marked, never rewritten** (ADR-006) — the opposite of
  what a retrieval system should do, and the reason is that the developer asked
  to read that specific file.

### Defects found and fixed during development

Recorded because the tests that caught them are the reason to trust the rest:

- `structuredContent` was not redacted, so a credential on a matched line left
  the process through the machine-readable half of a result while the prose was
  clean.
- After that was fixed, the injection scanner's *excerpt* — derived from the raw
  content and attached after the redaction pass — carried credentials again. The
  `INJ08` signal spans from `curl` to `| sh`, so a URL credential in such a line
  landed inside the excerpt. Fixed by assembling the whole result first and
  redacting once, which closes the class rather than the instance (ADR-007).
- `search_code`'s wall-clock budget did not bound a catastrophically
  backtracking regular expression, and the module docstring claimed it did. The
  budget is checked between files; `(a+)+b` never returns from a single
  `re.search`. Fixed with a static guard applied before compilation (ADR-008).
- The stdio transport used `loop.connect_read_pipe`, which does not work on
  Windows — the platform an MCP server most needs to run on. Rewritten to read
  on a worker thread.
- `Denylist.reason` carried a guard clause immediately subsumed by the check
  below it, which read as confusion about the rule in the file a reviewer opens
  first.

[Unreleased]: https://github.com/kogunlowo123/mcp-developer-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kogunlowo123/mcp-developer-server/releases/tag/v0.1.0
