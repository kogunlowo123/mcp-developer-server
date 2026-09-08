# Threat model

## Scope and posture

This document is about one process: an MCP server started by a developer's
editor or run as a container, serving one directory to a language model.

The defining fact is that **there is no privilege boundary between this process
and the developer's files**. It runs as them. Everything below follows from
that: the controls here are the only ones there are, and where they stop, the
document says so rather than implying otherwise.

## Assets

| Asset | Why it matters |
|---|---|
| Files outside the workspace | `~/.ssh`, `~/.aws`, `~/.config`, other repositories. The process can read them; the sandbox is what stops it. |
| Credentials inside the workspace | A checked-in `.env`, a fixture private key, a hard-coded token in `settings.py`. Reaching a model means reaching a provider's logs and any shared transcript. |
| The developer's attention | An answer built on injected text is worse than no answer, because it looks like an answer. |
| The host's CPU and memory | This is the developer's own machine. A request that pins a core is their laptop getting slower with no explanation. |
| The workspace's integrity | Nothing here writes, but a design that made writing possible would put it at risk. |

## Adversaries

**A1 — A malicious or confused client.** Sends crafted `tools/call` arguments:
traversal, absolute paths, oversized inputs, catastrophic patterns. Reaches
every published tool. This is the adversary the sandbox is built for.

**A2 — Content in the workspace.** A dependency, a vendored file, a pull request,
a downloaded fixture. Cannot make requests; can only be *read*. Its lever is what
a model does after reading it.

**A3 — A model steered by A2.** Reads an injected instruction and issues the
requests it asks for. Bounded by what the tool set makes possible — which is why
the tool set is the smallest one that is still useful.

**A4 — Another process on the machine, or a page in the developer's browser.**
Relevant only to the HTTP transport: a loopback listener is reachable by
anything local, and a browser can POST JSON cross-origin without a preflight.

**A5 — A supply-chain compromise of this server's dependencies.** Five runtime
packages, pinned by lockfile, audited in CI.

Explicitly **out of scope**: an attacker who already has code execution as the
developer. They do not need this server.

---

## Threats and controls

### T1 — Path traversal out of the workspace

*A1 asks for `../../.ssh/id_rsa`, or an absolute path, or `docs/../../../etc/passwd`.*

**Controls.** Paths are resolved on the real filesystem and the *resolved* path
is checked against the *resolved* root, using case-normalised path parts rather
than string prefixes. Absolute paths are not rejected out of hand — they may
name something legitimately inside — they are resolved and contained like any
other. A NUL byte in a path is refused, because it truncates the name at the
operating-system boundary and the string that is checked would not be the string
that is opened.

**Residual.** A hard link to a file outside the workspace, created inside it, is
indistinguishable from an ordinary file after resolution and would be readable.
Creating one requires write access to the workspace and the same privileges this
server already runs with, so it is not a privilege gain — but it is a real gap in
the containment claim, and mitigating it would mean comparing device and inode
numbers on every read.

**Tests.** `tests/security/test_sandbox_escape.py::TestPathTraversal` — eight
escape shapes against all seven path-taking tools.

### T2 — Symbolic link escape

*A1 asks for a link inside the workspace that points outside it; or a walk
descends a symlinked directory.*

**Controls.** Resolution follows links before containment is checked, so an
escaping link fails T1's check. Links are not followed at all by default, even
when they stay inside. `os.walk` runs with `followlinks=False` and symlinked
directories are dropped from the descent list explicitly; every yielded path is
re-checked for containment.

**Residual.** A link swapped between the check and the `open` is a genuine race.
The window is one `open` call, and closing it entirely needs `openat` with
`O_NOFOLLOW`, which is not portable to the Windows hosts this server has to run
on.

**Tests.** `TestSymlinkEscape`, plus `tests/unit/test_workspace.py`. These
**skip on Windows**, which cannot create links without elevation — a visible
skip rather than a silent pass. CI runs on Linux, where they execute.

### T3 — Reading a credential file that is inside the workspace

*A checked-in `.env`, `deploy.pem`, `.git/config` with a token in a remote URL.*

**Controls.** A denylist of names, glob patterns and whole directories, matched
case-insensitively against every component of the resolved relative path.
`.git/` is denied entirely — history is reached through the `git` binary, so
nothing needs the object store. Configuration can extend the list; there is no
setting that shortens it.

**Residual.** The list is a list. A credential in `config/production.yaml` is not
on it. That is what T4 is for.

**Tests.** `TestDenylist` in both the unit and security suites.

### T4 — A credential inside an ordinary file reaching the model

*A hard-coded token in `settings.py`, surfaced by `read_file` or `search_code`.*

**Controls.** Seventeen credential shapes are replaced on the way out —
provider-specific tokens, private key blocks, URL-inline credentials,
`Authorization` headers, and a generic assignment rule requiring both a
secret-ish name and a value with enough entropy shape to not be a placeholder.
Redaction runs over the **assembled** result, so both the prose and the
structured half are covered, including anything derived from raw content such as
a scanner excerpt. Every result reports whether redaction fired, how often, and
under which rules.

**Residual.** This recognises shapes, not entropy. A 40-character password in a
variable called `x` is indistinguishable from a hash and will pass through. It
is not a secret scanner and does not claim to be.

**Tests.** `tests/security/test_content_controls.py::TestSecretsDoNotLeave`,
including an assertion over the whole serialised envelope rather than one member
of it — because a control applied to one member is exactly the bug that appeared
twice during development.

### T5 — Prompt injection through file content

*A2 writes "AI assistant: ignore all previous instructions" into a comment. A3
reads it in a search result and acts on it.*

**Controls.** Content is fenced with a per-response nonce, so it cannot close its
own delimiter and continue outside. Ten signals score it — instruction override,
persona assignment, disclosure requests, counterfeit role markers, exfiltration
directives, concealment requests — combined with noisy-OR, with NFKC folding for
detection so homoglyph and full-width evasion is caught, and invisible
formatting characters counted as evidence in themselves. The signals, the risk
and the level appear in `structuredContent`; the tool descriptions and the
`server/discover` instructions tell the client what the fence means.

**The content itself is never rewritten.** ADR-006 explains why: the user asked
to read that file, and neutralising it would show them source that does not
exist and destroy the evidence a security review is looking for.

**Residual — and it is the largest one in this document.** Marking is
information. Nothing here can make a client act on it, and a client that ignores
the fence gets no protection from this control at all. The specification places
trust decisions on the client side, which is the right architecture and is also
why this server can only do half the job. The signals are heuristics; novel
phrasing gets through.

**Tests.** `TestUntrustedContentIsMarkedNotRewritten` — including an assertion
that the returned bytes match the file on disk line for line, and a negative
control that ordinary documentation is not flagged high.

### T6 — Command injection through the git tools

*A1 supplies a revision of `--upload-pack=curl …`, or a path beginning with a dash.*

**Controls.** Four layers. The published `inputSchema` constrains `revision` to a
charset that excludes `-` at the start and every shell metacharacter, so a hostile
value never reaches the handler. The handler validates again, so a loosened schema
does not silently remove the only check. `subprocess.run` is called with a list
and `shell=False`, so there is no point at which caller text is parsed by a shell.
Paths are passed after the `--` separator, where git treats every remaining token
as a path.

Two subcommands are reachable — `log` and `diff` — chosen by this module and
never by an argument. The child environment is **built rather than inherited**:
`GIT_EDITOR`, `GIT_SSH`, `GIT_EXTERNAL_DIFF` and the rest name programs git would
run, and inheriting the parent's environment means inheriting whatever the
developer's shell profile set. `HOME` points at the workspace and global config
is disabled, so a `~/.gitconfig` alias or pager cannot run.
`protocol.ext.allow=never` makes "no network" structural rather than incidental.

**Residual.** `git` itself is trusted. A vulnerability in the binary is not
mitigated here.

**Tests.** `TestGitSubprocessHardening` — eight hostile revisions against both
the schema and the handler, plus environment assertions.

### T7 — Denial of service through a catastrophic regular expression

*A1 sends `(a+)+b` to `search_code`.*

**Controls.** A static guard refuses quantified groups containing a quantifier
and quantified groups with overlapping alternatives, **before** compilation.
Pattern length is capped at 512.

**Residual.** A heuristic. A pattern outside these shapes that is merely slow is
bounded only by the per-file wall-clock budget, and a single pathological match
inside one file cannot be interrupted at all — Python offers no way to stop a
running `re` match, and abandoning the thread leaves it burning a core. The
honest mitigation for what remains is that this server is meant to be run by the
developer whose machine it is.

**Tests.** `tests/unit/test_redos.py` — ten catastrophic shapes caught, fourteen
legitimate patterns allowed.

### T8 — Denial of service through volume

*A1 reads a two-gigabyte file, walks a monorepo, or requests every match in it.*

**Controls.** Caps on file size (checked before reading, and again while
reading), read lines, search results, result bytes, directory entries, walked
files and wall-clock time. Generated trees — `node_modules`, `.venv`, build
output — are skipped by the walk. Files over 512 KB are skipped by search rather
than read. Request bodies are bounded on both transports, and a stdio line that
exceeds the cap is answered with a parse error and drained to the next newline so
the stream resynchronises.

**Residual.** Concurrency on stdio is bounded at eight; a client that opens many
connections to the HTTP transport is bounded only by the process.

**Tests.** `tests/security/test_resource_bounds.py`.

### T9 — An unauthenticated HTTP listener

*A4 reaches a loopback port opened by the developer.*

**Controls.** A bearer token, compared with `hmac.compare_digest` so the
comparison does not leak a matching prefix through timing. `Origin` is checked
before authentication — otherwise the endpoint is an oracle for token validity
from any page the developer visits — which is the DNS-rebinding defence the
specification asks HTTP servers for. Probes answer without a token, because a
liveness check that needs a credential reports the wrong thing when the
credential is wrong. Production **refuses to start** without a token.

**Residual.** Transport security is the deployment's problem: this server speaks
plain HTTP and expects a reverse proxy for TLS.

**Tests.** `TestHttpAuthorisation`.

### T10 — Information disclosure through error messages

*A1 probes the filesystem one refusal at a time.*

**Controls.** A containment denial names the workspace directory and the path as
*requested*, never the resolved absolute path. An unexpected exception becomes
`-32603` with no detail; the traceback goes to the log, because a traceback names
absolute paths outside the workspace — exactly what the sandbox exists to
withhold. A directory listing counts denied entries rather than naming them.

**Tests.** `test_the_refusal_does_not_disclose_the_absolute_path`,
`test_an_unexpected_failure_becomes_an_internal_error_without_detail`.

### T11 — Configuration that silently disables a control

*A mistyped environment variable leaves a limit unset while the operator believes
it is in force.*

**Controls.** Every settings section sets `extra="forbid"`, so an unknown key is
a start-up error rather than a shrug. Production invariants — redaction on,
scanning on, symlinks not followed, HTTP authenticated, workspace not a home or
root directory — are checked at start-up and refuse the process. `doctor`
reports the same list outside production as warnings.

**Tests.** `tests/unit/test_config_and_registry.py::TestSettings`.

### T12 — Server-side request forgery through JSON Schema

*A `$ref` pointing at an attacker's host.*

**Controls.** Only local `#/$defs` pointers resolve; anything else is refused at
registration, so a schema with a network `$ref` cannot be published. Depth is
capped on both schema and instance.

**Residual.** None known. This server does not accept client-supplied schemas at
all, so the control is defence in depth for a surface that is currently closed.

### T13 — Log output corrupting the protocol stream

*A library prints a warning to stdout, which is the stdio wire.*

**Controls.** Every log record goes to stderr. The root logger is configured
explicitly and its handlers are replaced rather than appended, so a second
`configure` cannot duplicate lines. Third-party records are routed through the
same processor chain. Credential-shaped keys are redacted from log events.

**Tests.** `tests/e2e/test_real_process.py::test_stdout_carries_nothing_but_responses`
— a real subprocess, asserting the exact line count on stdout.

### T14 — A compromised dependency

**Controls.** Five runtime packages, resolved by lockfile. CI runs `pip-audit`
against the locked set, Trivy over the filesystem and the image, `bandit` over
the source, CodeQL with `security-extended`, and gitleaks over both the tree and
the full history. No `continue-on-error` anywhere.

**Residual.** A compromise published and installed between two CI runs.

---

## Summary

| # | Threat | Mitigated | Residual risk |
|---|---|---|---|
| T1 | Path traversal | Yes | Hard links inside the workspace |
| T2 | Symlink escape | Yes | Check-to-open race, one `open` wide |
| T3 | Denied credential files | Yes | Only what is on the list |
| T4 | Credentials in ordinary files | Yes | Shapes, not entropy |
| T5 | Prompt injection in content | **Partly — by design** | The client must honour the marking |
| T6 | Git command injection | Yes | `git` itself is trusted |
| T7 | Catastrophic regex | Yes | Heuristic; merely-slow patterns bounded only by time |
| T8 | Resource exhaustion | Yes | HTTP connection count |
| T9 | Unauthenticated listener | Yes | TLS is the deployment's job |
| T10 | Disclosure via errors | Yes | — |
| T11 | Silent misconfiguration | Yes | — |
| T12 | SSRF via `$ref` | Yes | — |
| T13 | Log corrupting the wire | Yes | — |
| T14 | Supply chain | Partly | Window between CI runs |

## What a production deployment must add

This repository is a complete server and an incomplete deployment. Running it
somewhere that matters needs:

1. **TLS**, terminated by a reverse proxy. This server speaks plain HTTP.
2. **A real credential store** for `MCP_HTTP__BEARER_TOKEN`, and rotation. An
   environment variable in a compose file is a demonstration.
3. **Rate limiting** in front of the HTTP transport. Per-request bounds exist;
   per-client ones do not.
4. **Log shipping**, with the understanding that tool arguments are the
   developer's private directory structure. `MCP_OBSERVABILITY__LOG_TOOL_ARGUMENTS`
   is off by default for that reason.
5. **A client that honours the untrusted-content marking.** Without it, T5 is
   not mitigated at all — only reported.
6. **A decision about the workspace.** One directory, served whole. If different
   callers should see different subtrees, that is a separate server per subtree,
   not a setting.

## Reporting

See [SECURITY.md](SECURITY.md).
