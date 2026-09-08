# Architecture

## The shape of the problem

An MCP server is not a service. It is a subprocess your editor starts, running
as you, with your filesystem privileges, whose output is fed to a language model
and from there into a provider's context.

Three consequences drive every decision in this repository:

1. **The sandbox is the product.** There is no container, no user namespace and
   no seccomp filter between this process and `~/.aws/credentials`. The boundary
   is a Python function, so that function had better be right, and had better be
   tested as though somebody is attacking it.
2. **Everything returned is untrusted.** Not "possibly malicious" — *untrusted*,
   in the specific sense that a third party wrote it and a model will read it as
   though the developer said it.
3. **A denial has to teach.** A model that gets a transport error learns
   nothing and retries. A model that gets "that path is outside the workspace,
   paths must stay inside `myproject/`" adapts.

## Layers

```
                    stdio (an editor)          HTTP (a deployment)
                          │                            │
              transport/stdio.py            transport/http.py
                          │                            │
                          └────────────┬───────────────┘
                                       │
                            protocol/server.py          ← dispatch, per-request context
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
            protocol/meta.py   protocol/schema.py   tools/base.py
            (negotiation)      (argument validation) (registry, result rendering)
                                                          │
                                             ┌────────────┴────────────┐
                                             │                         │
                                    sandbox/workspace.py       security/redaction.py
                                    sandbox/denylist.py        security/untrusted.py
                                             │
                                        tools/*.py
```

Nothing below `protocol/server.py` knows which transport a request arrived on,
and nothing in `tools/` knows what JSON-RPC is. That separation is what lets the
conformance suite run identically over stdio, over HTTP and in-process — and
what makes a transport bug distinguishable from a dispatch bug when one appears.

## Request lifecycle

```
bytes on a pipe or a socket
   │
   ├─ jsonrpc.parse ────────────────── not JSON ─────────────► -32700
   │                                   not a request ─────────► -32600
   │
   ├─ meta.parse_context
   │     ├─ reserved _meta prefix ─────────────────────────────► -32602
   │     ├─ header disagrees with body ────────────────────────► -32020
   │     ├─ version not served ────────────────────────────────► -32022 + supported[]
   │     └─ clientCapabilities missing ────────────────────────► -32602
   │
   ├─ dispatch
   │     ├─ initialize (legacy) ───────────────────────────────► -32022
   │     ├─ unknown method ────────────────────────────────────► -32601
   │     ├─ server/discover ───────────────────────────────────► result
   │     ├─ tools/list ────────────────────────────────────────► result (paged)
   │     └─ tools/call
   │           ├─ unknown tool ────────────────────────────────► -32602
   │           ├─ arguments fail the published schema ─────────► -32602
   │           └─ handler, on a worker thread
   │                 ├─ sandbox refuses ───────────────► isError result
   │                 ├─ bound exceeded ────────────────► isError result
   │                 └─ success ──────────────────────► result
   │
   └─ render: scan → assemble → redact once → attach the redaction report
```

The last line is the one that was wrong first. See ADR-007.

---

## Decision records

### ADR-001 — The protocol layer is written against the specification, not an SDK

**Context.** An SDK exists. Using it would have removed roughly 600 lines.

**Decision.** Implement JSON-RPC framing, `_meta` negotiation, dispatch,
pagination and result construction directly.

**Why.** The specification's conformance requirements *are* the subject here.
An SDK would own exactly the code the conformance suite needs to exercise, and
the interesting question — "does this server emit `resultType` on every result,
and would anything notice if it stopped?" — would become a question about
somebody else's library. It also keeps the dependency set to five packages,
which is small enough that an operator can audit what they are running as their
own user.

**Cost.** Protocol changes are this repository's problem. `protocol/spec.py`
exists to make that a one-file diff.

### ADR-002 — Modern-only: no legacy `initialize` era

**Context.** Revisions up to 2025-11-25 used a stateful `initialize` handshake.
Serving both would let older clients connect.

**Decision.** Serve 2026-07-28 only. Answer `initialize` with `-32022` naming
the supported revisions.

**Why.** Two eras means two dispatch paths, two capability models, two session
lifetimes and two test suites — in a project whose subject is the sandbox, not
protocol archaeology. The specification's own compatibility guidance is that a
modern-only server should name what it supports in the error it returns, which
is ten lines and one test. A client that receives the version list can act on it
in one round trip.

**Cost.** Clients pinned to an older revision cannot connect. They get a precise
reason rather than a timeout.

### ADR-003 — Resolve, then contain; deny by resolved path

**Context.** Path containment is the whole boundary, and the two obvious
implementations are both wrong (see `sandbox/workspace.py`).

**Decision.** `Path.resolve()` the candidate against the real filesystem —
following every symlink — then compare the resolved path's normalised parts
against the resolved root's. Match the denylist against the *resolved* relative
path, not the requested string.

**Why.** The check then runs on the same object the subsequent `open` reaches.
Everything else is checking a different path than the one that gets used.

**Cost.** A `stat` per resolution, and containment re-checked during a walk. Both
are cheap next to the read that follows.

### ADR-004 — Denials are results, protocol errors are for malformed requests

**Context.** The specification defines two failure mechanisms and conflating
them is the commonest way an MCP server misbehaves.

**Decision.** If the caller could not have known better — unknown method,
unknown tool, arguments that fail a published schema — it is a JSON-RPC error.
If the caller asked a reasonable question and the answer is "no, and here is
why", it is a result with `isError: true` and a `remedy` field.

**Why.** A sandbox denial delivered as a transport failure is invisible to the
model that needs to learn from it, and the client logs an exception instead. The
`remedy` field is part of the type rather than optional prose because a denial
that does not say what would have worked teaches nothing, and the model tries
the same call again.

### ADR-005 — A subset JSON Schema validator instead of a dependency

**Context.** The specification requires servers to validate tool inputs.

**Decision.** Implement the Draft 2020-12 subset the published schemas use, and
**reject any schema that uses a keyword the validator does not implement** at
registration time.

**Why.** A full implementation adds a package whose surface is far larger than
what is used, and the interesting failure — a tool accepting an argument it
should have refused — is best pinned against a validator small enough to read.
The registration-time rejection is what makes the subset safe: an unsupported
keyword cannot become a constraint that silently is not enforced.

It also lets the `$ref` rule be absolute. The specification says `$ref` must not
dereference network URIs; here nothing but local `#/$defs` pointers resolves at
all, and depth is capped on both the schema and the instance.

### ADR-006 — Untrusted content is *marked*, never rewritten

**Context.** A previous project in this series neutralises injected instructions
in retrieved documents. That is the right call there and the wrong call here.

**Decision.** Return file content byte-identical to disk. Carry the warning in
the frame: a per-response nonce fence, a risk score, and the signals that fired,
in `structuredContent`.

**Why.** In a retrieval system, injected text is noise — nobody asked to see
that document verbatim, so scrambling it costs the user nothing. Here the user
asked to read a specific file. Rewriting it would mean the developer is shown a
version of their own source that does not exist, a model asked to fix a bug
reasons about text the compiler will never see, and — worst — *finding* injected
content in a repository, a real security task this server should be good at,
returns nothing because the tool destroyed the evidence on the way out.

The nonce matters. A fixed delimiter can be closed by the content; an
unpredictable one cannot.

**Cost.** Protection now depends on the client honouring the marking. That is
where the specification puts trust decisions, and `THREAT-MODEL.md` records it
as residual risk rather than pretending otherwise.

### ADR-007 — Assemble first, redact once, over the finished structure

**Context.** Redaction was added to the prose. Then a test showed the structured
half — a search match's `text`, a symbol's `signature` — carried credentials the
prose no longer did. That was fixed by redacting the structured input too. Then
the advisor pointed out that the scanner's *excerpt*, derived from the raw
content and attached after that pass, carried them again: `INJ08` matches from
`curl` through `| sh`, so a URL credential in such a line lands inside a 120-character
excerpt in `structuredContent`.

**Decision.** Build every content block and the whole structured object first,
then run one redaction pass over the assembled result, then attach the redaction
report (which names rules, never values).

**Why.** Redacting an input and then attaching something derived from the
un-redacted original leaves a credential in the result even though the pass
"ran". Ordering it this way closes the hole for anything added in future rather
than for the two members that leaked so far. `tests/unit` pins the excerpt case
directly, and `tests/security` asserts against the whole serialised envelope.

**Cost.** The scan still runs on raw content — deliberately, because scanning
redacted text would miss an injected instruction sitting next to a credential.
That asymmetry is the reason the ordering has to be explicit.

### ADR-008 — Catastrophic regular expressions are refused before compilation

**Context.** `search_code` takes a caller-supplied regular expression. The first
version of that module claimed the wall-clock budget bounded it. A test proved
otherwise: `(a+)+b` against forty characters is one `re.search` call that never
returns, and a budget checked around it is never reached.

**Decision.** A static guard, `tools/redos.py`, refuses quantified groups that
contain a quantifier and quantified groups whose alternatives can begin with the
same character. Applied before `re.compile`.

**Why.** It cannot be fixed downstream. `asyncio.wait_for` around
`asyncio.to_thread` abandons the coroutine but cannot stop the thread, and Python
offers no way to interrupt a running match — so the thread keeps a core busy for
the life of the process. On the developer's own laptop that is the whole machine
getting slower with no explanation.

**Cost.** It is a heuristic, not a decision procedure; that is undecidable in
general. The negative half of its test suite is as large as the positive half,
because a guard that refuses `(foo|bar)+` makes the tool useless and a developer
who is refused a legitimate pattern stops using it rather than rewriting it.

---

## Things that are deliberately absent

**No shell tool.** A general-purpose command tool hands the model every
privilege the process has, and no sandbox above it can constrain what the
command does.

**No test runner.** Running a project's tests means executing that project's
code, which path containment cannot constrain. A hole there would make every
other claim in this document unclaimable.

**No write, move or delete.** The server never opens a file for writing. A
confused or compromised client cannot damage the workspace through it — a
property of the code, not of a permission prompt.

**No `resources` or `prompts` capability.** More protocol surface, no more of
the thing this project is about.

**No outbound network requests from any tool.** The one subprocess is `git`,
with `protocol.ext.allow=never` and two subcommands that do not contact a
remote. The package does contain one HTTP client — `conformance/client.py`, used
by the operator-invoked `conform --http` command — which no MCP client can
reach.

## Concurrency

Handlers are synchronous, because filesystem work is synchronous and an
`async def` that never awaits would put blocking I/O on the event loop. The
dispatcher runs each on a worker thread, bounded at eight concurrent requests on
stdio, with an outer timeout above each handler's own deadline check.

Because the server is stateless, concurrent handling cannot change any answer.
That is not a hope: `tests/conformance` interleaves unrelated requests on one
connection and asserts the results are identical to running them alone.
