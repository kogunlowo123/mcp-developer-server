# Security policy

## Reporting a vulnerability

Report privately through GitHub's advisory workflow:
<https://github.com/kogunlowo123/mcp-developer-server/security/advisories/new>

Please do not open a public issue for a vulnerability.

Include what you have: the request or configuration that triggers it, what you
expected, what happened, and the version or commit. A proof of concept helps but
is not required.

**What to expect.** This is a portfolio project maintained by one person, not a
funded product, and it is fairer to say so than to publish a service-level
agreement nobody is on call for. Acknowledgement within a week is realistic. If
a report is valid it will be fixed and credited, and the fix will say what was
wrong rather than describing it as "hardening".

## Supported versions

The `main` branch. There is no backport policy for older tags.

## What this project protects, and what it does not

The threat model is in [THREAT-MODEL.md](THREAT-MODEL.md) and is the document to
read before deploying this anywhere. The short version:

**In scope.** Path traversal and symlink escape out of the workspace; reading
denied credential files; credentials in ordinary files reaching a model; prompt
injection through file content; command injection through the git tools;
resource exhaustion; unauthenticated access to the HTTP transport; information
disclosure through error messages.

**Out of scope.** An attacker who already has code execution as the developer —
they do not need this server. Vulnerabilities in `git` itself. Transport
security, which is the deployment's reverse proxy.

## The thing most worth understanding before you deploy this

**This server runs with your privileges and there is no boundary underneath it.**
An MCP server launched by an editor is a subprocess started by you, running as
you. Whatever it can read, it can hand to a language model, and from there to a
provider's logs and any transcript you share.

The sandbox in this repository is a Python function, not a container. It is
tested as though someone is attacking it — 131 security tests, including 74 path
traversal attempts across every tool that takes a path — and it is still a
Python function. Set `MCP_SANDBOX__WORKSPACE` to the narrowest directory that is
useful, and do not serve your home directory.

## Known residual risks

These are not oversights; they are stated because a security document that
claims complete coverage is one nobody should believe.

1. **Untrusted-content marking depends on the client.** File content is fenced
   and scored, and returned unchanged — deliberately, see ADR-006. Nothing here
   can make a client act on the marking. A client that ignores it gets no
   protection from this control.
2. **Injection detection is heuristic.** Ten signals tuned for source code, with
   a negative control so ordinary documentation is not flagged. Novel phrasing
   gets through.
3. **The ReDoS guard is heuristic.** Recognising every exponential regular
   expression is undecidable. Merely-slow patterns are bounded only by the
   wall-clock budget, and a single pathological match inside one file cannot be
   interrupted — Python offers no way to stop a running `re` match.
4. **Secret redaction recognises shapes, not entropy.** A high-entropy password
   in a variable called `x` is indistinguishable from a hash.
5. **A hard link inside the workspace pointing outside it** resolves to an
   ordinary file and is readable. Creating one needs the same privileges this
   server already has, so it is not a privilege gain — but it is a real gap in
   the containment claim.
6. **A check-to-open race on symbolic links.** The window is one `open` call.
   Closing it needs `openat` with `O_NOFOLLOW`, which is not portable to the
   Windows hosts this server has to run on.

## What this server does not do

- It does not write, move or delete anything. No tool opens a file for writing.
- It does not run a shell, or any program named by caller input.
- It does not execute the workspace's code. There is no test runner, and
  [ARCHITECTURE.md](ARCHITECTURE.md) explains why adding one would undermine
  everything else.
- No tool makes an outbound network request. The one subprocess is `git`, with
  `protocol.ext.allow=never` and two subcommands that do not contact a remote.

The package does contain one HTTP client: `conformance/client.py`, used by the
operator-invoked `mcp-devserver conform --http` command to check a server you
point it at. It is not reachable from any MCP request.

## Credentials in this repository

There are none, and there never were. The credential-shaped strings in the tests
and examples are constructed by concatenation — `"AKIA" + "IOSFODNN7EXAMPLE"` —
so that a scanner reading this repository does not report a fixture as a finding,
and so a human can see at a glance that nothing here was ever valid.

CI enforces this: gitleaks runs over the working tree **and the full git
history** on every push, and the build fails on a finding.

## Verifying the security claims yourself

```bash
uv run pytest -m security          # 131 adversarial tests
uv run bandit -c pyproject.toml -r src
uv run python tasks.py security    # bandit + pip-audit against the locked set
python examples/sandbox_demo.py    # eight escape attempts, and what each was told
python examples/untrusted_demo.py  # a poisoned file, marked and returned intact
```
