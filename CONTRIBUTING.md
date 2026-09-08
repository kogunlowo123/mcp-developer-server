# Contributing

Thanks for taking the time to contribute. This document describes the local
workflow, the quality bar enforced in CI, and how changes are reviewed.

## Prerequisites

- Python 3.12 (the project pins `>=3.12,<3.13`)
- [uv](https://docs.astral.sh/uv/) 0.10 or newer
- Docker (optional, only needed for container work)

`make` is convenient on Linux and macOS but is not required. `python tasks.py`
is the cross-platform entry point and the source of truth; the `Makefile`
simply delegates to it.

## Getting set up

```bash
uv sync --all-extras --dev     # or: python tasks.py setup
cp .env.example .env
```

Never commit a populated `.env`. `.gitignore` excludes it and CI runs a secret
scan over both the working tree and the full git history.

## Development loop

| Task | Command |
| --- | --- |
| Format | `python tasks.py fmt` |
| Lint | `python tasks.py lint` |
| Type check | `python tasks.py typecheck` |
| Unit tests | `python tasks.py test-unit` |
| Integration tests | `python tasks.py test-integration` |
| Security tests | `python tasks.py test-security` |
| Conformance tests | `python tasks.py test-conformance` |
| Full suite + coverage gate | `python tasks.py test` |
| Protocol conformance gate | `python tasks.py conform` |
| The same, over a real process | `python tasks.py conform-stdio` |
| What this configuration serves | `python tasks.py doctor` |
| Local security scans | `python tasks.py security` |
| Documentation site | `python tasks.py site` |
| Container image + smoke test | `python tasks.py smoke` |

Run `python tasks.py --list` for the full list.

## Quality bar

A change is mergeable when all of the following hold:

1. `ruff check` and `ruff format --check` are clean.
2. `mypy --strict` reports no errors.
3. The full test suite passes and line coverage is at least **88%**.
4. `mcp-devserver conform --strict` exits zero, in-process **and** over stdio.
   A protocol regression is a build failure, not a note in a review.
5. `bandit` and `pip-audit` report no unresolved findings. If a dependency
   vulnerability has no upstream fix, add a justified, dated entry to
   `security/audit-exceptions.md` and the identifier to
   `security/audit-ignores.txt`.
6. No secret scanner finding, in the tree or in history.
7. Every example still runs. They are documentation that executes; one that
   stops working is a README that lies.
8. The documentation site builds. The builder fails on a broken internal link,
   so a renamed file fails the pull request rather than the deployment.

## Tests

Tests are grouped by pytest marker so each layer can run independently:

- `unit` — pure logic, no I/O and no network.
- `integration` — component wiring against a real temporary workspace and both
  transports.
- `security` — adversarial cases. **A failure here is a security regression**,
  not a bug.
- `e2e` — a real server process driven over a real pipe.
- `conformance` — the protocol suite, including its negative controls.

New behaviour needs a test at the lowest layer that can express it. Tests that
assert nothing meaningful (`assert True`, calls with no assertions) are rejected
in review.

### Two rules specific to this repository

**A security control is tested through the server, not against its helper.**
The interesting failure is a control that exists and is not wired up — which has
happened twice here, both times with redaction. Assert against the whole
serialised result, not one member of it.

**A change to the conformance suite needs a negative control.** Adding a check
means adding a mutation in `tests/conformance/` that breaks the requirement and
asserts the new check goes red. A check that has only ever seen a correct server
proves nothing about whether it would notice an incorrect one.

### Fixtures with credential-shaped strings

Build them by concatenation — `"AKIA" + "IOSFODNN7EXAMPLE"` — so a scanner
reading this repository does not report a fixture as a finding, and so a reader
can see at a glance that nothing was ever valid. Add the file to the path
allowlist in `.gitleaks.toml` with a written reason.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `docs:`, `refactor:`, `test:`, `build:`, `ci:`, `chore:`.
- Keep the subject line under 72 characters and use the imperative mood.
- One logical change per pull request.
- Describe the behaviour change, the risk, and how you verified it.
- Update `CHANGELOG.md` under `## [Unreleased]` for anything user-visible.

## Changing the protocol revision

`src/mcp_devserver/protocol/spec.py` is a transcription of the specification and
nothing else. Work in this order:

1. Update the constants in `spec.py`.
2. Run `mcp-devserver conform --strict`. The failures name the requirements that
   moved.
3. Add or amend checks in `conformance/checks.py`, with a negative control for
   each.
4. Only then change handlers.

Doing it the other way round means the handlers decide what the specification
says.

## Reporting security issues

Do not open a public issue for a vulnerability. Follow the process in
[SECURITY.md](SECURITY.md).
