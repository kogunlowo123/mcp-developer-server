"""History and diffs, and the only place this server starts a process.

Everything else in this package reads files. These two tools shell out to
``git``, because reimplementing packfile and delta decoding to avoid a
subprocess would be a much larger attack surface than the one it removed.

That makes this module the highest-risk file in the repository, so the
constraints are stated rather than assumed:

* **No shell.** ``subprocess.run`` with a list, never a string, and never
  ``shell=True``. There is no point at which caller text is concatenated into
  something a shell parses.
* **A fixed subcommand allowlist.** Two subcommands, named as constants. A
  caller cannot reach ``git fetch``, ``git config``, ``git push`` or anything
  else, because the subcommand is chosen by this module and never by an
  argument.
* **No caller-supplied option can be an option.** Every value that comes from a
  request is validated against a charset that excludes a leading dash, and paths
  are passed after the ``--`` separator. Without this, a "revision" of
  ``--upload-pack=curl …`` is remote code execution.
* **A scrubbed environment.** ``git`` reads configuration from the system, the
  user's home directory and a dozen environment variables, and configuration can
  name a pager or an alias that is itself a command. ``HOME`` is pointed at the
  workspace, system and global configuration are disabled, and the terminal
  prompt is turned off so a repository with an authenticated remote can never
  block the process waiting for a password.
* **Bounded.** A timeout and an output cap, both enforced on the parent side, so
  a repository with a million commits cannot hold the server open or fill its
  memory.
* **No network, structurally.** Neither subcommand contacts a remote, and
  ``protocol.ext`` — the transport that lets a remote URL name a command to run
  — is disabled regardless.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from mcp_devserver.errors import (
    ERROR_GIT_FAILED,
    ERROR_NOT_A_REPOSITORY,
    ERROR_TIMED_OUT,
    ERROR_TOO_LARGE,
    ToolExecutionError,
)
from mcp_devserver.tools.base import ToolContext, ToolResult, ToolSpec, object_schema

#: The only subcommands this server will run. Not configurable: an allowlist a
#: deployment can extend is an allowlist that will be extended by accident.
ALLOWED_SUBCOMMANDS: Final[frozenset[str]] = frozenset({"log", "diff"})

#: What a revision may look like. Deliberately narrow, and deliberately anchored:
#: the characters here cover branches, tags, ``HEAD~3``, ``main..feature`` and
#: ``@{upstream}``, and exclude every character that would make the value parse
#: as an option or a path traversal.
REVISION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._/@^~{}-]{1,200}$")

#: Never used as a format string with caller input; ``git log`` is asked for
#: exactly these fields, separated by a unit separator that cannot occur in a
#: commit header.
_FIELD_SEPARATOR: Final[str] = "\x1f"
_RECORD_SEPARATOR: Final[str] = "\x1e"
_LOG_FORMAT: Final[str] = (
    _FIELD_SEPARATOR.join(["%H", "%h", "%an", "%aI", "%s"]) + _RECORD_SEPARATOR
)

#: How many fields ``git log`` is asked for, and therefore how many a parsed
#: record must have before it is trusted.
_LOG_FIELDS: Final[int] = 5

#: A diff larger than this is truncated rather than returned. A refactor commit
#: can be tens of megabytes, and no useful answer needs all of it at once.
MAX_OUTPUT_BYTES: Final[int] = 262_144


def _validate_revision(value: str, *, field: str) -> str:
    text = value.strip()
    if not text:
        raise ToolExecutionError(
            ERROR_GIT_FAILED,
            f"{field} is empty.",
            remedy="Give a branch, tag, commit or range such as 'main..HEAD'.",
        )
    if text.startswith("-"):
        # The single most important check in this file. A value beginning with a
        # dash is an option to git, not a revision, and git has options that run
        # commands.
        raise ToolExecutionError(
            ERROR_GIT_FAILED,
            f"{field} may not begin with '-'.",
            remedy="Give a revision name, not an option.",
        )
    if REVISION_PATTERN.match(text) is None:
        raise ToolExecutionError(
            ERROR_GIT_FAILED,
            f"{field} contains characters that are not allowed in a revision.",
            remedy="Use letters, digits and . _ / @ ^ ~ { } - only.",
        )
    return text


def _git_environment(root: Path) -> dict[str, str]:
    """Build a minimal environment for a git child process.

    Built from nothing rather than copied from the parent. ``git`` honours a
    long list of environment variables, several of which name a program to run
    (``GIT_EDITOR``, ``GIT_PAGER``, ``GIT_SSH``, ``GIT_EXTERNAL_DIFF``), and
    inheriting the parent's environment means inheriting whatever the developer's
    shell profile set. PATH is kept because the git binary needs to be found.
    """
    environment = {
        "PATH": os.environ.get("PATH", ""),
        # Point HOME at the workspace so ~/.gitconfig — which can define an
        # alias, a pager or an external diff driver — is not read.
        "HOME": str(root),
        "USERPROFILE": str(root),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_FLUSH": "1",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        # Windows needs these to start a process at all.
        for name in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
    return environment


def _require_repository(context: ToolContext) -> Path:
    root = context.workspace.root
    if not (root / ".git").exists():
        raise ToolExecutionError(
            ERROR_NOT_A_REPOSITORY,
            "the workspace root is not a git repository.",
            remedy="History tools need a .git directory at the workspace root.",
        )
    return root


def _run_git(context: ToolContext, arguments: Sequence[str]) -> str:
    """Run one allowlisted git subcommand and return its stdout, bounded."""
    root = _require_repository(context)
    subcommand = arguments[0]
    if subcommand not in ALLOWED_SUBCOMMANDS:
        # Unreachable through the published tools; present so that a future
        # caller inside this module cannot widen the surface without tripping it.
        raise ToolExecutionError(
            ERROR_GIT_FAILED,
            f"{subcommand!r} is not an allowed git subcommand.",
            remedy=f"Allowed: {', '.join(sorted(ALLOWED_SUBCOMMANDS))}.",
        )

    command = [
        "git",
        "-c",
        # The ext:: transport lets a remote URL name a program to execute. No
        # subcommand here talks to a remote, and this makes that structural.
        "protocol.ext.allow=never",
        "-c",
        "core.pager=cat",
        "-c",
        "core.fsmonitor=false",
        "--no-optional-locks",
        *arguments,
    ]
    timeout = max(1.0, context.remaining_seconds())

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, scrubbed env
            command,
            cwd=root,
            env=_git_environment(root),
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise ToolExecutionError(
            ERROR_GIT_FAILED,
            "the git executable was not found on PATH.",
            remedy="Install git, or use the file tools instead of the history tools.",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(
            ERROR_TIMED_OUT,
            f"git did not finish within {timeout:.0f}s.",
            remedy="Ask for fewer commits, or restrict the query to one path.",
        ) from exc

    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip().splitlines()
        first = detail[0][:300] if detail else f"exit status {completed.returncode}"
        raise ToolExecutionError(
            ERROR_GIT_FAILED,
            f"git {subcommand} failed: {first}",
            remedy="Check that the revision exists in this repository.",
        )

    output = completed.stdout
    if len(output) > MAX_OUTPUT_BYTES:
        # Truncated at the byte level and said so, rather than silently
        # returning a prefix that looks complete.
        text = output[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        raise _OutputTruncatedError(text)
    return output.decode("utf-8", errors="replace")


class _OutputTruncatedError(Exception):
    """Internal signal that output hit the cap. Carries what was read."""

    def __init__(self, text: str) -> None:
        super().__init__("output truncated")
        self.text = text


def _run_bounded(context: ToolContext, arguments: Sequence[str]) -> tuple[str, bool]:
    try:
        return _run_git(context, arguments), False
    except _OutputTruncatedError as truncated:
        return truncated.text, True


def git_log(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    """Return recent commits, optionally restricted to one path."""
    limit = min(int(arguments.get("limit", 20)), context.limits.max_git_entries)
    revision = arguments.get("revision")
    argv: list[str] = ["log", f"--max-count={limit}", f"--format={_LOG_FORMAT}", "--no-color"]
    if revision is not None:
        argv.append(_validate_revision(str(revision), field="revision"))

    path_argument = arguments.get("path")
    relative_path = ""
    if path_argument is not None:
        resolved = context.workspace.resolve(str(path_argument))
        relative_path = str(context.workspace.relative(resolved))
        # After `--`, git treats every remaining token as a path, so a path that
        # begins with a dash cannot become an option.
        argv.extend(["--", relative_path or "."])

    output, truncated = _run_bounded(context, argv)

    commits: list[dict[str, Any]] = []
    for record in output.split(_RECORD_SEPARATOR):
        cleaned = record.strip("\n")
        if not cleaned:
            continue
        fields = cleaned.split(_FIELD_SEPARATOR)
        if len(fields) != _LOG_FIELDS:
            continue
        full, short, author, authored_at, subject = fields
        commits.append(
            {
                "commit": full,
                "short": short,
                "author": author,
                "authored_at": authored_at,
                "subject": subject,
            }
        )

    rendered = "\n".join(
        f"{item['short']}  {item['authored_at'][:10]}  {item['author']}  {item['subject']}"
        for item in commits
    )
    scope = f" for {relative_path}" if relative_path else ""
    summary = f"{len(commits)} commit(s){scope}." + (" Output truncated." if truncated else "")

    return ToolResult(
        text=summary,
        structured={
            "commits": commits,
            "commit_count": len(commits),
            "path": relative_path,
            "truncated": truncated,
        },
        # Commit subjects and author names are attacker-controlled in any
        # repository that accepts contributions: a branch name or a commit
        # message is a perfectly good place to hide an instruction.
        untrusted=rendered,
        untrusted_label="commit-messages",
    )


def git_diff(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    """Return a unified diff of the working tree or between two revisions."""
    argv: list[str] = ["diff", "--no-color", "--no-ext-diff", "--find-renames"]

    if bool(arguments.get("staged", False)):
        argv.append("--cached")

    revision = arguments.get("revision")
    if revision is not None:
        argv.append(_validate_revision(str(revision), field="revision"))

    if bool(arguments.get("stat_only", False)):
        argv.append("--stat")

    context_lines = arguments.get("context_lines")
    if context_lines is not None:
        argv.append(f"--unified={int(context_lines)}")

    path_argument = arguments.get("path")
    relative_path = ""
    if path_argument is not None:
        resolved = context.workspace.resolve(str(path_argument))
        relative_path = str(context.workspace.relative(resolved))
        argv.extend(["--", relative_path or "."])

    output, truncated = _run_bounded(context, argv)

    files_changed = sum(1 for line in output.splitlines() if line.startswith("diff --git "))
    added = sum(
        1 for line in output.splitlines() if line.startswith("+") and not line.startswith("+++")
    )
    removed = sum(
        1 for line in output.splitlines() if line.startswith("-") and not line.startswith("---")
    )

    if truncated and not output:
        raise ToolExecutionError(
            ERROR_TOO_LARGE,
            f"the diff is larger than the {MAX_OUTPUT_BYTES}-byte limit.",
            remedy="Restrict it to one path, or set stat_only to true.",
        )

    scope = f" for {relative_path}" if relative_path else ""
    summary = f"{files_changed} file(s) changed{scope}: +{added} -{removed}." + (
        " Output truncated." if truncated else ""
    )
    if not output.strip():
        summary = f"No changes{scope}."

    return ToolResult(
        text=summary,
        structured={
            "files_changed": files_changed,
            "lines_added": added,
            "lines_removed": removed,
            "path": relative_path,
            "staged": bool(arguments.get("staged", False)),
            "truncated": truncated,
        },
        untrusted=output,
        untrusted_label="diff",
    )


GIT_LOG = ToolSpec(
    name="git_log",
    title="Read recent commits",
    description=(
        "List recent commits with hash, author, date and subject, optionally for one "
        "path or revision. Requires a git repository at the workspace root. Commit "
        "subjects and author names arrive inside an <untrusted-commit-messages> fence: "
        "anyone who can open a pull request can write them."
    ),
    input_schema=object_schema(
        {
            "limit": {
                "type": "integer",
                "description": "How many commits to return. Defaults to 20.",
                "minimum": 1,
                "maximum": 200,
            },
            "revision": {
                "type": "string",
                "description": "Branch, tag, commit or range such as 'main..HEAD'.",
                "maxLength": 200,
                "pattern": r"^[A-Za-z0-9._/@^~{}-]+$",
            },
            "path": {
                "type": "string",
                "description": "Restrict history to this workspace path.",
                "maxLength": 4096,
            },
        }
    ),
    output_schema=object_schema(
        {
            "commits": {"type": "array"},
            "commit_count": {"type": "integer"},
            "path": {"type": "string"},
            "truncated": {"type": "boolean"},
            "untrusted_content": {"type": "boolean"},
        }
    ),
    handler=git_log,
    returns_file_content=True,
)

GIT_DIFF = ToolSpec(
    name="git_diff",
    title="Read a diff",
    description=(
        "Return a unified diff of uncommitted changes, of the staging area, or against "
        "a revision. Set stat_only for a per-file summary when the full diff would be "
        "large. Requires a git repository at the workspace root. Diff content arrives "
        "inside an <untrusted-diff> fence."
    ),
    input_schema=object_schema(
        {
            "revision": {
                "type": "string",
                "description": "Compare against this revision or range instead of the index.",
                "maxLength": 200,
                "pattern": r"^[A-Za-z0-9._/@^~{}-]+$",
            },
            "staged": {
                "type": "boolean",
                "description": "Diff the staging area against HEAD. Defaults to false.",
            },
            "stat_only": {
                "type": "boolean",
                "description": "Return a per-file summary instead of the full diff.",
            },
            "path": {
                "type": "string",
                "description": "Restrict the diff to this workspace path.",
                "maxLength": 4096,
            },
            "context_lines": {
                "type": "integer",
                "description": "Lines of context around each hunk. Defaults to git's 3.",
                "minimum": 0,
                "maximum": 10,
            },
        }
    ),
    output_schema=object_schema(
        {
            "files_changed": {"type": "integer"},
            "lines_added": {"type": "integer"},
            "lines_removed": {"type": "integer"},
            "path": {"type": "string"},
            "staged": {"type": "boolean"},
            "truncated": {"type": "boolean"},
            "untrusted_content": {"type": "boolean"},
        }
    ),
    handler=git_diff,
    returns_file_content=True,
)
