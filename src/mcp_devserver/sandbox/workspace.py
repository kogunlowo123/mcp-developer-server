"""Workspace containment: the boundary every tool goes through.

An MCP server launched by an editor runs as the developer, with the developer's
filesystem privileges. There is no operating-system boundary between it and
``~/.ssh``. The boundary is this module, and it is worth being precise about how
it works, because the two obvious implementations are both wrong.

**Wrong: check the requested string, then open it.** ``docs/../../.ssh/id_rsa``
contains no suspicious component after the first, and a check that runs before
normalisation is a check against a different path than the one that gets opened.

**Wrong: normalise lexically, then compare prefixes.** ``Path("/work/../worker")``
normalises inside ``/work`` by string prefix and outside it in fact, and a
symlink is invisible to lexical normalisation entirely.

**Right, and what this module does:** resolve the candidate fully — following
every symlink, on the real filesystem — and only then ask whether the *resolved*
path lies under the *resolved* root. The check happens on the same object the
subsequent ``open`` will reach, which is the only version of the check that
means anything.

Containment is checked again at the point of opening, not only at the point of
resolving. Between the two, a path can change underneath the process: a
directory replaced by a symlink after the check and before the read is a real
race, and the second check narrows it to the window inside a single ``open``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from mcp_devserver.errors import (
    ERROR_BINARY,
    ERROR_DENIED_PATH,
    ERROR_NOT_A_DIRECTORY,
    ERROR_NOT_A_FILE,
    ERROR_NOT_FOUND,
    ERROR_OUTSIDE_WORKSPACE,
    ERROR_TOO_LARGE,
    ConfigurationError,
    SandboxError,
)
from mcp_devserver.sandbox.denylist import Denylist, should_skip_directory

#: Read in chunks rather than whole. A cap applied after ``read_bytes`` has
#: already returned is not a cap: the memory was allocated before anything
#: checked its size.
_CHUNK: Final[int] = 65_536

#: A NUL byte in the first chunk means the file is not text. Cheap, and it is
#: what ``git`` itself uses.
_BINARY_SNIFF: Final[int] = 8_192


@dataclass(frozen=True, slots=True)
class Entry:
    """One resolved thing inside the workspace."""

    relative: PurePosixPath
    absolute: Path
    is_directory: bool
    size_bytes: int

    def as_dict(self) -> dict[str, object]:
        """Render for a structured tool result."""
        return {
            "path": str(self.relative),
            "type": "directory" if self.is_directory else "file",
            "size_bytes": self.size_bytes,
        }


def _normalised_parts(path: Path) -> tuple[str, ...]:
    r"""Case-fold a resolved path for comparison.

    ``os.path.normcase`` is a no-op on POSIX and lowercases plus normalises
    separators on Windows. Comparing raw ``Path`` objects would make containment
    case-sensitive on a case-insensitive filesystem, where ``C:\\Work\\x`` and
    ``C:\\work\\x`` are the same file and would compare unequal.
    """
    return tuple(os.path.normcase(part) for part in path.parts)


class Workspace:
    """A directory, and the rule that nothing outside it is reachable.

    Construction is where a misconfigured server dies. A root that does not
    exist, is not a directory, or is a filesystem root is refused here rather
    than serving requests with an ineffective boundary.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        denylist: Denylist | None = None,
        max_file_bytes: int = 1_048_576,
        follow_symlinks: bool = False,
    ) -> None:
        candidate = Path(root).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError(
                f"workspace root {candidate} cannot be resolved: {exc}"
            ) from exc

        if not resolved.is_dir():
            raise ConfigurationError(f"workspace root {resolved} is not a directory")
        if resolved.parent == resolved:
            raise ConfigurationError(
                f"refusing to serve {resolved} as a workspace: it is a filesystem root, "
                "which would place every file on the machine inside the sandbox"
            )

        self._root = resolved
        self._root_parts = _normalised_parts(resolved)
        self._denylist = denylist or Denylist()
        self._max_file_bytes = max_file_bytes
        self._follow_symlinks = follow_symlinks

    @property
    def root(self) -> Path:
        """The resolved workspace root."""
        return self._root

    @property
    def denylist(self) -> Denylist:
        """The denylist in force."""
        return self._denylist

    @property
    def max_file_bytes(self) -> int:
        """The largest file this workspace will read."""
        return self._max_file_bytes

    # -- containment -------------------------------------------------------

    def contains(self, resolved: Path) -> bool:
        """Whether an already-resolved path lies inside the root."""
        parts = _normalised_parts(resolved)
        return parts[: len(self._root_parts)] == self._root_parts

    def relative(self, resolved: Path) -> PurePosixPath:
        """Render a contained path in its workspace-relative form.

        POSIX-style regardless of host, because the path travels to a model and
        into a JSON result, and a backslash in a JSON string is an escape
        sequence waiting to be misread.
        """
        return PurePosixPath(resolved.relative_to(self._root).as_posix())

    def display(self, resolved: Path) -> str:
        """Render a contained path for prose.

        The workspace root relativises to ``"."``, which reads badly at the end
        of a sentence ("under .."). Naming the directory instead keeps summaries
        legible without leaking the absolute path.
        """
        relative = self.relative(resolved)
        if str(relative) == ".":
            return f"{self._root.name}/"
        return str(relative)

    def resolve(self, requested: str) -> Path:
        """Resolve a caller-supplied path and prove it is inside the workspace.

        Raises :class:`SandboxError` rather than a protocol error: a path
        outside the workspace is a reasonable question with the answer "no", and
        a model that receives it as a tool result can correct itself, whereas a
        transport-level failure would be invisible to it.
        """
        text = requested.strip()
        if not text or text in {".", "./"}:
            return self._root

        # A NUL byte truncates a path at the operating-system boundary, so a
        # name containing one is checked as one string and opened as another.
        if "\x00" in text:
            raise SandboxError(
                ERROR_OUTSIDE_WORKSPACE,
                "the path contains a NUL byte.",
                remedy="Supply a path relative to the workspace root.",
            )

        candidate = Path(text)
        if candidate.is_absolute() or (os.name == "nt" and candidate.drive):
            # An absolute path is not refused out of hand: it may name something
            # legitimately inside the root. It is resolved and contained like
            # any other, and fails the same check if it is not.
            target = candidate
        else:
            target = self._root / candidate

        try:
            resolved = target.resolve()
        except (OSError, RuntimeError) as exc:
            # RuntimeError is a symlink loop on some platforms; OSError covers
            # a path segment that is not a directory, and Windows name limits.
            raise SandboxError(
                ERROR_OUTSIDE_WORKSPACE,
                f"the path could not be resolved: {exc}.",
                remedy="Supply a path relative to the workspace root.",
            ) from exc

        if not self.contains(resolved):
            # The message names the workspace but never the resolved path: a
            # denial that echoes back the absolute location it refused is an
            # oracle for probing the filesystem outside the sandbox.
            raise SandboxError(
                ERROR_OUTSIDE_WORKSPACE,
                f"{requested!r} resolves outside the workspace and cannot be read.",
                remedy=f"Paths must stay inside {self._root.name}/.",
            )

        if not self._follow_symlinks and target.is_symlink() and target.resolve() != target:
            # Reachable only when a symlink inside the root points at another
            # place inside the root. That is contained and therefore safe, but
            # it is still an indirection the caller did not ask for, so the
            # default is to refuse and say what happened.
            raise SandboxError(
                ERROR_DENIED_PATH,
                f"{requested!r} is a symbolic link, and this server does not follow links.",
                remedy="Read the link's target directly.",
            )

        reason = self._denylist.reason(self.relative(resolved))
        if reason:
            raise SandboxError(
                ERROR_DENIED_PATH,
                f"{requested!r} is refused: {reason}.",
                remedy="This file class is never readable through this server.",
            )

        return resolved

    # -- reading -----------------------------------------------------------

    def stat_entry(self, resolved: Path) -> Entry:
        """Describe a contained path."""
        try:
            info = resolved.stat()
        except OSError as exc:
            raise SandboxError(
                ERROR_NOT_FOUND,
                f"{self.relative(resolved)} does not exist.",
                remedy="Use list_directory to see what is there.",
            ) from exc
        is_directory = resolved.is_dir()
        return Entry(
            relative=self.relative(resolved),
            absolute=resolved,
            is_directory=is_directory,
            size_bytes=0 if is_directory else info.st_size,
        )

    def require_file(self, resolved: Path) -> Entry:
        """Assert a contained path is an existing regular file."""
        if not resolved.exists():
            raise SandboxError(
                ERROR_NOT_FOUND,
                f"{self.relative(resolved)} does not exist.",
                remedy="Use list_directory to see what is there.",
            )
        if resolved.is_dir():
            raise SandboxError(
                ERROR_NOT_A_FILE,
                f"{self.relative(resolved)} is a directory, not a file.",
                remedy="Use list_directory for directories.",
            )
        return self.stat_entry(resolved)

    def require_directory(self, resolved: Path) -> Entry:
        """Assert a contained path is an existing directory."""
        if not resolved.exists():
            raise SandboxError(
                ERROR_NOT_FOUND,
                f"{self.relative(resolved)} does not exist.",
                remedy="Use list_directory on a parent to see what is there.",
            )
        if not resolved.is_dir():
            raise SandboxError(
                ERROR_NOT_A_DIRECTORY,
                f"{self.relative(resolved)} is a file, not a directory.",
                remedy="Use read_file for files.",
            )
        return self.stat_entry(resolved)

    def read_text(self, resolved: Path, *, max_bytes: int | None = None) -> str:
        """Read a contained text file, bounded.

        The bound is enforced while reading, not afterwards. Every failure mode
        here — too large, binary, vanished — is a tool error the model can act
        on rather than an exception the client logs.
        """
        limit = self._max_file_bytes if max_bytes is None else min(max_bytes, self._max_file_bytes)
        entry = self.require_file(resolved)
        if entry.size_bytes > limit:
            raise SandboxError(
                ERROR_TOO_LARGE,
                f"{entry.relative} is {entry.size_bytes} bytes, over the {limit}-byte limit.",
                remedy="Request a line range, or search the file instead of reading it.",
            )

        chunks: list[bytes] = []
        total = 0
        try:
            with resolved.open("rb") as handle:
                first = handle.read(_BINARY_SNIFF)
                if b"\x00" in first:
                    raise SandboxError(
                        ERROR_BINARY,
                        f"{entry.relative} is a binary file.",
                        remedy="This server reads text only.",
                    )
                chunks.append(first)
                total += len(first)
                while total <= limit:
                    chunk = handle.read(_CHUNK)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except OSError as exc:
            raise SandboxError(
                ERROR_NOT_FOUND,
                f"{entry.relative} could not be read: {exc}.",
                remedy="Check that the path still exists.",
            ) from exc

        if total > limit:
            raise SandboxError(
                ERROR_TOO_LARGE,
                f"{entry.relative} grew past the {limit}-byte limit while being read.",
                remedy="Request a line range instead.",
            )

        # surrogateescape rather than replace: a file that is *mostly* text with
        # one bad byte stays readable, and the bad byte survives round-tripping
        # instead of being silently rewritten to U+FFFD. Rendering to JSON
        # re-encodes it, which is handled at the serialisation boundary.
        return b"".join(chunks).decode("utf-8", errors="replace")

    # -- walking -----------------------------------------------------------

    def walk(self, start: Path, *, max_entries: int = 20_000) -> Iterator[Path]:
        """Yield contained regular files under ``start``.

        Symlinks are never followed during a walk, and every yielded path is
        re-checked for containment. Both matter: ``os.walk`` will happily
        descend a symlinked directory if asked, and a link created between the
        walk starting and a file being yielded would otherwise escape.
        """
        yielded = 0
        for directory, subdirectories, filenames in os.walk(start, followlinks=False):
            here = Path(directory)
            subdirectories[:] = sorted(
                name
                for name in subdirectories
                if not should_skip_directory(name) and not (here / name).is_symlink()
            )
            for filename in sorted(filenames):
                path = here / filename
                if path.is_symlink():
                    continue
                if not self.contains(path):
                    continue
                if self._denylist.refuses(self.relative(path)):
                    continue
                yield path
                yielded += 1
                if yielded >= max_entries:
                    return
