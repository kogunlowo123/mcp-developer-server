"""What may never be read, regardless of how it is asked for.

Two properties make this list worth having rather than decorative:

**It is matched against the resolved path, not the requested one.** A request
for ``docs/../.env`` and a request for ``.env`` are the same request by the time
this module sees it, and a symlink named ``notes.txt`` that points at ``~/.ssh/id_ed25519``
has already been resolved to its target. Matching on the string a caller typed is
the classic way a denylist is bypassed.

**It is additive only.** Configuration can extend it. Nothing can shorten it.
A server whose denylist can be emptied by an environment variable has a denylist
in the same sense that a door with the key taped to it has a lock.

The list is not the security boundary — containment is. This is the second
layer, for the case where a file is legitimately inside the workspace and still
must not be handed to a model: a checked-in ``.env``, a test fixture private key,
a ``.git/config`` carrying a token in a remote URL.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

#: Exact file names, matched case-insensitively against any component of the
#: path. Case-insensitive because a denylist that lets ``.ENV`` through on a
#: case-insensitive filesystem is not a denylist.
DENIED_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".env",
        ".envrc",
        ".netrc",
        "_netrc",
        ".pgpass",
        ".htpasswd",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "service-account.json",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "known_hosts",
        "secring.gpg",
        "shadow",
    }
)

#: Glob patterns matched case-insensitively against any single component.
DENIED_NAME_PATTERNS: Final[tuple[str, ...]] = (
    ".env.*",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "*.ppk",
    "*.asc",
    "*_rsa",
    "*_ed25519",
    "*.tfstate",
    "*.tfstate.backup",
)

#: Directory names whose entire subtree is refused. ``.git`` is here because the
#: git tools reach history through the ``git`` binary with a fixed argument
#: vector; nothing needs raw access to the object store, and ``.git/config``
#: routinely contains a credential-bearing remote URL.
DENIED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".ssh",
        ".aws",
        ".azure",
        ".gnupg",
        ".kube",
        ".docker",
        ".config/gcloud",
        "node_modules/.cache",
    }
)

#: Directories that are skipped when walking, but are not *refused* — asking for
#: a specific file inside one is allowed. These are large, generated, or vendored
#: trees whose contents would swamp a search without informing it.
SKIPPED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".terraform",
        ".gradle",
        ".idea",
        ".vscode",
        "site-packages",
        "htmlcov",
        ".coverage",
    }
)


@dataclass(frozen=True, slots=True)
class Denylist:
    """The names and patterns a workspace refuses.

    Built once at start-up. ``extra`` is whatever configuration added; the
    built-in sets are always applied regardless of what it contains.
    """

    extra_names: frozenset[str] = frozenset()
    extra_patterns: tuple[str, ...] = ()

    @classmethod
    def with_extra(cls, entries: Iterable[str]) -> Denylist:
        """Extend the built-in list.

        An entry containing a glob metacharacter becomes a pattern; anything
        else becomes an exact name. Splitting here rather than asking the
        operator to declare which is which removes a class of configuration
        mistake in which a pattern is registered as a literal and silently
        matches nothing.
        """
        names: set[str] = set()
        patterns: list[str] = []
        for raw in entries:
            entry = raw.strip().lower()
            if not entry:
                continue
            if any(character in entry for character in "*?["):
                patterns.append(entry)
            else:
                names.add(entry)
        return cls(extra_names=frozenset(names), extra_patterns=tuple(patterns))

    @property
    def names(self) -> frozenset[str]:
        """Every exact name refused, built-in and configured."""
        return DENIED_NAMES | self.extra_names

    @property
    def patterns(self) -> tuple[str, ...]:
        """Every glob refused, built-in and configured."""
        return DENIED_NAME_PATTERNS + self.extra_patterns

    def reason(self, relative: PurePosixPath) -> str:
        """Return why a workspace-relative path is refused, or ``""`` if it is not.

        The path must already be resolved and relative to the workspace root.
        Every component is examined, not only the last: a request for
        ``.ssh/config`` is refused by its directory even though ``config`` is
        not itself a denied name.
        """
        parts = [part.lower() for part in relative.parts]

        for index, part in enumerate(parts):
            if part in DENIED_DIRECTORIES and index < len(parts) - 1:
                return f"{part!r} is a directory this server never reads from"
            # A denied directory named as the target itself is refused too;
            # listing `.git` is not more acceptable than reading inside it.
            if part in DENIED_DIRECTORIES:
                return f"{part!r} is a directory this server never reads from"

        # Multi-segment directory rules such as `.config/gcloud`.
        joined = "/".join(parts)
        for denied in DENIED_DIRECTORIES:
            if "/" in denied and (joined == denied or joined.startswith(denied + "/")):
                return f"{denied!r} is a directory this server never reads from"

        names = self.names
        patterns = self.patterns
        for part in parts:
            if part in names:
                return f"{part!r} is on the list of files this server never reads"
            for pattern in patterns:
                if fnmatch.fnmatchcase(part, pattern):
                    return f"{part!r} matches {pattern!r}, which this server never reads"
        return ""

    def refuses(self, relative: PurePosixPath) -> bool:
        """Whether the path is refused."""
        return bool(self.reason(relative))


def should_skip_directory(name: str) -> bool:
    """Whether a directory is skipped when walking a tree."""
    return name in SKIPPED_DIRECTORIES
