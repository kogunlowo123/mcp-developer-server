"""A first look at an unfamiliar repository.

This exists because of what a coding agent does when it is dropped into a
codebase it has never seen: it issues six or seven exploratory calls to work out
what the project is, what language it is in, where the tests live and how it is
built. Every one of those calls is a round trip and a chunk of context.

One call answers all of it, from the filesystem, with no model involved: language
mix by file count and line count, the dependency manifests that exist and what
they declare, the likely entry points, where tests live, and whether the tree is
under version control. It is cheap because it is arithmetic over a directory
walk, and it is exact because nothing was inferred by a language model.

Manifest parsing is deliberately shallow: the name, version and direct
dependency *names* declared by each manifest, not a resolved dependency graph.
Resolving would mean reaching the network, and this server never does.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

from mcp_devserver.tools.base import ToolContext, ToolResult, ToolSpec, object_schema
from mcp_devserver.tools.symbols import language_of

#: Files that identify how a project is built and what it depends on.
MANIFESTS: Final[tuple[str, ...]] = (
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "CMakeLists.txt",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
)

#: Directory names that conventionally hold tests.
TEST_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {"tests", "test", "spec", "specs", "__tests__", "e2e", "integration"}
)

#: Files that are conventionally the way in.
ENTRY_POINTS: Final[tuple[str, ...]] = (
    "main.py",
    "__main__.py",
    "app.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "index.js",
    "index.ts",
    "main.go",
    "main.rs",
    "Main.java",
    "server.js",
    "cli.py",
)

_MAX_MANIFEST_BYTES: Final[int] = 262_144

#: A ``go.mod`` requirement line is ``<module path> <version>``; anything with
#: fewer tokens is not one.
_GO_REQUIREMENT_FIELDS: Final[int] = 2


def _read_manifest(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _summarise_pyproject(text: str) -> dict[str, Any]:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return {"parse_error": str(exc)}
    project = document.get("project", {})
    dependencies = project.get("dependencies", [])
    names = [re.split(r"[<>=!~\[; ]", str(item), maxsplit=1)[0] for item in dependencies]
    return {
        "name": project.get("name", ""),
        "version": project.get("version", ""),
        "requires_python": project.get("requires-python", ""),
        "dependencies": sorted(name for name in names if name),
    }


def _summarise_package_json(text: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"parse_error": str(exc)}
    if not isinstance(document, dict):
        return {"parse_error": "package.json is not an object"}
    dependencies = document.get("dependencies", {})
    scripts = document.get("scripts", {})
    return {
        "name": document.get("name", ""),
        "version": document.get("version", ""),
        "dependencies": sorted(dependencies) if isinstance(dependencies, dict) else [],
        "scripts": sorted(scripts) if isinstance(scripts, dict) else [],
    }


def _summarise_cargo(text: str) -> dict[str, Any]:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return {"parse_error": str(exc)}
    package = document.get("package", {})
    dependencies = document.get("dependencies", {})
    return {
        "name": package.get("name", ""),
        "version": package.get("version", ""),
        "dependencies": sorted(dependencies) if isinstance(dependencies, dict) else [],
    }


def _summarise_go_mod(text: str) -> dict[str, Any]:
    module = ""
    version = ""
    dependencies: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("module "):
            module = stripped.removeprefix("module ").strip()
        elif stripped.startswith("go "):
            version = stripped.removeprefix("go ").strip()
        elif stripped and not stripped.startswith(("require", "//", ")", "replace", "exclude")):
            parts = stripped.split()
            if len(parts) >= _GO_REQUIREMENT_FIELDS and "." in parts[0] and "/" in parts[0]:
                dependencies.append(parts[0])
    return {
        "name": module,
        "go_version": version,
        "dependencies": sorted(set(dependencies)),
    }


_SUMMARISERS: Final[dict[str, Any]] = {
    "pyproject.toml": _summarise_pyproject,
    "package.json": _summarise_package_json,
    "Cargo.toml": _summarise_cargo,
    "go.mod": _summarise_go_mod,
}


def _is_test_file(relative: PurePosixPath, path: Path) -> bool:
    """Report whether a file looks like a test, by directory or by name."""
    if any(part in TEST_DIRECTORIES for part in relative.parts[:-1]):
        return True
    return path.name.startswith("test_") or path.stem.endswith(("_test", ".test", ".spec"))


def _count_lines(path: Path, size: int) -> int:
    """Count the lines in a file small enough to read whole, else report zero."""
    if size > _MAX_MANIFEST_BYTES:
        return 0
    try:
        return path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
    except OSError:
        return 0


@dataclass(slots=True)
class _Survey:
    """Everything one walk of the tree measured."""

    total_files: int = 0
    total_bytes: int = 0
    test_files: int = 0
    timed_out: bool = False
    by_language: dict[str, dict[str, int]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    largest: list[tuple[int, str]] = field(default_factory=list)

    def languages(self) -> list[dict[str, Any]]:
        """Render per-language counts, busiest first."""
        return sorted(
            ({"language": language, **counts} for language, counts in self.by_language.items()),
            key=lambda item: (-int(item["files"]), str(item["language"])),
        )


def _survey(context: ToolContext, root: Path) -> _Survey:
    """Walk the tree once and measure it."""
    survey = _Survey()
    for path in context.workspace.walk(root, max_entries=context.limits.max_search_files):
        if context.deadline_exceeded():
            survey.timed_out = True
            break
        survey.total_files += 1
        try:
            size = path.stat().st_size
        except OSError:
            continue
        survey.total_bytes += size
        relative = context.workspace.relative(path)

        if _is_test_file(relative, path):
            survey.test_files += 1

        language = language_of(path)
        if not language:
            continue

        bucket = survey.by_language.setdefault(language, {"files": 0, "lines": 0, "bytes": 0})
        bucket["files"] += 1
        bucket["bytes"] += size
        bucket["lines"] += _count_lines(path, size)

        if path.name in ENTRY_POINTS:
            survey.entry_points.append(str(relative))
        survey.largest.append((size, str(relative)))

    survey.largest.sort(reverse=True)
    return survey


def _manifests(root: Path) -> list[dict[str, Any]]:
    """Find the dependency manifests present and summarise the ones understood."""
    found: list[dict[str, Any]] = []
    for name in MANIFESTS:
        candidate = root / name
        if not candidate.is_file() or candidate.is_symlink():
            continue
        record: dict[str, Any] = {"file": name}
        summariser = _SUMMARISERS.get(name)
        if summariser is not None:
            text = _read_manifest(candidate)
            if text:
                record["declares"] = summariser(text)
        found.append(record)
    return found


def project_overview(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    """Summarise the workspace: languages, manifests, entry points and tests."""
    root = context.workspace.resolve(str(arguments.get("path", ".")))
    context.workspace.require_directory(root)

    survey = _survey(context, root)
    manifests = _manifests(root)
    languages = survey.languages()
    total_files = survey.total_files
    total_bytes = survey.total_bytes
    test_files = survey.test_files
    entry_points = survey.entry_points
    largest = survey.largest
    timed_out = survey.timed_out

    version_control = "git" if (context.workspace.root / ".git").exists() else "none"

    lines = [
        f"{total_files} file(s), {total_bytes} bytes under {context.workspace.display(root)}",
        f"Version control: {version_control}.",
    ]
    if languages:
        rendered = ", ".join(
            f"{item['language']} ({item['files']} files, {item['lines']} lines)"
            for item in languages[:8]
        )
        lines.append(f"Languages: {rendered}.")
    if manifests:
        lines.append("Manifests: " + ", ".join(item["file"] for item in manifests) + ".")
    if entry_points:
        lines.append("Entry points: " + ", ".join(sorted(entry_points)[:10]) + ".")
    lines.append(f"Test files: {test_files}.")
    if timed_out:
        lines.append("The walk stopped at the time budget; counts are a lower bound.")

    return ToolResult(
        text="\n".join(lines),
        structured={
            "path": str(context.workspace.relative(root)),
            "total_files": total_files,
            "total_bytes": total_bytes,
            "languages": languages,
            "manifests": manifests,
            "entry_points": sorted(entry_points),
            "test_files": test_files,
            "largest_files": [{"path": name, "size_bytes": size} for size, name in largest[:10]],
            "version_control": version_control,
            "timed_out": timed_out,
        },
    )


PROJECT_OVERVIEW = ToolSpec(
    name="project_overview",
    title="Summarise the project",
    description=(
        "Summarise the workspace in one call: language mix by file and line count, the "
        "dependency manifests present and what they declare, likely entry points, how "
        "many test files there are, and whether the tree is under version control. "
        "Call this first when you do not know the project — it replaces several "
        "exploratory listings. Everything reported is measured from the filesystem, "
        "not inferred."
    ),
    input_schema=object_schema(
        {
            "path": {
                "type": "string",
                "description": "Directory to summarise. Defaults to the workspace root.",
                "maxLength": 4096,
            }
        }
    ),
    output_schema=object_schema(
        {
            "path": {"type": "string"},
            "total_files": {"type": "integer"},
            "total_bytes": {"type": "integer"},
            "languages": {"type": "array"},
            "manifests": {"type": "array"},
            "entry_points": {"type": "array", "items": {"type": "string"}},
            "test_files": {"type": "integer"},
            "largest_files": {"type": "array"},
            "version_control": {"type": "string"},
            "timed_out": {"type": "boolean"},
        }
    ),
    handler=project_overview,
)

__all__ = ["MANIFESTS", "PROJECT_OVERVIEW", "project_overview"]
