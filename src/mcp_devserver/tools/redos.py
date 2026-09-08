r"""Refusing regular expressions that can be made to run for an unbounded time.

This module exists because of a defect the tests found and the docstring in
``search.py`` originally denied. ``search_code`` takes a caller-supplied regular
expression and applies it line by line, checking a wall-clock budget between
files. That bounds a *slow* search. It does not bound a *catastrophic* one:
``(a+)+b`` against forty ``a`` characters is a single ``re.search`` call that
does not return in the lifetime of the universe, and no budget checked around it
is ever reached.

Nor can it be fixed by a timeout at a higher level. ``asyncio.wait_for`` around
``asyncio.to_thread`` abandons the coroutine but cannot stop the thread, and
Python has no way to interrupt a running ``re`` match. The thread keeps a core
busy for the life of the process. On a developer's laptop that is the whole
machine getting slower with no explanation.

So the check has to happen before the pattern is compiled, and it has to be a
static one. This is a **heuristic and not a decision procedure** — recognising
every exponential regular expression is undecidable in the general case — but it
catches the shapes that actually appear:

* a quantified group whose body contains a quantifier: ``(a+)+``, ``(a*)*``,
  ``(\\d+)+``, ``([a-z]*)+``;
* a quantified group whose alternatives can match the same single character:
  ``(a|a)+``, ``(a|ab)*``.

``THREAT-MODEL.md`` records what remains: a pattern outside these shapes that is
still slow is bounded only by the per-file budget, and the honest mitigation for
that is that this server is meant to be run by the developer whose machine it is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: Quantifiers that can repeat unboundedly. ``{n}`` with an exact count is not
#: one of them, and ``?`` repeats at most once.
_UNBOUNDED: Final[re.Pattern[str]] = re.compile(r"[*+]|\{\d*,\d*\}|\{\d+,\}")


@dataclass(frozen=True, slots=True)
class Group:
    """One parenthesised group and the quantifier that follows it, if any."""

    #: The body with escapes replaced by a placeholder, for analysis.
    body: str
    #: The body exactly as the caller wrote it, for the refusal message. A
    #: message quoting the placeholder form would show the user a pattern they
    #: never typed.
    source: str
    quantifier: str


def _strip_escapes(pattern: str) -> str:
    r"""Replace every escaped character with placeholders, preserving length.

    ``\\+`` is a literal plus, not a quantifier, and a scanner that does not know
    the difference reports every escaped pattern as dangerous.

    Two placeholders per escape, not one, so that offsets into the stripped
    string are also offsets into the original. Without that, the refusal message
    quotes a shifted slice — ``(\\d)`` for a pattern the caller wrote as
    ``(\\d+)``.
    """
    output: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            output.append("\x00\x00")
            index += 2
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _groups(pattern: str) -> list[Group]:
    """Extract each group's body and the quantifier applied to it.

    Written as a scanner rather than a regular expression because the thing
    being parsed is a regular expression: nesting and character classes both
    defeat a pattern-based approach.
    """
    text = _strip_escapes(pattern)
    found: list[Group] = []
    stack: list[int] = []
    in_class = False
    index = 0
    while index < len(text):
        character = text[index]
        if in_class:
            if character == "]":
                in_class = False
            index += 1
            continue
        if character == "[":
            in_class = True
        elif character == "(":
            stack.append(index)
        elif character == ")" and stack:
            start = stack.pop()
            body = text[start + 1 : index]
            quantifier = ""
            after = index + 1
            if after < len(text):
                if text[after] in "*+?":
                    quantifier = text[after]
                elif text[after] == "{":
                    closing = text.find("}", after)
                    if closing != -1:
                        quantifier = text[after : closing + 1]
            found.append(
                Group(
                    body=body,
                    source=pattern[start + 1 : index],
                    quantifier=quantifier,
                )
            )
        index += 1
    return found


def _body_without_group_markers(body: str) -> str:
    """Strip the non-capturing markers from a group body."""
    return body.removeprefix("?:").removeprefix("?i:").removeprefix("?=").removeprefix("?!")


def _alternatives(body: str) -> list[str]:
    """Split a group body on top-level ``|``."""
    parts: list[str] = []
    depth = 0
    in_class = False
    current: list[str] = []
    for character in body:
        if in_class:
            current.append(character)
            if character == "]":
                in_class = False
            continue
        if character == "[":
            in_class = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "|" and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    parts.append("".join(current))
    return parts


def _first_atoms_overlap(alternatives: list[str]) -> bool:
    """Whether two alternatives can begin with the same character.

    An approximation, and deliberately a narrow one: it looks only at the first
    literal character of each branch, so ``(a|ab)`` is caught and ``(foo|bar)``
    — which is safe and common — is not.
    """
    firsts: list[str] = []
    for alternative in alternatives:
        stripped = alternative.lstrip("^")
        if not stripped or stripped[0] in "([.\x00":
            # A class, a group, a wildcard or an escape. Not analysed rather
            # than guessed at.
            return False
        firsts.append(stripped[0])
    return len(set(firsts)) < len(firsts)


def catastrophic_shape(pattern: str) -> str:
    """Name the dangerous construct in ``pattern``, or return ``""``.

    Returns the reason rather than a boolean so the caller can tell the user
    which part of their pattern was refused.
    """
    for group in _groups(pattern):
        if not group.quantifier or group.quantifier == "?":
            continue
        if group.quantifier.startswith("{") and not _UNBOUNDED.fullmatch(group.quantifier):
            continue
        body = _body_without_group_markers(group.body)
        if _UNBOUNDED.search(body):
            return (
                f"the group '({group.source})' is repeated with '{group.quantifier}' and "
                "already contains a repetition"
            )
        alternatives = _alternatives(body)
        if len(alternatives) > 1 and _first_atoms_overlap(alternatives):
            return (
                f"the group '({group.source})' is repeated with '{group.quantifier}' and its "
                "alternatives can match the same text"
            )
    return ""
