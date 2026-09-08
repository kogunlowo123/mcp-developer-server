"""The ReDoS guard: what it catches, and what it must not.

Both halves matter equally. A guard that refuses ``(foo|bar)+`` is a guard that
makes the search tool useless for real work, and a developer who is refused a
legitimate pattern will stop using the tool rather than rewrite it.
"""

from __future__ import annotations

import re
import time

import pytest

from mcp_devserver.tools.redos import catastrophic_shape

pytestmark = pytest.mark.unit

#: Patterns whose match time is exponential in the length of the input.
CATASTROPHIC = (
    r"(a+)+b",
    r"(a*)*c",
    r"([a-z]+)*x",
    r"(\d+)+",
    r"(x+x+)+y",
    r"(?:a+)+b",
    r"(a{1,}){2,}",
    r"(\w+\s?)*$",
    r"(a|a)+",
    r"(a|ab)*",
)

#: Patterns a developer would reasonably type. Every one must be allowed.
LEGITIMATE = (
    "class Engine",
    r"^def \w+\(",
    r"(foo|bar)+",
    r"\(a\+\)\+",
    r"[a-z]+",
    r"(abc)+",
    r"a+b+c+",
    r"(?:https?://)\S+",
    r"(a)?",
    r"(a){3}",
    r"^\s*def\s+(\w+)",
    r"TODO|FIXME",
    r"import\s+(\w+)",
    r"#\s*type:\s*ignore\[(\w+)\]",
)


@pytest.mark.parametrize("pattern", CATASTROPHIC)
def test_a_catastrophic_pattern_is_named(pattern: str):
    reason = catastrophic_shape(pattern)
    assert reason
    assert "repeated with" in reason


@pytest.mark.parametrize("pattern", LEGITIMATE)
def test_a_legitimate_pattern_is_allowed(pattern: str):
    assert catastrophic_shape(pattern) == ""


def test_the_reason_quotes_the_pattern_the_caller_wrote():
    # Escapes are replaced by placeholders for analysis. If the offsets shifted,
    # the message would quote a pattern the caller never typed.
    assert r"(\d+)" in catastrophic_shape(r"(\d+)+")


def test_a_bounded_repetition_is_not_flagged():
    # `{3}` repeats a fixed number of times; the blow-up needs an unbounded one.
    assert catastrophic_shape(r"(a+){3}") == ""


def test_an_escaped_quantifier_is_a_literal_not_a_repetition():
    assert catastrophic_shape(r"(a\+)+") == ""


def test_a_flagged_pattern_really_is_slow_and_its_rewrite_is_not():
    # The guard is only worth having if what it refuses is what actually hangs,
    # and only usable if the obvious rewrite is allowed. Both halves, measured.
    #
    # Twenty characters is chosen so the nested version is clearly slower while
    # still finishing: a longer input would make a wrong assumption here hang
    # the suite instead of failing it.
    subject = "a" * 20 + "!"

    started = time.monotonic()
    re.compile(r"(a+)+b").search(subject)
    nested = time.monotonic() - started

    started = time.monotonic()
    re.compile(r"a+b").search(subject)
    flat = time.monotonic() - started

    assert nested > flat
    assert catastrophic_shape(r"(a+)+b")
    assert catastrophic_shape(r"a+b") == ""
