"""Redact credentials from anything on its way out of the process.

The denylist stops whole files. This stops the other case: a secret that lives
in a file nobody would think to deny — a hard-coded token in ``settings.py``, an
API key in a test fixture, a connection string in a docstring. A search tool
that returns matching lines will happily return that line, and once it is in a
model's context it is in the conversation, the provider's logs, and any
transcript the developer shares.

Redaction here is conservative in one direction and deliberate in the other:

* **It replaces, it does not drop.** ``AKIA...`` becomes ``[redacted:aws-access-key-id]``.
  A model that sees the placeholder knows a credential is there, which is
  frequently the answer the developer wanted ("do we leak keys anywhere?"),
  without receiving the credential itself.
* **It reports what it did.** Every result carries the count and the rule names,
  so redaction is auditable rather than invisible. A tool that quietly alters
  its output is worse than one that does not redact at all, because nobody can
  tell whether it worked.

It is not a secret scanner and does not claim to be. It catches
recognisably-shaped credentials; a bare 40-character password in a variable
called ``x`` is indistinguishable from a hash. ``THREAT-MODEL.md`` says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Rule:
    """One credential shape."""

    name: str
    pattern: re.Pattern[str]
    #: Which capture group holds the secret. Group 0 replaces the whole match,
    #: which is right for a self-delimiting token and wrong for an assignment,
    #: where the variable name is the useful part and must survive.
    group: int = 0


def _rule(name: str, pattern: str, *, group: int = 0, flags: int = 0) -> Rule:
    return Rule(name=name, pattern=re.compile(pattern, flags), group=group)


#: Ordered. Earlier rules win, so specific provider shapes are tried before the
#: generic assignment rule, and a match is reported under the most informative
#: name available.
RULES: Final[tuple[Rule, ...]] = (
    _rule("aws-access-key-id", r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b", group=1),
    _rule("github-token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", group=1),
    _rule("github-fine-grained-token", r"\b(github_pat_[A-Za-z0-9_]{60,})\b", group=1),
    _rule("gitlab-token", r"\b(glpat-[A-Za-z0-9_-]{20,})\b", group=1),
    _rule("slack-token", r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b", group=1),
    _rule("stripe-key", r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b", group=1),
    _rule("openai-key", r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b", group=1),
    _rule("anthropic-key", r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b", group=1),
    _rule("google-api-key", r"\b(AIza[0-9A-Za-z_-]{35})\b", group=1),
    _rule("npm-token", r"\b(npm_[A-Za-z0-9]{36})\b", group=1),
    _rule("hugging-face-token", r"\b(hf_[A-Za-z0-9]{34,})\b", group=1),
    _rule("jwt", r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", group=1),
    _rule(
        "private-key-block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    ),
    # A URL with inline credentials. The scheme and host stay, because "which
    # host" is usually the question and only the password is the secret.
    _rule(
        "url-credentials",
        r"\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s/@]+)(@)",
        group=2,
    ),
    _rule("basic-auth-header", r"(?i)\b(authorization\s*:\s*(?:basic|bearer)\s+)(\S+)", group=2),
    # The generic case, last. Requires a secret-ish key name *and* a value with
    # enough entropy shape to not be a placeholder, which is what keeps
    # `password = "REPLACE_ME"` and `token = ""` out of the results.
    _rule(
        "assigned-secret",
        r"(?i)\b((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret"
        r"|private[_-]?key|passwd|password|secret)\s*[:=]\s*[\"']?)"
        r"([A-Za-z0-9_+/.=~-]{12,})([\"']?)",
        group=2,
    ),
)

#: A value made of this few distinct characters, at this length or longer, is a
#: mask (``xxxxxxxx``, ``********``) rather than a credential.
_MASK_DISTINCT_CHARACTERS: Final[int] = 2
_MASK_MINIMUM_LENGTH: Final[int] = 4

#: Values that look like credentials but are documentation. Redacting these
#: makes ``.env.example`` unreadable and teaches nothing, and a placeholder that
#: leaks is not a leak.
PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {
        "replace_me",
        "changeme",
        "change_me",
        "your_api_key",
        "your-api-key",
        "yourapikeyhere",
        "xxxxxxxxxxxx",
        "placeholder",
        "example",
        "notarealkey",
        "dummy",
        "redacted",
        "none",
        "null",
        "undefined",
        "true",
        "false",
    }
)


@dataclass(frozen=True, slots=True)
class Redaction:
    """The outcome of redacting one piece of text."""

    text: str
    count: int
    rules: tuple[str, ...]

    @property
    def redacted(self) -> bool:
        """Whether anything was replaced."""
        return self.count > 0


def _is_placeholder(value: str) -> bool:
    stripped = value.strip("\"'` \t").lower()
    if stripped in PLACEHOLDERS:
        return True
    # A run of a single repeated character is a mask, not a credential.
    core = stripped.strip("<>{}[]")
    return len(set(core)) <= _MASK_DISTINCT_CHARACTERS and len(core) >= _MASK_MINIMUM_LENGTH


class Redactor:
    """Applies the rule set to text leaving the process."""

    def __init__(self, rules: tuple[Rule, ...] = RULES, *, enabled: bool = True) -> None:
        self._rules = rules
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Whether redaction is on."""
        return self._enabled

    def apply(self, text: str) -> Redaction:
        """Replace every recognised credential in ``text``."""
        if not self._enabled or not text:
            return Redaction(text=text, count=0, rules=())

        fired: list[str] = []
        total = 0
        result = text

        for rule in self._rules:
            replaced = 0

            def substitute(match: re.Match[str], rule: Rule = rule) -> str:
                nonlocal replaced
                secret = match.group(rule.group)
                if not secret or _is_placeholder(secret):
                    return match.group(0)
                replaced += 1
                token = f"[redacted:{rule.name}]"
                if rule.group == 0:
                    return token
                whole = match.group(0)
                start, end = match.span(rule.group)
                offset = match.start()
                return whole[: start - offset] + token + whole[end - offset :]

            result = rule.pattern.sub(substitute, result)
            if replaced:
                fired.append(rule.name)
                total += replaced

        return Redaction(text=result, count=total, rules=tuple(fired))
