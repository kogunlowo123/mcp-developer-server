"""Running the conformance suite, and deciding whether it passed.

This is the gate. ``mcp-devserver conform`` exits non-zero when a MUST check
fails, which is the difference between a report and a gate: CI runs the command,
and a change that breaks the protocol contract fails the build rather than
printing a red line nobody reads.

SHOULD checks are reported separately and do not fail by default, because a
recommendation is not a requirement. ``--strict`` promotes them, and CI uses it:
this server has no reason to violate a SHOULD, so a new violation is a
regression here even though it would not be non-conformance in general.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_devserver.conformance.checks import CHECKS, MUST, Check, CheckFailedError
from mcp_devserver.conformance.client import Client


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    """What happened to one check."""

    identifier: str
    level: str
    title: str
    passed: bool
    duration_ms: float
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Render for a JSON report."""
        return {
            "id": self.identifier,
            "level": self.level,
            "title": self.title,
            "passed": self.passed,
            "duration_ms": round(self.duration_ms, 3),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class Report:
    """The outcome of a whole run."""

    target: str
    outcomes: tuple[CheckOutcome, ...]
    started_at: str
    duration_ms: float
    strict: bool = False
    failures: tuple[str, ...] = field(default=())

    @property
    def must_failures(self) -> tuple[CheckOutcome, ...]:
        """Failed MUST checks."""
        return tuple(item for item in self.outcomes if not item.passed and item.level == MUST)

    @property
    def should_failures(self) -> tuple[CheckOutcome, ...]:
        """Failed SHOULD checks."""
        return tuple(item for item in self.outcomes if not item.passed and item.level != MUST)

    @property
    def passed(self) -> int:
        """How many checks passed."""
        return sum(1 for item in self.outcomes if item.passed)

    @property
    def green(self) -> bool:
        """Whether this run is a pass under the configured strictness."""
        if self.must_failures:
            return False
        return not (self.strict and self.should_failures)

    def to_dict(self) -> dict[str, Any]:
        """Render the whole report."""
        return {
            "target": self.target,
            "started_at": self.started_at,
            "duration_ms": round(self.duration_ms, 3),
            "strict": self.strict,
            "total": len(self.outcomes),
            "passed": self.passed,
            "must_failures": len(self.must_failures),
            "should_failures": len(self.should_failures),
            "green": self.green,
            "checks": [item.as_dict() for item in self.outcomes],
        }

    def render(self) -> str:
        """Render a human-readable report."""
        lines = [
            f"target      {self.target}",
            f"checks      {self.passed}/{len(self.outcomes)} passed",
        ]
        if self.must_failures:
            lines.append(f"MUST        {len(self.must_failures)} failed")
        if self.should_failures:
            lines.append(f"SHOULD      {len(self.should_failures)} failed")
        lines.append(f"duration    {self.duration_ms:.0f}ms")
        lines.append("")
        for outcome in self.outcomes:
            mark = "ok  " if outcome.passed else "FAIL"
            lines.append(f"  {mark}  {outcome.identifier}  [{outcome.level}]  {outcome.title}")
            if not outcome.passed:
                lines.append(f"          {outcome.detail}")
        lines.append("")
        lines.append("CONFORMANT" if self.green else "NOT CONFORMANT")
        return "\n".join(lines)


async def run_check(check: Check, client: Client) -> CheckOutcome:
    """Run one check, converting any failure into an outcome."""
    started = time.perf_counter()
    try:
        await check.run(client)
    except CheckFailedError as failure:
        return CheckOutcome(
            identifier=check.identifier,
            level=check.level,
            title=check.title,
            passed=False,
            duration_ms=(time.perf_counter() - started) * 1000,
            detail=str(failure),
        )
    except Exception as error:
        # A check that raises something else is still a failure, and the type is
        # part of the detail: a JSONDecodeError here means the server wrote
        # something that is not JSON, which is exactly what one wants to see.
        return CheckOutcome(
            identifier=check.identifier,
            level=check.level,
            title=check.title,
            passed=False,
            duration_ms=(time.perf_counter() - started) * 1000,
            detail=f"{type(error).__name__}: {error}",
        )
    return CheckOutcome(
        identifier=check.identifier,
        level=check.level,
        title=check.title,
        passed=True,
        duration_ms=(time.perf_counter() - started) * 1000,
    )


async def run_suite(
    client: Client,
    *,
    checks: tuple[Check, ...] = CHECKS,
    strict: bool = False,
) -> Report:
    """Run every check against one client."""
    started = time.perf_counter()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    outcomes = [await run_check(check, client) for check in checks]
    return Report(
        target=client.label,
        outcomes=tuple(outcomes),
        started_at=started_at,
        duration_ms=(time.perf_counter() - started) * 1000,
        strict=strict,
    )


def write_report(report: Report, path: Path) -> None:
    """Write the JSON report, creating the directory if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
