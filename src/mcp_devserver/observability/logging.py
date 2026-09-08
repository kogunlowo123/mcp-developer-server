"""Structured logging, configured so it cannot corrupt the protocol stream.

The constraint that shapes this module is specific to stdio servers: **stdout is
the wire**. A library that prints a deprecation warning, a stray ``print`` in a
handler, or a logger with a default ``StreamHandler`` writes bytes into the
middle of a JSON-RPC stream and the client sees a parse error it cannot explain.

So every log record goes to stderr, the root logger is configured explicitly
rather than left to its defaults, and ``configure`` is called before the
transport starts. Third-party records are routed through the same processor
chain, which means an SQLAlchemy or urllib warning arrives as JSON on stderr
rather than as prose on stdout.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Final

import structlog

from mcp_devserver.config import ObservabilitySettings

#: Argument names whose values are replaced before a record is emitted. Paths
#: are the developer's private directory structure and tokens are credentials;
#: neither belongs in a log file that may be attached to a bug report.
REDACTED_KEYS: Final[frozenset[str]] = frozenset(
    {"bearer_token", "authorization", "token", "secret", "password", "api_key"}
)

_REPLACEMENT: Final[str] = "[redacted]"


def _redact(_logger: object, _method: str, event: dict[str, Any]) -> dict[str, Any]:
    """Replace credential-shaped values in the event dictionary.

    Last in the chain, so it also covers keys added by earlier processors.
    """
    for key in list(event):
        if key.lower() in REDACTED_KEYS and event[key]:
            event[key] = _REPLACEMENT
    return event


def configure(settings: ObservabilitySettings) -> None:
    """Configure structlog and the standard library logging module."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _redact,
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer(sort_keys=True)
        if settings.log_json
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        # LoggerFactory, not PrintLoggerFactory: the stdlib factory is what lets
        # ProcessorFormatter unify third-party records into this chain, and
        # PrintLoggerFactory raises when combined with add_logger_name.
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Replace rather than add. A second handler installed by an earlier import
    # would duplicate every line, and one of the duplicates could be on stdout.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn installs its own handlers on these; let them propagate to the root
    # handler above so the whole process logs in one format on one stream.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
