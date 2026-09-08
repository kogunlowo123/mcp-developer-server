"""Streamable HTTP transport.

The same dispatcher as stdio, reached over one endpoint. What this module adds
is everything HTTP makes possible and therefore necessary to defend against:

* **A body limit before the body is read.** ``Content-Length`` is checked first,
  and the read itself is bounded, because a client may lie about the header or
  omit it entirely with a chunked body.
* **A bearer token when one is configured**, compared in constant time. Without
  authentication an MCP server on a listening port is a remote filesystem read
  primitive for anything else on the machine — including a page in the
  developer's browser.
* **Origin checking.** A browser can POST JSON cross-origin without a preflight.
  A server bound to loopback is reachable from any page the developer visits, so
  a request carrying an ``Origin`` this server does not know is refused. This is
  DNS-rebinding defence, and it is the reason the specification tells HTTP
  servers to validate ``Origin``.
* **A protocol-version header**, cross-checked against ``_meta``. When they
  disagree the request is refused rather than resolved in favour of one.

``/healthz`` and ``/readyz`` exist for a container runtime and answer without
authentication: a liveness probe that needs a credential is a liveness probe
that reports the wrong thing when the credential is wrong.
"""

from __future__ import annotations

import hmac
import json
from typing import Any, Final

import structlog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_devserver.errors import (
    HeaderMismatchError,
    InvalidRequestError,
    McpError,
    ParseError,
)
from mcp_devserver.protocol import jsonrpc, spec
from mcp_devserver.protocol.server import Server

_log = structlog.get_logger(__name__)

#: The header carrying the protocol version at the transport level.
PROTOCOL_VERSION_HEADER: Final[str] = "mcp-protocol-version"

#: The single RPC endpoint.
ENDPOINT: Final[str] = "/mcp"

#: JSON-RPC errors that mean "the caller sent something wrong" map to 400; a
#: version error maps to 400 as well, because the request as sent cannot be
#: served. Everything else is 200 with an error body, which is what JSON-RPC
#: over HTTP expects: the transport succeeded, the call did not.
_BAD_REQUEST_CODES: Final[frozenset[int]] = frozenset(
    {
        spec.PARSE_ERROR,
        spec.INVALID_REQUEST,
        spec.INVALID_PARAMS,
        spec.HEADER_MISMATCH,
        spec.MISSING_REQUIRED_CLIENT_CAPABILITY,
        spec.UNSUPPORTED_PROTOCOL_VERSION,
    }
)


def _status_for(payload: dict[str, Any]) -> int:
    error = payload.get("error")
    if not isinstance(error, dict):
        return 200
    code = error.get("code")
    if code == spec.METHOD_NOT_FOUND:
        return 404
    if isinstance(code, int) and code in _BAD_REQUEST_CODES:
        return 400
    return 500 if code == spec.INTERNAL_ERROR else 200


class HttpTransport:
    """Builds the Starlette application for one server."""

    def __init__(self, server: Server) -> None:
        self._server = server
        self._settings = server.settings
        self._token = self._settings.http.bearer_token
        self._origins = frozenset(self._settings.http.allowed_origins)
        self._max_bytes = self._settings.http.max_request_bytes

    def application(self) -> Starlette:
        """Build the ASGI application."""
        return Starlette(
            routes=[
                Route(ENDPOINT, self.rpc, methods=["POST"]),
                Route("/healthz", self.healthz, methods=["GET"]),
                Route("/readyz", self.readyz, methods=["GET"]),
            ]
        )

    # -- probes ------------------------------------------------------------

    async def healthz(self, _request: Request) -> Response:
        """Liveness: the process is up and can serialise a response."""
        return JSONResponse({"status": "ok"})

    async def readyz(self, _request: Request) -> Response:
        """Readiness: the workspace still resolves and the tools are published."""
        root = self._server.workspace.root
        ready = root.is_dir()
        return JSONResponse(
            {
                "status": "ready" if ready else "unready",
                "workspace_present": ready,
                "tools": len(self._server.registry),
                "protocol_versions": list(spec.SUPPORTED_VERSIONS),
            },
            status_code=200 if ready else 503,
        )

    # -- rpc ---------------------------------------------------------------

    def _authorised(self, request: Request) -> bool:
        if not self._token:
            return True
        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer":
            return False
        # compare_digest, not ==: a naive comparison leaks the length of the
        # matching prefix through timing, which is enough to recover a token.
        return hmac.compare_digest(presented.strip(), self._token)

    def _origin_allowed(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if origin is None:
            # No Origin means the request did not come from a browser context.
            return True
        return origin in self._origins

    async def rpc(self, request: Request) -> Response:
        """Handle one JSON-RPC request over HTTP."""
        if not self._origin_allowed(request):
            _log.warning("http.origin_rejected", origin=request.headers.get("origin"))
            return JSONResponse(
                {"error": "origin not allowed"},
                status_code=403,
            )

        if not self._authorised(request):
            return JSONResponse(
                {"error": "unauthorised"},
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )

        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self._max_bytes:
            return JSONResponse(
                {"error": f"request larger than the {self._max_bytes}-byte limit"},
                status_code=413,
            )

        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > self._max_bytes:
                # The header may have been absent or wrong; this is the check
                # that actually bounds memory.
                return JSONResponse(
                    {"error": f"request larger than the {self._max_bytes}-byte limit"},
                    status_code=413,
                )

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self._error_response(None, ParseError(f"request body is not valid JSON: {exc}"))

        if isinstance(payload, list):
            # JSON-RPC batching is not part of MCP 2026-07-28, and accepting it
            # would mean one HTTP request could start an unbounded number of
            # tool runs.
            return self._error_response(
                None, InvalidRequestError("this server does not accept JSON-RPC batches")
            )

        header_version = request.headers.get(PROTOCOL_VERSION_HEADER)
        try:
            parsed = jsonrpc.from_payload(payload)
        except McpError as error:
            identifier = payload.get("id") if isinstance(payload, dict) else None
            if not isinstance(identifier, str | int) or isinstance(identifier, bool):
                identifier = None
            return self._error_response(identifier, error)

        try:
            response = await self._server.handle(parsed, header_version=header_version)
        except HeaderMismatchError as error:
            return self._error_response(parsed.id, error)

        if response is None:
            # A notification. 202 rather than 200 with an empty body: the
            # request was accepted and there is deliberately nothing to read.
            return Response(status_code=202)

        return JSONResponse(response, status_code=_status_for(response))

    def _error_response(self, identifier: object, error: McpError) -> Response:
        payload = jsonrpc.failure(identifier if isinstance(identifier, str | int) else None, error)
        return JSONResponse(payload, status_code=_status_for(payload))


def build_application(server: Server) -> Starlette:
    """Build the ASGI application for a server."""
    return HttpTransport(server).application()
