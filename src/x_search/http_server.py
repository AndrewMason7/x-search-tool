"""Network transports (streamable HTTP + SSE) for the x-search MCP server.

The ``stdio`` transport is what local MCP hosts (Hermes, Claude Desktop, Cursor)
use: the host spawns this process and talks JSON-RPC over stdin/stdout. Remote
web clients cannot do that -- Google Gemini Spark's "custom apps" in particular
needs a public HTTPS endpoint that accepts JSON-RPC over POST (streamable HTTP)
or a Server-Sent-Events stream.

This module builds a single ASGI application serving both transports on one
port, so a reverse proxy (Caddy -> Cloudflare Tunnel) can front the server with
one upstream:

    GET  /health       -> liveness probe, always unauthenticated
    POST /mcp          -> streamable HTTP: JSON-RPC request/response
    GET  /sse          -> SSE stream (legacy HTTP+SSE transport)
    POST /messages/    -> SSE client -> server channel

Security is handled at two levels. A reverse proxy can gate the public surface
(see the README's Gemini Spark section), and when ``X_SEARCH_PUBLIC_URL`` is set
the MCP server runs its own OAuth 2.1 authorization server
(:mod:`x_search.oauth`), so every request except ``/health`` must carry a bearer
token that this server issued. Passing ``bearer_token`` here adds a third, much
blunter option: a single static token required on every request. It is kept for
proxies that inject an upstream credential and is incompatible with OAuth (the
static check runs first and would reject OAuth-issued tokens).
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("x_search.http")

HEALTH_PATH = "/health"
OAUTH_METADATA_PREFIX = "/.well-known/oauth-protected-resource"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8091
DEFAULT_STREAMABLE_HTTP_PATH = "/mcp"
DEFAULT_SSE_PATH = "/sse"
DEFAULT_MESSAGE_PATH = "/messages/"

_HEADER_LOOKUP_KEY = b"authorization"


def _header_value(scope: Scope, name: bytes) -> bytes | None:
    """Return the raw value of the first matching header in an ASGI scope."""
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value
    return None


class BearerAuthMiddleware:
    """Require ``Authorization: Bearer <token>`` on every request.

    Pure ASGI middleware rather than a Starlette ``BaseHTTPMiddleware`` so that
    streaming SSE responses are never buffered. The health probe and the OAuth
    resource-metadata endpoint stay open: clients (Gemini Spark among them) probe
    those before they have anywhere to put a credential.
    """

    def __init__(
        self,
        app: ASGIApp,
        token: str,
        exempt_paths: Iterable[str] = (HEALTH_PATH,),
    ) -> None:
        if not token:
            raise ValueError("BearerAuthMiddleware requires a non-empty token")
        self.app = app
        self._expected = f"Bearer {token}".encode()
        self._exempt = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # lifespan / websocket scopes pass through
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self._exempt or path.startswith(OAUTH_METADATA_PREFIX):
            await self.app(scope, receive, send)
            return

        supplied = _header_value(scope, _HEADER_LOOKUP_KEY)
        if supplied is None or not secrets.compare_digest(supplied, self._expected):
            logger.warning("Rejected unauthenticated request: %s %s", scope.get("method"), path)
            response = PlainTextResponse(
                "Unauthorized\n",
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="x-search"'},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _health_endpoint(server_name: str, transports: list[str]) -> Any:
    async def health(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": server_name, "transports": transports})

    return health


def _oauth_metadata_endpoint(_request: Any) -> JSONResponse:
    """Advertise "no authorization server" for the RFC 9728 discovery probe.

    Clients -- Gemini Spark among them -- probe this before they have anywhere to
    put a credential. An empty document tells them the resource is not OAuth
    protected, so they stop probing and proceed to the JSON-RPC handshake instead
    of reporting the endpoint as invalid.
    """

    return JSONResponse({})


def build_asgi_app(
    mcp: MCPServer[Any],
    *,
    enable_streamable_http: bool = True,
    enable_sse: bool = True,
    streamable_http_path: str = DEFAULT_STREAMABLE_HTTP_PATH,
    sse_path: str = DEFAULT_SSE_PATH,
    message_path: str = DEFAULT_MESSAGE_PATH,
    stateless_http: bool = False,
    bearer_token: str | None = None,
    host: str = DEFAULT_HOST,
) -> ASGIApp:
    """Compose the streamable-HTTP and SSE transports into one ASGI application.

    Args:
        mcp: The configured MCP server instance.
        enable_streamable_http: Mount the streamable-HTTP transport at
            ``streamable_http_path``.
        enable_sse: Mount the legacy HTTP+SSE transport at ``sse_path`` /
            ``message_path``.
        stateless_http: When True the streamable transport issues no session ID,
            which is more forgiving with clients that do not replay
            ``Mcp-Session-Id``. Recommended behind a reverse proxy.
        bearer_token: When set, require this bearer token on all requests except
            ``/health`` and the OAuth resource-metadata probe.
        host: Origin host used for the transport-security policy. The public
            hostname differs (it is the tunnel's), so DNS-rebinding protection is
            disabled and left to the proxy layer.

    Raises:
        ValueError: If neither transport is enabled, or the paths collide.
    """
    if not enable_streamable_http and not enable_sse:
        raise ValueError("At least one of enable_streamable_http / enable_sse must be True")
    if (
        enable_streamable_http
        and enable_sse
        and streamable_http_path.rstrip("/") == sse_path.rstrip("/")
    ):
        raise ValueError(f"streamable_http_path and sse_path collide on {streamable_http_path!r}")

    # The public hostname is the tunnel's, not this process's bind address, so
    # host-based rebinding checks would reject every proxied request. The proxy
    # is the trust boundary here.
    transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    routes: list[Any] = []
    transports: list[str] = []

    http_app: Starlette | None = None
    if enable_streamable_http:
        http_app = mcp.streamable_http_app(
            streamable_http_path=streamable_http_path,
            stateless_http=stateless_http,
            transport_security=transport_security,
            host=host,
        )
        routes.extend(http_app.routes)
        transports.append("streamable-http")

    sse_app: Starlette | None = None
    if enable_sse:
        sse_app = mcp.sse_app(
            sse_path=sse_path,
            message_path=message_path,
            transport_security=transport_security,
            host=host,
        )
        routes.extend(sse_app.routes)
        transports.append("sse")

    # When OAuth is configured the SDK mounts a real RFC 9728 protected-resource
    # document pointing at our authorization server. That must win: inserting the
    # "no auth here" stub in front of it would send clients hunting for a
    # registration endpoint that is deliberately absent.
    auth_configured = bool(getattr(getattr(mcp, "settings", None), "auth", None))
    if not auth_configured:
        routes.insert(
            0,
            Route(
                f"{OAUTH_METADATA_PREFIX}{{rest:path}}",
                _oauth_metadata_endpoint,
                methods=["GET"],
            ),
        )
    routes.insert(
        0, Route(HEALTH_PATH, _health_endpoint(mcp.name or "x-search", transports), methods=["GET"])
    )

    # The sub-apps carry app-level middleware that must survive the merge. With
    # OAuth enabled that is Starlette's AuthenticationMiddleware (which is what
    # populates request.auth for the SDK's RequireAuthMiddleware) plus the auth
    # context middleware — dropping it turns every authenticated request into a
    # 401 "Authentication required". Both sub-apps install the same set, so they
    # are merged by middleware class to avoid stacking duplicates.
    middleware: list[Any] = []
    seen_middleware: set[str] = set()
    for sub_app in (http_app, sse_app):
        if sub_app is None:
            continue
        for entry in sub_app.user_middleware:
            key = getattr(entry, "cls", type(entry)).__name__
            if key in seen_middleware:
                continue
            seen_middleware.add(key)
            middleware.append(entry)

    # The streamable app owns the only lifespan that matters: it starts and stops
    # the StreamableHTTPSessionManager task group. The SSE app is lifespan-free,
    # so its routes can simply be merged in.
    http_router = http_app.router if http_app is not None else None

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        if http_router is None:
            yield
            return
        async with http_router.lifespan_context(app):
            yield

    if bearer_token is not None and not bearer_token.strip():
        raise ValueError(
            "bearer_token was provided but is empty; pass None to disable authentication "
            "or supply a non-empty token"
        )

    app: ASGIApp = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)

    if bearer_token:
        app = BearerAuthMiddleware(app, bearer_token)

    logger.info("Built x-search ASGI app: transports=%s", ", ".join(transports))
    return app


def run_http_server(
    mcp: MCPServer[Any],
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    enable_streamable_http: bool = True,
    enable_sse: bool = True,
    streamable_http_path: str = DEFAULT_STREAMABLE_HTTP_PATH,
    sse_path: str = DEFAULT_SSE_PATH,
    message_path: str = DEFAULT_MESSAGE_PATH,
    stateless_http: bool = False,
    bearer_token: str | None = None,
    access_log: bool = False,
) -> None:
    """Serve the MCP server over HTTP until interrupted."""
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - uvicorn ships with mcp
        raise RuntimeError(
            "The HTTP/SSE transports require uvicorn, which is normally installed "
            "alongside mcp. Install it with `uv add uvicorn` (or `pip install uvicorn`)."
        ) from exc

    app = build_asgi_app(
        mcp,
        enable_streamable_http=enable_streamable_http,
        enable_sse=enable_sse,
        streamable_http_path=streamable_http_path,
        sse_path=sse_path,
        message_path=message_path,
        stateless_http=stateless_http,
        bearer_token=bearer_token,
        host=host,
    )

    logger.info(
        "Serving x-search MCP over HTTP on http://%s:%d (streamable=%s, sse=%s, auth=%s)",
        host,
        port,
        streamable_http_path if enable_streamable_http else "off",
        sse_path if enable_sse else "off",
        "bearer" if bearer_token else "none",
    )

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=access_log,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
