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

import html
import logging
import os
import secrets
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import AuthorizeError
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from x_search.oauth import authorization_server_metadata, protected_resource_metadata

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


def _env_flag(name: str) -> bool:
    """Read a boolean-ish environment variable."""
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


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


#: OAuth endpoints whose request shape is worth logging when debugging a client
#: integration. Bodies are small and non-streaming, so buffering them is safe.
DEBUGGED_AUTH_PATHS = frozenset({"/authorize", "/token", "/register"})
_SECRET_FIELDS = ("client_secret", "code", "code_verifier", "refresh_token", "assertion")


MAX_AUTH_BODY_BYTES = 64 * 1024  # 64 KB


class AuthDebugMiddleware:
    """Log the shape (never the values) of OAuth requests.

    Enabled by ``X_SEARCH_DEBUG_AUTH=1``. Exists because a client that fails
    "account linking" gives you nothing to work with: you cannot tell whether it
    never called ``/token``, called it without a secret, or used HTTP Basic when
    the registered client expects the secret in the body. This answers that in one
    attempt. Secrets are recorded only as present/absent.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") not in DEBUGGED_AUTH_PATHS:
            await self.app(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            body.extend(chunk)
            if len(body) > MAX_AUTH_BODY_BYTES:
                logger.warning(
                    "AUTH DEBUG: request body exceeded %d bytes on %s %s; aborting",
                    MAX_AUTH_BODY_BYTES,
                    scope.get("method"),
                    scope.get("path"),
                )
                response = PlainTextResponse("Payload Too Large\n", status_code=413)
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        # GET /authorize carries everything in the query string, POST /token in the
        # body; log both so one retry tells the whole story.
        parsed.update(
            parse_qs(
                scope.get("query_string", b"").decode("utf-8", "replace"), keep_blank_values=True
            )
        )
        auth_header = _header_value(scope, _HEADER_LOOKUP_KEY)
        scheme = auth_header.split(b" ", 1)[0].decode() if auth_header else "none"

        detail: dict[str, Any] = {
            key: ("<present>" if key in _SECRET_FIELDS else value)
            for key, values in parsed.items()
            for value in ["|".join(values)]
        }
        detail["authorization_scheme"] = scheme
        detail["has_client_secret_field"] = "client_secret" in parsed

        status: int | None = None

        async def capture_send(message: Any) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        logger.info("AUTH DEBUG %s %s %s", scope.get("method"), scope.get("path"), detail)

        replayed = False

        async def replay() -> Any:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, capture_send)
        logger.info("AUTH DEBUG %s %s -> %s", scope.get("method"), scope.get("path"), status)


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


def _json_endpoint(document: dict[str, Any]) -> Any:
    """Serve a static JSON document, built once at startup."""

    async def endpoint(_request: Any) -> JSONResponse:
        return JSONResponse(document)

    return endpoint


def _consent_html(
    client_name: str,
    request_id: str,
    csrf_token: str | None = None,
    error: str | None = None,
) -> str:
    """Render the approval page.

    Deliberately dependency-free: it is a handful of lines of HTML and a form, so
    there is no template engine to keep in sync and nothing to escape beyond the
    interpolated values.
    """
    error_block = f'<p class="err">{html.escape(error)}</p>' if error else ""
    csrf_field = (
        f'    <input type="hidden" name="csrf" value="{html.escape(csrf_token)}">\n'
        if csrf_token
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve connection</title>
<style>
 body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1rem; }}
 .card {{ border: 1px solid #d0d0d0; border-radius: 10px; padding: 1.5rem; }}
 .err {{ color: #b00020; }}
 code {{ background: #f2f2f2; padding: .1rem .3rem; border-radius: 4px; }}
 input[type=password] {{ width: 100%; padding: .6rem; font-size: 1rem; box-sizing: border-box; }}
 button {{ margin-top: 1rem; padding: .6rem 1.2rem; font-size: 1rem; cursor: pointer; }}
</style>
</head>
<body>
<div class="card">
  <h1>Approve connection</h1>
  <p><strong>{html.escape(client_name)}</strong> is asking to use the X search tools
     on this server.</p>
  {error_block}
  <p>Enter the approval secret for this deployment to allow it.</p>
  <form method="post" action="/consent">
    <input type="hidden" name="req" value="{html.escape(request_id)}">
{csrf_field}    <label for="consent_secret">Approval secret</label>
    <input id="consent_secret" name="consent_secret" type="password"
           autocomplete="off" autofocus required>
    <button type="submit">Approve</button>
  </form>
</div>
</body>
</html>"""


def _consent_endpoints(provider: Any) -> tuple[Any, Any]:
    """Build the GET/POST handlers for the approval page."""

    async def page(request: Any) -> HTMLResponse:
        request_id = request.query_params.get("req", "")
        consent = await provider.pending_authorization(request_id)
        if consent is None:
            return HTMLResponse(
                _consent_html(
                    "This request",
                    request_id,
                    None,
                    "This approval link has expired, was locked out, or was already used. "
                    "Start the connection again from your client.",
                ),
                status_code=400,
            )
        csrf_token = getattr(consent, "csrf_token", None)
        return HTMLResponse(_consent_html(provider.client_name, request_id, csrf_token, None))

    async def submit(request: Any) -> Response:
        # Cross-Site Request Forgery (CSRF) defenses
        sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
        if sec_fetch_site == "cross-site":
            logger.warning("Rejected cross-site POST to /consent (Sec-Fetch-Site: cross-site)")
            return PlainTextResponse("Forbidden: Cross-site request rejected\n", status_code=403)

        origin = request.headers.get("origin")
        if origin:
            parsed_origin = urlparse(origin)
            issuer_url = getattr(getattr(provider, "_config", None), "issuer_url", "")
            if issuer_url:
                issuer_parsed = urlparse(issuer_url)
                origin_host = (parsed_origin.hostname or "").lower()
                issuer_host = (issuer_parsed.hostname or "").lower()
                is_loopback = origin_host in {"localhost", "127.0.0.1", "::1"} and issuer_host in {
                    "localhost",
                    "127.0.0.1",
                    "::1",
                }
                if (
                    parsed_origin.scheme != issuer_parsed.scheme
                    or parsed_origin.netloc != issuer_parsed.netloc
                ) and not is_loopback:
                    logger.warning("Rejected cross-origin POST to /consent from origin: %s", origin)
                    return PlainTextResponse(
                        "Forbidden: Cross-origin request rejected\n", status_code=403
                    )

        form = await request.form()
        request_id = str(form.get("req", ""))
        consent_secret = str(form.get("consent_secret", ""))
        csrf_token = str(form.get("csrf", "")) if "csrf" in form else None

        try:
            redirect_url = await provider.approve_authorization(
                request_id, consent_secret, csrf_token=csrf_token
            )
        except AuthorizeError as exc:
            consent = await provider.pending_authorization(request_id)
            status = 403 if consent is not None else 400
            csrf = getattr(consent, "csrf_token", None) if consent is not None else None
            return HTMLResponse(
                _consent_html(
                    provider.client_name,
                    request_id,
                    csrf,
                    f"Approval failed: {exc.error_description or exc.error}",
                ),
                status_code=status,
            )

        logger.info("Consent granted; redirecting to the client")
        return RedirectResponse(redirect_url, status_code=302)

    return page, submit


def _root_probe_endpoint(mcp: MCPServer[Any]) -> Any:
    """Answer Spark's probes of the origin root.

    Spark treats the URL as a single Streamable-HTTP endpoint and probes the
    origin root before it will talk to ``/mcp``. Two cases matter:

    - **No token** — a bare 404 gives the client nothing to work with. Return the
      same 401 challenge the MCP endpoint gives, carrying the ``resource_metadata``
      pointer, so discovery starts immediately.
    - **With a valid token** — Spark re-probes the root mid-session as a health
      check, reusing the token it already holds. Answering 401 there tells it the
      server it just connected to is no longer valid, so a presented token has to
      be verified rather than ignored.
    """

    async def probe(request: Any) -> Response:
        settings = getattr(mcp, "settings", None)
        auth_settings = getattr(settings, "auth", None)
        if auth_settings is None:
            return Response(status_code=200)

        if await _request_has_valid_token(mcp, request):
            return Response(status_code=200)

        resource_url = str(auth_settings.resource_server_url).rstrip("/")
        metadata_url = f"{resource_url}/.well-known/oauth-protected-resource"
        return Response(
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer error="unauthorized", resource_metadata="{metadata_url}"'
                )
            },
        )

    return probe


async def _request_has_valid_token(mcp: MCPServer[Any], request: Any) -> bool:
    """True when the request carries a bearer token this server issued.

    Uses the SDK's own token verifier, which ``MCPServer`` builds from the
    authorization server provider when one is configured — the same check the MCP
    endpoints apply, so the root probe can never disagree with them.
    """
    header = request.headers.get("authorization", "") if hasattr(request, "headers") else ""
    if not header.lower().startswith("bearer "):
        return False

    verifier = getattr(mcp, "_token_verifier", None)
    if verifier is None:
        return False

    try:
        info = await verifier.verify_token(header[7:].strip())
    except Exception:  # noqa: BLE001 - a malformed token must simply not authenticate
        logger.warning("Root probe presented a token that failed verification", exc_info=True)
        return False

    if info is None:
        return False

    expires_at = getattr(info, "expires_at", None)
    if expires_at is not None and expires_at < int(time.time()):
        return False

    return True


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
    oauth_provider: Any | None = None,
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
        bearer_token: When set, require this static bearer token on all requests
            except ``/health`` and the OAuth resource-metadata probe.
        host: Origin host used for the transport-security policy. The public
            hostname differs (it is the tunnel's), so DNS-rebinding protection is
            disabled and left to the proxy layer.
        oauth_provider: The OAuth provider, when OAuth is configured. Required for
            the approval page: without it ``/authorize`` parks a request that
            nothing can approve, so no token can ever be issued.

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
    auth_settings = getattr(getattr(mcp, "settings", None), "auth", None)
    auth_configured = auth_settings is not None
    if not auth_configured:
        routes.insert(
            0,
            Route(
                f"{OAUTH_METADATA_PREFIX}{{rest:path}}",
                _oauth_metadata_endpoint,
                methods=["GET"],
            ),
        )
    else:
        # Shadow the SDK's authorization-server metadata document. Its version
        # advertises only the secret-based token endpoint auth methods, and Spark
        # is a public client — it rejects the server outright with "uses an
        # authentication method that Gemini doesn't support". Registered first so
        # Starlette matches this route before the SDK's.
        routes.insert(
            0,
            Route(
                "/.well-known/oauth-authorization-server",
                _json_endpoint(authorization_server_metadata(auth_settings)),
                methods=["GET", "OPTIONS"],
            ),
        )
        # Spark asks for OIDC discovery in addition to the RFC 8414 document. The
        # SDK registers only the latter, so this path 404s and Spark rejects the
        # URL with "This isn't a valid MCP link" during validation — before it
        # ever registers a client. RFC 8414 §5 explicitly permits serving the
        # authorization-server metadata at the OIDC well-known location, and this
        # server issues no id_tokens, so no OIDC-only field is advertised.
        routes.insert(
            0,
            Route(
                "/.well-known/openid-configuration",
                _json_endpoint(authorization_server_metadata(auth_settings)),
                methods=["GET", "OPTIONS"],
            ),
        )
        # RFC 9728 §3.1 also allows the resource's own path to be appended to the
        # well-known prefix, and MCP clients try that form when the MCP endpoint
        # URL is used as the resource identifier. The SDK registers only the bare
        # prefix, so answer any suffixed path with the same document. Anchored to
        # a trailing segment so the SDK's bare-prefix route is left untouched.
        routes.insert(
            0,
            Route(
                f"{OAUTH_METADATA_PREFIX}/{{rest:path}}",
                _json_endpoint(protected_resource_metadata(auth_settings)),
                methods=["GET", "OPTIONS"],
            ),
        )
        # Spark probes the origin root with HEAD before it will talk to the MCP
        # endpoint. Answer with the same 401 challenge the MCP endpoint gives, so
        # the probe carries the resource_metadata pointer instead of a bare 404.
        routes.insert(0, Route("/", _root_probe_endpoint(mcp), methods=["HEAD", "GET"]))

        # The approval page. Without it the authorization endpoint parks a request
        # that nothing can approve, so refuse to start rather than serve a server
        # that silently cannot issue a token.
        if oauth_provider is None:
            raise ValueError(
                "OAuth is configured on the MCP server but no oauth_provider was passed "
                "to build_asgi_app: the approval page would be missing and no client "
                "could ever complete the flow."
            )
        consent_page, consent_submit = _consent_endpoints(oauth_provider)
        routes.insert(0, Route("/consent", consent_page, methods=["GET"]))
        routes.insert(0, Route("/consent", consent_submit, methods=["POST"]))
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
        mcp_lifespan_fn = getattr(getattr(mcp, "settings", None), "lifespan", None)

        @asynccontextmanager
        async def _run_mcp() -> AsyncIterator[None]:
            if mcp_lifespan_fn is not None:
                async with mcp_lifespan_fn(mcp):
                    yield
            else:
                yield

        @asynccontextmanager
        async def _run_http() -> AsyncIterator[None]:
            if http_router is not None:
                async with http_router.lifespan_context(app):
                    yield
            else:
                yield

        try:
            async with _run_mcp():
                async with _run_http():
                    yield
        finally:
            if oauth_provider is not None and hasattr(oauth_provider, "aclose"):
                try:
                    await oauth_provider.aclose()
                except Exception:
                    logger.warning("Error draining OAuth provider on shutdown", exc_info=True)

    if bearer_token is not None and not bearer_token.strip():
        raise ValueError(
            "bearer_token was provided but is empty; pass None to disable authentication "
            "or supply a non-empty token"
        )

    app: ASGIApp = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)

    if bearer_token:
        app = BearerAuthMiddleware(app, bearer_token)

    if _env_flag("X_SEARCH_DEBUG_AUTH"):
        app = AuthDebugMiddleware(app)
        logger.warning(
            "OAuth request-shape logging is ON (X_SEARCH_DEBUG_AUTH); secret fields "
            "are logged as <present> only"
        )

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
    oauth_provider: Any | None = None,
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
        oauth_provider=oauth_provider,
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
