# Architectural Blueprint: API Key Authentication for MCP HTTP Servers

This document serves as an engineering blueprint for adding robust, production-grade **API Key Authentication** to any Python MCP (Model Context Protocol) server running over HTTP and Server-Sent Events (SSE). It accounts for pure standalone servers as well as servers configured with OAuth 2.1 (RFC 8414 / RFC 9728) for Gemini Spark.

---

## 1. High-Level Architecture & The "OAuth Trap"

When implementing authentication on an MCP server using the official Python SDK (`mcp`), there are two operational modes to consider:

1. **Standalone Mode (No OAuth)**:
   The server only requires an API key or bearer token. A pure ASGI middleware wrapped around the root Starlette application intercepts every request and validates the credential.

2. **OAuth 2.1 Coexistence Mode (e.g. Gemini Spark)**:
   When `settings.auth` is configured on `MCPServer`, the SDK mounts:
   - `AuthenticationMiddleware` with `BearerAuthBackend(token_verifier)`
   - `RequireAuthMiddleware` on `/mcp` and `/sse` routes

### The "OAuth Trap"
If you simply wrap an outer ASGI middleware around a server with OAuth enabled, two critical bugs emerge:
- **Outer Failure**: When Gemini Spark connects with an OAuth bearer token, your outer API key middleware rejects it with `401` because it is not in your static API keys list.
- **Inner Failure**: When a client sends a valid API key, your outer middleware lets it through, but Starlette's inner `AuthenticationMiddleware` does not recognize `X-API-Key` or `?api_key=`, leaving `scope["user"] = UnauthenticatedUser()`. Then the SDK's `RequireAuthMiddleware` immediately rejects the API key with `401 {"error": "invalid_token", "error_description": "Authentication required"}`.

### The Solution: Dual-Layer Architecture
- **In Standalone Mode**: Protect the app with **`ApiKeyAuthMiddleware`** (pure ASGI).
- **In OAuth Mode**: Wrap Starlette's inner `AuthenticationMiddleware` backend with **`ApiKeyAndBearerAuthBackend`**. If an API key is present, it synthesizes an `AuthenticatedUser` with the required scopes; if not, it seamlessly delegates to the OAuth `BearerAuthBackend`.

```
Incoming Request
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ Standalone Mode? (No OAuth configured)                 │
│  └─► ApiKeyAuthMiddleware (Pure ASGI)                  │
│       ├─► Valid API Key? ────► Pass to MCP Handlers    │
│       └─► Invalid/None? ─────► HTTP 401 Unauthorized   │
└────────────────────────────────────────────────────────┘
       │
       ▼ (OAuth Mode Configured)
┌────────────────────────────────────────────────────────┐
│ OAuth Coexistence Mode                                 │
│  └─► ApiKeyAndBearerAuthBackend                        │
│       ├─► Valid API Key? ────► Synthesize AuthenticatedUser
│       │                        (Scopes granted, admitted)
│       ├─► OAuth Bearer Token? ─► Verify via TokenVerifier
│       │                          (Admitted if valid)
│       └─► Neither? ──────────► RequireAuthMiddleware   │
│                                  (HTTP 401 + RFC 9728) │
└────────────────────────────────────────────────────────┘
```

---

## 2. Supported Credential Vectors

To maximize interoperability with diverse MCP clients (CLI tools, curl, web proxies, and browser EventSource), always accept credentials in three locations:

1. **`X-API-Key: <key>` header**: Standard de-facto header for REST/RPC APIs.
2. **`Authorization` header**:
   - `Authorization: Bearer <key>`
   - `Authorization: Api-Key <key>`
   - `Authorization: ApiKey <key>`
3. **URL Query Parameter `?api_key=<key>`**:
   *Crucial* for Server-Sent Events (SSE). Browsers using the native `EventSource` API cannot set custom request headers; query parameters allow SSE streams to authenticate seamlessly.

---

## 3. Drop-in Code Components

### Component 1: `ApiKeyAuthMiddleware` (Pure ASGI for Standalone Mode)

> **Important**: Never use Starlette's `BaseHTTPMiddleware` here. `BaseHTTPMiddleware` buffers response streams, which breaks real-time Server-Sent Events (SSE). Always write raw ASGI middleware (`async def __call__(scope, receive, send)`).

```python
import secrets
from collections.abc import Iterable
from urllib.parse import parse_qs
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

HEALTH_PATH = "/health"
OAUTH_METADATA_PREFIX = "/.well-known/oauth-protected-resource"
_HEADER_LOOKUP_KEY = b"authorization"
_X_API_KEY_HEADER = b"x-api-key"

def _header_value(scope: Scope, name: bytes) -> bytes | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value
    return None

class ApiKeyAuthMiddleware:
    """Require an API key or bearer token on every request (Pure ASGI)."""

    def __init__(
        self,
        app: ASGIApp,
        api_keys: Iterable[str] | str,
        exempt_paths: Iterable[str] = (HEALTH_PATH,),
    ) -> None:
        if isinstance(api_keys, str):
            raw_keys = [k.strip() for k in api_keys.split(",")]
        else:
            raw_keys = [k.strip() if isinstance(k, str) else "" for k in api_keys]

        clean_keys = [k.encode("utf-8") for k in raw_keys if k]
        if not clean_keys:
            raise ValueError("ApiKeyAuthMiddleware requires at least one non-empty API key")

        self.app = app
        self._valid_keys = tuple(clean_keys)
        self._exempt = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Always allow health checks and OAuth discovery probes through unauthenticated
        if path in self._exempt or path.startswith(OAUTH_METADATA_PREFIX):
            await self.app(scope, receive, send)
            return

        candidates: list[bytes] = []

        # 1. Header: X-API-Key
        x_api_key = _header_value(scope, _X_API_KEY_HEADER)
        if x_api_key is not None:
            candidates.append(x_api_key.strip())

        # 2. Header: Authorization (Bearer, Api-Key, ApiKey)
        auth = _header_value(scope, _HEADER_LOOKUP_KEY)
        if auth is not None:
            parts = auth.split(b" ", 1)
            if len(parts) == 2 and parts[0].lower() in (b"bearer", b"api-key", b"apikey"):
                candidates.append(parts[1].strip())

        # 3. Query Parameter: ?api_key= (or ?apiKey= / ?key=)
        query_string = scope.get("query_string", b"")
        if query_string:
            query_params = parse_qs(query_string.decode("latin1", errors="replace"))
            for param in ("api_key", "apiKey", "key"):
                vals = query_params.get(param)
                if vals and vals[0].strip():
                    candidates.append(vals[0].strip().encode("utf-8"))

        authenticated = False
        for candidate in candidates:
            for expected in self._valid_keys:
                # Constant-time comparison prevents timing attacks
                if secrets.compare_digest(candidate, expected):
                    authenticated = True
                    break
            if authenticated:
                break

        if not authenticated:
            response = PlainTextResponse(
                "Unauthorized\n",
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="mcp-server"'},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
```

---

### Component 2: `ApiKeyAndBearerAuthBackend` (Starlette Backend for OAuth Mode)

When OAuth is enabled, replace or wrap the inner `AuthenticationMiddleware` backend:

```python
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.authentication import AuthCredentials, AuthenticationBackend, SimpleUser
from starlette.requests import HTTPConnection

class ApiKeyAndBearerAuthBackend(AuthenticationBackend):
    """Authentication backend accepting API keys with fallback to OAuth Bearer tokens."""

    def __init__(
        self,
        inner_backend: AuthenticationBackend | None,
        valid_keys: tuple[bytes, ...],
        scopes: list[str],
    ) -> None:
        self.inner_backend = inner_backend
        self._valid_keys = valid_keys
        self._scopes = scopes

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, SimpleUser] | None:
        candidates: list[bytes] = []

        # 1. Header: X-API-Key
        x_api_key = conn.headers.get("x-api-key")
        if x_api_key:
            candidates.append(x_api_key.strip().encode("utf-8"))

        # 2. Header: Authorization
        auth = conn.headers.get("authorization")
        if auth:
            parts = auth.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() in ("bearer", "api-key", "apikey"):
                candidates.append(parts[1].strip().encode("utf-8"))

        # 3. Query Parameter: ?api_key=
        if conn.query_params:
            for param in ("api_key", "apiKey", "key"):
                val = conn.query_params.get(param)
                if val and val.strip():
                    candidates.append(val.strip().encode("utf-8"))

        # Constant-time API key verification
        for candidate in candidates:
            for expected in self._valid_keys:
                if secrets.compare_digest(candidate, expected):
                    auth_info = AccessToken(
                        token=candidate.decode("utf-8", errors="replace"),
                        client_id="api-key",
                        scopes=self._scopes,
                    )
                    # Satisfies RequireAuthMiddleware
                    return AuthCredentials(self._scopes), AuthenticatedUser(auth_info)

        # Fall back to OAuth Bearer token verification if no API key matched
        if self.inner_backend is not None:
            return await self.inner_backend.authenticate(conn)

        return None
```

---

## 4. Application Assembly (`build_asgi_app`)

In your ASGI application builder:

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware

def build_asgi_app(
    mcp: MCPServer,
    *,
    bearer_token: str | None = None,
    api_keys: Iterable[str] | str | None = None,
    # ... other options ...
) -> ASGIApp:
    auth_settings = getattr(getattr(mcp, "settings", None), "auth", None)
    auth_configured = auth_settings is not None

    # 1. Resolve and validate keys
    resolved_keys: list[str] = []
    if bearer_token:
        if not bearer_token.strip():
            raise ValueError("bearer_token was provided but is empty")
        resolved_keys.append(bearer_token.strip())

    if api_keys is not None:
        if isinstance(api_keys, str):
            parsed_keys = [k.strip() for k in api_keys.split(",")]
        else:
            parsed_keys = [k.strip() if isinstance(k, str) else "" for k in api_keys]
        non_empty = [k for k in parsed_keys if k]
        if not non_empty:
            raise ValueError("api_keys was provided but is empty")
        resolved_keys.extend(non_empty)

    # 2. Extract SDK middleware from sub-apps
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

            # If OAuth is enabled and API keys are configured, adapt AuthenticationMiddleware
            if key == "AuthenticationMiddleware" and resolved_keys:
                original_backend = entry.kwargs.get("backend")
                scopes = getattr(auth_settings, "required_scopes", None) or ["read", "write"]
                clean_bytes = tuple(k.encode("utf-8") for k in resolved_keys)
                entry = Middleware(
                    entry.cls,
                    backend=ApiKeyAndBearerAuthBackend(original_backend, clean_bytes, scopes),
                )
            middleware.append(entry)

    app = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)

    # 3. If standalone mode (no OAuth), wrap with outer ApiKeyAuthMiddleware
    if resolved_keys and not auth_configured:
        app = ApiKeyAuthMiddleware(app, resolved_keys)

    return app
```

---

## 5. CLI & Configuration Integration

Add `--api-key` to your argument parser and support environment variable fallback:

```python
parser.add_argument(
    "--api-key",
    action="append",
    default=None,
    help=(
        "Require an API key on all HTTP requests except /health. "
        "Accepted via 'X-API-Key' header, 'Authorization: Bearer <key>', "
        "'Authorization: Api-Key <key>', or '?api_key=<key>' query param. "
        "Can be specified multiple times or as comma-separated values. "
        "Defaults to $MCP_API_KEY."
    ),
)
```

In `main()`:

```python
api_keys: list[str] | None = None
if args.api_key is not None:
    api_keys = []
    for k in args.api_key:
        for sub in k.split(","):
            api_keys.append(sub.strip())
elif os.getenv("MCP_API_KEY") is not None:
    api_keys = [sub.strip() for sub in os.environ["MCP_API_KEY"].split(",")]
```

And in `.env.example`:
```bash
# API key authentication (supports single or comma-separated keys).
# Accepted via 'X-API-Key' header, 'Authorization: Bearer <key>',
# 'Authorization: Api-Key <key>', or '?api_key=<key>' query parameter.
# MCP_API_KEY=your_api_key_here
```

---

## 6. Comprehensive Test Checklist

When implementing this pattern on a new MCP server, create tests for:

| Test Case | Scenario / Expected Outcome |
|-----------|-----------------------------|
| `test_empty_api_key_is_rejected` | `api_keys=""`, `api_keys=[]`, or `api_keys=[" "]` raises `ValueError`. |
| `test_x_api_key_header` | Request with valid `X-API-Key` returns 200; invalid returns 401. |
| `test_authorization_header_schemes` | `Bearer <key>`, `Api-Key <key>`, and `ApiKey <key>` all return 200. |
| `test_query_param_auth` | `?api_key=<key>` on POST/GET returns 200 without headers. |
| `test_multiple_keys_supported` | Key rotation: both `key1` and `key2` authenticate. |
| `test_comma_separated_parsing` | Passing `"key1, key2"` string works identically to `["key1", "key2"]`. |
| `test_public_routes_unauthenticated` | `/health` and `/.well-known/oauth-protected-resource` remain 200 without keys. |
| `test_oauth_coexistence` | When OAuth is active, API keys authenticate **AND** OAuth tokens authenticate; invalid keys receive OAuth challenge. |
| `test_cli_argument_parsing` | Passing `--api-key k1 --api-key k2,k3` correctly resolves to `["k1", "k2", "k3"]`. |
