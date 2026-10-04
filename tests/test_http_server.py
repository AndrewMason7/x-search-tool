"""Tests for the HTTP/SSE hosting layer (``x_search.http_server``).

These exercise the ASGI application directly rather than binding a socket, so
they cover the parts that a reverse proxy cannot: the health probe, bearer-token
enforcement, the JSON-RPC handshake on the streamable transport, and the
configuration guards.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from mcp.server.mcpserver import MCPServer
from starlette.testclient import TestClient

from x_search.http_server import HEALTH_PATH, AuthDebugMiddleware, build_asgi_app
from x_search.server import server_lifespan


@pytest.fixture
def mcp() -> MCPServer:
    """A plain server with no OAuth configured.

    Built fresh rather than reusing the module singleton: the singleton is
    constructed at import time from the ambient environment, so a stray
    ``X_SEARCH_PUBLIC_URL`` in the shell would silently turn these tests into
    OAuth-enabled ones.
    """
    return MCPServer("x-search", lifespan=server_lifespan)


TOKEN = "test-bearer-token"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1"},
    },
}
JSON_HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def authed_client(mcp: MCPServer) -> Iterator[TestClient]:
    """A client for the dual-transport app with bearer auth enabled."""
    app = build_asgi_app(mcp, stateless_http=True, bearer_token=TOKEN)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def open_client(mcp: MCPServer) -> Iterator[TestClient]:
    """A client for the dual-transport app with no bearer auth."""
    app = build_asgi_app(mcp, stateless_http=True, bearer_token=None)
    with TestClient(app) as client:
        yield client


def test_health_is_public(authed_client: TestClient) -> None:
    """The health probe must answer without credentials so proxies can poll it."""
    response = authed_client.get(HEALTH_PATH)

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["server"] == "x-search"


def test_oauth_discovery_probe_is_public(authed_client: TestClient) -> None:
    """Clients probe RFC 9728 metadata before they have anywhere to put a token."""
    response = authed_client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    assert response.json() == {}


def test_streamable_http_rejects_missing_token(authed_client: TestClient) -> None:
    """An unauthenticated JSON-RPC call must be refused, not silently served."""
    response = authed_client.post("/mcp", json=INITIALIZE, headers=JSON_HEADERS)

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_streamable_http_rejects_wrong_token(authed_client: TestClient) -> None:
    """A near-miss token must not be accepted."""
    response = authed_client.post(
        "/mcp",
        json=INITIALIZE,
        headers={**JSON_HEADERS, "Authorization": f"Bearer {TOKEN}-nope"},
    )

    assert response.status_code == 401


def test_streamable_http_handshake_with_token(authed_client: TestClient) -> None:
    """With the correct token the initialize handshake returns server info."""
    response = authed_client.post(
        "/mcp",
        json=INITIALIZE,
        headers={**JSON_HEADERS, "Authorization": f"Bearer {TOKEN}"},
    )

    assert response.status_code == 200
    assert '"name":"x-search"' in response.text
    assert '"protocolVersion":"2025-06-18"' in response.text


def test_sse_transport_is_mounted(mcp: MCPServer) -> None:
    """The legacy HTTP+SSE stream must be mounted alongside streamable HTTP.

    Asserted structurally: an open SSE stream never completes, so reading one
    through the test client would block teardown. The live behaviour (200 +
    ``text/event-stream``) is covered against the deployed endpoint instead.
    """
    app = build_asgi_app(mcp, enable_streamable_http=True, enable_sse=True, bearer_token=None)
    paths = {getattr(route, "path", None) for route in app.routes}  # type: ignore[attr-defined]

    assert "/sse" in paths
    assert "/mcp" in paths


def test_streamable_only_mounts_no_sse(mcp: MCPServer) -> None:
    """A streamable-only deployment must not expose the SSE routes."""
    app = build_asgi_app(mcp, enable_streamable_http=True, enable_sse=False, bearer_token=None)
    paths = {getattr(route, "path", None) for route in app.routes}  # type: ignore[attr-defined]

    assert "/mcp" in paths
    assert "/sse" not in paths


def test_no_auth_configured_serves_requests(open_client: TestClient) -> None:
    """With no token configured the endpoint is open (reverse proxy owns auth)."""
    response = open_client.post("/mcp", json=INITIALIZE, headers=JSON_HEADERS)

    assert response.status_code == 200
    assert '"name":"x-search"' in response.text


def test_requires_at_least_one_transport(mcp: MCPServer) -> None:
    """Disabling every transport is a configuration error, not a silent no-op."""
    with pytest.raises(ValueError, match="At least one"):
        build_asgi_app(mcp, enable_streamable_http=False, enable_sse=False)


def test_rejects_colliding_paths(mcp: MCPServer) -> None:
    """A streamable path that shadows the SSE path must fail loudly at startup."""
    with pytest.raises(ValueError, match="collide"):
        build_asgi_app(mcp, streamable_http_path="/sse", sse_path="/sse")


def test_empty_bearer_token_is_rejected(mcp: MCPServer) -> None:
    """An empty token must fail loudly instead of silently disabling auth."""
    with pytest.raises(ValueError, match="empty"):
        build_asgi_app(mcp, bearer_token="")


def test_none_bearer_token_actually_disables_auth(mcp: MCPServer) -> None:
    """Passing None must let an unauthenticated request through.

    Asserting the behaviour rather than ``app is not None``: the old assertion
    could not fail for the reason it named.
    """
    with TestClient(build_asgi_app(mcp, stateless_http=True, bearer_token=None)) as client:
        response = client.post("/mcp", json=INITIALIZE, headers=JSON_HEADERS)

    assert response.status_code == 200


async def test_auth_debug_middleware_redacts_secrets() -> None:
    """The debug logger must reveal request shape without leaking credentials."""
    captured: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: captured.append(record.getMessage())  # type: ignore[method-assign]
    debug_logger = logging.getLogger("x_search.http")
    debug_logger.addHandler(handler)
    previous_level = debug_logger.level
    debug_logger.setLevel(logging.INFO)

    sent: list[dict] = []

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        await receive()  # the replayed body must still be readable downstream
        await send({"type": "http.response.start", "status": 400, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():  # type: ignore[no-untyped-def]
        return {
            "type": "http.request",
            "body": b"grant_type=authorization_code&client_id=abc&client_secret=top-secret",
            "more_body": False,
        }

    async def send(message):  # type: ignore[no-untyped-def]
        sent.append(message)

    try:
        middleware = AuthDebugMiddleware(inner)
        await middleware(
            {
                "type": "http",
                "method": "POST",
                "path": "/token",
                "query_string": b"",
                "headers": [(b"authorization", b"Basic YWJjOnNlY3JldA==")],
            },
            receive,
            send,
        )
    finally:
        debug_logger.removeHandler(handler)
        debug_logger.setLevel(previous_level)

    joined = " ".join(captured)
    assert "top-secret" not in joined
    assert "YWJjOnNlY3JldA==" not in joined
    assert "client_secret" in joined and "<present>" in joined
    assert "authorization_scheme" in joined and "Basic" in joined
    assert "-> 400" in joined
    assert sent and sent[0]["status"] == 400


async def test_auth_debug_middleware_rejects_payload_too_large() -> None:
    """The debug logger must terminate streams that exceed MAX_AUTH_BODY_BYTES."""
    sent: list[dict] = []

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        pass

    async def receive():  # type: ignore[no-untyped-def]
        return {
            "type": "http.request",
            "body": b"x" * 70000,
            "more_body": False,
        }

    async def send(message):  # type: ignore[no-untyped-def]
        sent.append(message)

    middleware = AuthDebugMiddleware(inner)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/token",
            "query_string": b"",
            "headers": [],
        },
        receive,
        send,
    )
    assert sent and sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_asgi_app_lifespan_cleans_up(mcp: MCPServer) -> None:
    """The lifespan context manager must gracefully enter and exit, invoking provider teardown."""
    from unittest.mock import AsyncMock

    mock_provider = AsyncMock()
    app = build_asgi_app(
        mcp,
        enable_streamable_http=True,
        bearer_token=None,
        oauth_provider=mock_provider,
    )

    with TestClient(app) as client:
        response = client.post("/mcp", json=INITIALIZE, headers=JSON_HEADERS)
        assert response.status_code == 200

    mock_provider.aclose.assert_awaited_once()

