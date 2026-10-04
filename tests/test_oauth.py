"""End-to-end tests for the OAuth authorization server (``x_search.oauth``).

Gemini Spark will not accept an MCP endpoint that cannot answer OAuth discovery,
so these walk the whole flow the way a real client does: discovery, an
authorization request with PKCE, the token exchange, and an authenticated
JSON-RPC call — plus the failure modes that must stay closed.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest
from mcp.server.mcpserver import MCPServer
from starlette.testclient import TestClient

from x_search.http_server import build_asgi_app
from x_search.oauth import (
    OAuthConfig,
    XSearchOAuthProvider,
    build_auth_settings,
)
from x_search.server import server_lifespan

ISSUER = "https://xsearch.example.test"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
REDIRECT_URI = "https://gemini.google.com/oauth/callback"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "spark-simulator", "version": "1"},
    },
}
JSON_HEADERS = {"Accept": "application/json, text/event-stream"}


def _pkce_pair() -> tuple[str, str]:
    """Return a (verifier, S256 challenge) pair."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def oauth_config(tmp_path: Path) -> OAuthConfig:
    return OAuthConfig(
        issuer_url=ISSUER,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        store_path=tmp_path / "oauth.json",
    )


@pytest.fixture
def provider(oauth_config: OAuthConfig) -> XSearchOAuthProvider:
    return XSearchOAuthProvider(oauth_config)


@pytest.fixture
def client(oauth_config: OAuthConfig, provider: XSearchOAuthProvider) -> Iterator[TestClient]:
    server = MCPServer(
        "x-search",
        lifespan=server_lifespan,
        auth=build_auth_settings(oauth_config),
        auth_server_provider=provider,
    )
    with TestClient(build_asgi_app(server, stateless_http=True)) as test_client:
        yield test_client


def _authorize(client: TestClient, challenge: str, state: str = "st-1") -> str:
    """Run the authorization request and return the issued code."""
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(REDIRECT_URI)
    assert f"state={state}" in location
    assert f"iss={ISSUER}" in location or "iss=https%3A%2F%2Fxsearch.example.test" in location
    return location.split("code=", 1)[1].split("&", 1)[0]


def _exchange(client: TestClient, code: str, verifier: str, secret: str = CLIENT_SECRET) -> dict:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": secret,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------- discovery


def test_protected_resource_points_at_our_authorization_server(client: TestClient) -> None:
    """RFC 9728 metadata must name us as the authorization server, not say "none"."""
    response = client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    body = response.json()
    # pydantic normalises a bare origin to include a trailing slash.
    assert [s.rstrip("/") for s in body["authorization_servers"]] == [ISSUER]
    assert body["resource"].rstrip("/") == ISSUER


def test_authorization_server_metadata_has_endpoints_but_no_registration(
    client: TestClient,
) -> None:
    """DCR stays off so clients fall back to the pre-registered credentials."""
    response = client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    body = response.json()
    assert body["issuer"].rstrip("/") == ISSUER
    assert body["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert body["token_endpoint"] == f"{ISSUER}/token"
    assert "registration_endpoint" not in body
    assert "S256" in body["code_challenge_methods_supported"]


def test_mcp_endpoint_challenges_with_resource_metadata(client: TestClient) -> None:
    """An unauthenticated call must point the client at the discovery document."""
    response = client.post("/mcp", json=INITIALIZE, headers=JSON_HEADERS)

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer")
    assert "resource_metadata=" in challenge


# ------------------------------------------------------------------------- flow


def test_full_authorization_code_flow(client: TestClient) -> None:
    """Discovery -> authorize -> token -> authenticated MCP call."""
    verifier, challenge = _pkce_pair()
    code = _authorize(client, challenge)
    tokens = _exchange(client, code, verifier)

    assert tokens["token_type"] == "Bearer"
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["expires_in"] == 3600

    response = client.post(
        "/mcp",
        json=INITIALIZE,
        headers={**JSON_HEADERS, "Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    assert '"name":"x-search"' in response.text


def test_authorization_code_is_single_use(client: TestClient) -> None:
    """A replayed code must not mint a second token."""
    verifier, challenge = _pkce_pair()
    code = _authorize(client, challenge)
    _exchange(client, code, verifier)

    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )

    assert response.status_code == 400


def test_wrong_client_secret_is_rejected(client: TestClient) -> None:
    """The client secret is the authorization decision; a wrong one must fail."""
    verifier, challenge = _pkce_pair()
    code = _authorize(client, challenge)

    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": "not-the-secret",
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )

    assert response.status_code == 401


def test_wrong_pkce_verifier_is_rejected(client: TestClient) -> None:
    """PKCE must actually be enforced, not just advertised."""
    _, challenge = _pkce_pair()
    code = _authorize(client, challenge)

    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": secrets.token_urlsafe(64),
            "redirect_uri": REDIRECT_URI,
        },
    )

    assert response.status_code == 400


def test_refresh_token_rotates(client: TestClient) -> None:
    """A refresh grant returns a new access token and invalidates the old one."""
    verifier, challenge = _pkce_pair()
    tokens = _exchange(client, _authorize(client, challenge), verifier)

    response = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )

    assert response.status_code == 200
    refreshed = response.json()
    assert refreshed["access_token"] != tokens["access_token"]

    replayed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert replayed.status_code == 400


def test_bogus_access_token_is_rejected(client: TestClient) -> None:
    """An invented bearer token must not open the MCP endpoint."""
    response = client.post(
        "/mcp",
        json=INITIALIZE,
        headers={**JSON_HEADERS, "Authorization": "Bearer not-a-real-token"},
    )

    assert response.status_code == 401


def test_unknown_client_id_is_rejected(client: TestClient) -> None:
    """Only the configured client exists; anything else is a 400, not a redirect."""
    _, challenge = _pkce_pair()

    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "someone-elses-client",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# ------------------------------------------------------------------ redirects


def test_https_redirect_uri_is_accepted(client: TestClient) -> None:
    """Spark's Google-hosted callback is not pinned, so any https URI is allowed."""
    _, challenge = _pkce_pair()

    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "https://some.other.origin/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://some.other.origin/cb")


def test_plain_http_redirect_uri_is_rejected(client: TestClient) -> None:
    """Authorization codes must never be delivered over plaintext."""
    _, challenge = _pkce_pair()

    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://evil.example.test/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# -------------------------------------------------------------------- config


def test_config_requires_https_issuer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A mismatched issuer would produce tokens no client can validate."""
    monkeypatch.setenv("X_SEARCH_PUBLIC_URL", "http://not-secure.example.test")
    monkeypatch.setenv("X_SEARCH_OAUTH_STORE", str(tmp_path / "oauth.json"))

    with pytest.raises(ValueError, match="https"):
        OAuthConfig.from_env()


def test_config_is_absent_without_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """No public URL means no OAuth layer at all, keeping stdio deployments simple."""
    monkeypatch.delenv("X_SEARCH_PUBLIC_URL", raising=False)

    assert OAuthConfig.from_env() is None


def test_client_credentials_persist_across_restarts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regenerating credentials on restart would silently break a live connection."""
    store = tmp_path / "oauth.json"
    monkeypatch.setenv("X_SEARCH_PUBLIC_URL", ISSUER)
    monkeypatch.setenv("X_SEARCH_OAUTH_STORE", str(store))

    first = OAuthConfig.from_env()
    second = OAuthConfig.from_env()

    assert first is not None and second is not None
    assert first.client_id == second.client_id
    assert first.client_secret == second.client_secret
    assert store.exists()


def test_tokens_survive_a_provider_restart(oauth_config: OAuthConfig) -> None:
    """A systemd restart must not log the connected client out."""
    first = XSearchOAuthProvider(oauth_config)
    token = first._issue_tokens(first.pre_registered_client(), ["x-search"])

    second = XSearchOAuthProvider(oauth_config)

    assert second._access_tokens.get(token.access_token) is not None
    assert second._refresh_tokens.get(token.refresh_token or "") is not None
