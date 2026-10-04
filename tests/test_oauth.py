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
from dataclasses import replace
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
#: Spark completes the flow at Google's own callback origin, which is the only
#: origin registrations are accepted from.
REDIRECT_URI = "https://oauth-redirect.googleusercontent.com/r/spark-test"
OFF_ORIGIN_REDIRECT_URI = "https://evil.example.test/cb"
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
    with _client_for(oauth_config, provider) as test_client:
        yield test_client


def _client_for(config: OAuthConfig, provider: XSearchOAuthProvider | None = None) -> TestClient:
    """Build a TestClient around a fresh server for the given OAuth config."""
    server = MCPServer(
        "x-search",
        lifespan=server_lifespan,
        auth=build_auth_settings(config),
        auth_server_provider=provider or XSearchOAuthProvider(config),
    )
    return TestClient(build_asgi_app(server, stateless_http=True))


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


def test_authorization_server_metadata_advertises_public_client_and_dcr(
    client: TestClient,
) -> None:
    """The two fields Spark actually gates on.

    ``token_endpoint_auth_methods_supported`` must include ``none`` (Spark is a
    public client) and ``registration_endpoint`` must be present, or Spark refuses
    the server with "uses an authentication method that Gemini doesn't support".
    """
    response = client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    body = response.json()
    assert body["issuer"].rstrip("/") == ISSUER
    assert body["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert body["token_endpoint"] == f"{ISSUER}/token"
    assert body["registration_endpoint"] == f"{ISSUER}/register"
    assert body["token_endpoint_auth_methods_supported"] == ["none"]
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


def test_public_client_exchanges_code_without_a_secret(client: TestClient) -> None:
    """Spark sends no client_secret — PKCE is the only proof it needs.

    Real Spark token requests carry client_id, code, code_verifier and
    redirect_uri, and nothing else. A server that demands a secret fails the
    exchange with a 401 and Spark reports "account linking is required".
    """
    verifier, challenge = _pkce_pair()
    code = _authorize(client, challenge)

    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["access_token"]


def test_confidential_client_must_still_present_its_secret(
    oauth_config: OAuthConfig, tmp_path: Path
) -> None:
    """The public default must not break operators who configure a real secret."""
    config = replace(oauth_config, token_auth_method="client_secret_post")
    with _client_for(config) as confidential:
        verifier, challenge = _pkce_pair()
        code = _authorize(confidential, challenge)

        without_secret = confidential.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert without_secret.status_code == 401

        verifier2, challenge2 = _pkce_pair()
        code2 = _authorize(confidential, challenge2)
        with_secret = confidential.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code2,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code_verifier": verifier2,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert with_secret.status_code == 200


def test_sparks_real_redirect_uris_are_accepted(
    client: TestClient, provider: XSearchOAuthProvider
) -> None:
    """Regression: Spark sends six URIs across three googleusercontent hosts.

    The earlier allow-list named only ``oauth-redirect.googleusercontent.com``, so
    the sandbox and test hosts were rejected, Dynamic Client Registration returned
    400, and Spark fell back to the manual credentials path.
    """
    spark_uris = [
        f"https://oauth-redirect{env}.googleusercontent.com/r/user_bound_custom-mcp-1-x"
        for env in ("-sandbox", "-test", "")
    ] + [
        f"https://oauth-redirect{env}.googleusercontent.com/a/user_bound_custom-mcp-1-x"
        for env in ("-sandbox", "-test", "")
    ]

    response = client.post(
        "/register",
        json={
            "client_name": "Google",
            "redirect_uris": spark_uris,
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert response.status_code == 201, response.text
    client_id = response.json()["client_id"]
    assert provider._clients[client_id].client_secret is None

    # And each of those URIs must also survive authorization-time validation.
    _, challenge = _pkce_pair()
    for uri in spark_uris:
        authorize = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302, (uri, authorize.text)


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


def test_allowed_origin_redirect_uri_is_accepted(client: TestClient) -> None:
    """Any path on a trusted client origin is fine — Spark's callback varies."""
    _, challenge = _pkce_pair()

    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "https://oauth-redirect.googleusercontent.com/r/other",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"].startswith(
        "https://oauth-redirect.googleusercontent.com/r/other"
    )


def test_off_origin_redirect_uri_is_rejected(client: TestClient) -> None:
    """A code must never be delivered to an origin we do not trust."""
    _, challenge = _pkce_pair()

    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": OFF_ORIGIN_REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# ------------------------------------------------------- dynamic registration


def test_dynamic_registration_issues_a_public_client(
    client: TestClient, provider: XSearchOAuthProvider
) -> None:
    """Spark self-registers and the stored client is public, with no secret.

    The registration *response* may still carry a ``client_secret`` because the
    SDK issues one whenever the request does not ask for ``none``. What matters is
    the stored client: with no secret and method ``none``, the token endpoint
    ignores any secret the client sends, so a public client authenticates on PKCE
    alone either way.
    """
    response = client.post(
        "/register",
        json={
            "client_name": "Google",
            "redirect_uris": [
                REDIRECT_URI,
                "https://oauth-redirect.googleusercontent.com/r/other",
            ],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )

    assert response.status_code == 201, response.text
    client_id = response.json()["client_id"]

    stored = provider._clients[client_id]
    assert stored.client_secret is None
    assert stored.token_endpoint_auth_method == "none"


def test_dynamic_registration_rejects_off_origin_redirect_uris(client: TestClient) -> None:
    """Open registration must not become an open redirector."""
    response = client.post(
        "/register",
        json={"client_name": "Not Google", "redirect_uris": [OFF_ORIGIN_REDIRECT_URI]},
    )

    assert response.status_code == 400


def test_dynamic_registration_requires_redirect_uris(client: TestClient) -> None:
    """A client with nowhere to send the code is useless; refuse it up front."""
    response = client.post("/register", json={"client_name": "Google"})

    assert response.status_code == 400


def test_registered_public_client_completes_the_whole_flow(client: TestClient) -> None:
    """The end-to-end path Spark takes: register, authorize, PKCE token, MCP call."""
    registration = client.post(
        "/register",
        json={
            "client_name": "Google",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert registration.status_code == 201, registration.text
    client_id = registration.json()["client_id"]

    verifier, challenge = _pkce_pair()
    authorize = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "spark-1",
            "resource": ISSUER,
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 302, authorize.text
    code = authorize.headers["location"].split("code=", 1)[1].split("&", 1)[0]

    # A public client sends no client_secret — PKCE is the only proof.
    token_response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert token_response.status_code == 200, token_response.text
    access_token = token_response.json()["access_token"]

    call = client.post(
        "/mcp",
        json=INITIALIZE,
        headers={**JSON_HEADERS, "Authorization": f"Bearer {access_token}"},
    )

    assert call.status_code == 200
    assert '"name":"x-search"' in call.text


def test_root_head_probe_returns_the_auth_challenge(client: TestClient) -> None:
    """Spark probes HEAD / first; a bare 404 there gives it nothing to work with."""
    response = client.head("/")

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "resource_metadata=" in challenge
    assert challenge.startswith("Bearer")


def test_root_head_probe_succeeds_with_a_valid_token(client: TestClient) -> None:
    """Spark re-probes the root mid-session with the token it already holds.

    Answering 401 there makes it treat the server it just connected to as
    invalid — the probe has to verify a presented token rather than ignore it.
    """
    verifier, challenge = _pkce_pair()
    code = _authorize(client, challenge)
    tokens = _exchange(client, code, verifier)

    response = client.head("/", headers={"Authorization": f"Bearer {tokens['access_token']}"})

    assert response.status_code == 200


def test_root_head_probe_rejects_a_bogus_token(client: TestClient) -> None:
    """A token we did not issue must still get the challenge, not a pass."""
    response = client.head("/", headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]


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
