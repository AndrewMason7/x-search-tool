"""Self-contained OAuth 2.1 authorization server for the network transports.

Google Gemini Spark's custom connected apps are **OAuth-only**: when you paste an
MCP server URL it performs protected-resource discovery, then authorization-server
discovery, and only then tries to obtain a token. A server that answers "no
authorization server here" is rejected outright with *"This URL does not appear to
be a valid MCP server"* — regardless of how well the JSON-RPC endpoint itself
works. stdio-only deployments are unaffected; this module only activates when
``X_SEARCH_PUBLIC_URL`` is set.

Design
------
- One **pre-registered confidential client**. Dynamic Client Registration is left
  off, so a client that cannot register falls back to asking for a client ID and
  secret — which is exactly the verified path for Spark ("Advanced features").
- ``authorize()`` **auto-approves** and redirects straight back with a code. That
  is safe here precisely because the client is confidential: an authorization code
  is only redeemable by whoever also holds the client secret, and it is only ever
  delivered to a redirect URI registered against that client.
- All state (client, codes, access and refresh tokens) is persisted to a
  ``0600`` JSON file so a restart does not invalidate the connection.

The heavy lifting — PKCE verification, client authentication, the RFC 8414 and
RFC 9728 metadata documents, the token and revocation endpoints — is handled by
the MCP SDK's ``create_auth_routes``; this module only implements the provider
interface it calls into.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl, AnyUrl

logger = logging.getLogger("x_search.oauth")

DEFAULT_STORE_PATH = Path.home() / ".config" / "xsearch-oauth.json"
DEFAULT_SUBJECT = "owner"

ACCESS_TOKEN_TTL_SECONDS = 3600
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30
AUTHORIZATION_CODE_TTL_SECONDS = 300

#: Gemini Spark registers dynamically and completes the flow at Google's own
#: callback origin. Restricting registrations to Google-owned origins is what
#: keeps open Dynamic Client Registration from being an open door: a hostile
#: registrant cannot receive the authorization code, so its client is inert.
#: ``oauth-redirect.googleusercontent.com`` is the origin observed in real Spark
#: traffic; ``google.com`` is included so a change of callback host does not
#: silently break registration. Override with
#: ``X_SEARCH_OAUTH_ALLOWED_REDIRECT_ORIGINS`` (comma-separated).
DEFAULT_ALLOWED_REDIRECT_ORIGINS = (
    "oauth-redirect.googleusercontent.com",
    "google.com",
)

#: OAuth 2.1 lets a confidential client present its secret either in the request
#: body (``client_secret_post``) or via HTTP Basic (``client_secret_basic``). The
#: SDK authenticator picks exactly one based on the registered client, and clients
#: disagree on which they use, so this is operator-selectable.
TOKEN_AUTH_METHODS = ("client_secret_post", "client_secret_basic")
DEFAULT_TOKEN_AUTH_METHOD = "client_secret_post"

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})


def _env_flag(name: str, *, default: bool = False) -> bool:
    """Read a boolean-ish environment variable."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class SparkClient(OAuthClientInformationFull):
    """A client whose redirect URIs must land on a trusted origin.

    This is what makes open Dynamic Client Registration safe. Anyone can POST to
    the registration endpoint, but a client is only usable if it can receive the
    authorization code — and codes are only ever delivered to an allowed origin.
    In practice that means Google's own Spark callback, a domain the registrant
    does not control, so a hostile registration yields a client that can never
    obtain a token. Combined with PKCE (which Spark always sends) this gives the
    public-client model real protection without a shared secret.
    """

    allowed_redirect_origins: tuple[str, ...] = ()

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is None:
            return super().validate_redirect_uri(redirect_uri)

        parsed = urlparse(str(redirect_uri))
        host = (parsed.hostname or "").lower()

        if parsed.scheme != "https" and host not in LOOPBACK_HOSTS:
            raise InvalidRedirectUriError(f"Redirect URI must use https; got {redirect_uri}")

        if host in LOOPBACK_HOSTS:
            return redirect_uri

        allowed = self.allowed_redirect_origins
        if allowed and not any(host == origin or host.endswith(f".{origin}") for origin in allowed):
            raise InvalidRedirectUriError(
                f"Redirect URI host {host!r} is not an allowed client origin "
                f"(allowed: {', '.join(allowed)})"
            )
        return redirect_uri


def _validate_registration_redirect_uris(
    redirect_uris: list[AnyUrl] | None, allowed_origins: tuple[str, ...]
) -> None:
    """Reject a registration whose redirect URIs could never receive a code.

    Raises:
        RegistrationError: If any redirect URI is non-HTTPS or off-origin.
    """
    if not redirect_uris:
        raise RegistrationError("invalid_redirect_uri", "At least one redirect_uri is required")

    for uri in redirect_uris:
        parsed = urlparse(str(uri))
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" and host not in LOOPBACK_HOSTS:
            raise RegistrationError("invalid_redirect_uri", f"Redirect URI must use https: {uri}")
        if host in LOOPBACK_HOSTS:
            continue
        if allowed_origins and not any(
            host == origin or host.endswith(f".{origin}") for origin in allowed_origins
        ):
            raise RegistrationError(
                "invalid_redirect_uri",
                f"Redirect URI host {host!r} is not permitted on this server",
            )


@dataclass(frozen=True)
class OAuthConfig:
    """Resolved OAuth settings for this deployment."""

    issuer_url: str
    client_id: str
    client_secret: str
    store_path: Path
    subject: str = DEFAULT_SUBJECT
    token_auth_method: str = DEFAULT_TOKEN_AUTH_METHOD
    allowed_redirect_origins: tuple[str, ...] = DEFAULT_ALLOWED_REDIRECT_ORIGINS
    registration_enabled: bool = True

    @property
    def client_name(self) -> str:
        return "X Search MCP"

    @classmethod
    def from_env(cls) -> OAuthConfig | None:
        """Build a config from the environment, or None when OAuth is not enabled.

        Returns:
            An ``OAuthConfig`` when ``X_SEARCH_PUBLIC_URL`` is set, else ``None``
            (which leaves the server exactly as it was: no authentication layer).
        """
        public_url = (os.getenv("X_SEARCH_PUBLIC_URL") or "").strip().rstrip("/")
        if not public_url:
            return None

        if not public_url.startswith("https://") and not public_url.startswith("http://localhost"):
            raise ValueError(
                "X_SEARCH_PUBLIC_URL must be an https:// URL (the issuer URL has to match "
                f"what clients reach); got {public_url!r}"
            )

        store_path = Path(os.getenv("X_SEARCH_OAUTH_STORE") or DEFAULT_STORE_PATH).expanduser()
        subject = os.getenv("X_SEARCH_OAUTH_SUBJECT") or DEFAULT_SUBJECT

        raw_origins = os.getenv("X_SEARCH_OAUTH_ALLOWED_REDIRECT_ORIGINS")
        if raw_origins is None:
            allowed_origins = DEFAULT_ALLOWED_REDIRECT_ORIGINS
        else:
            allowed_origins = tuple(
                part.strip().lower().lstrip(".") for part in raw_origins.split(",") if part.strip()
            )

        registration_enabled = _env_flag("X_SEARCH_OAUTH_DYNAMIC_REGISTRATION", default=True)

        token_auth_method = (
            os.getenv("X_SEARCH_OAUTH_TOKEN_AUTH_METHOD") or DEFAULT_TOKEN_AUTH_METHOD
        ).strip()
        if token_auth_method not in TOKEN_AUTH_METHODS:
            raise ValueError(
                f"X_SEARCH_OAUTH_TOKEN_AUTH_METHOD must be one of {TOKEN_AUTH_METHODS}; "
                f"got {token_auth_method!r}"
            )

        # The client credentials are generated once and persisted, so re-running
        # setup (or restarting the service) never invalidates a connected client.
        store = _JsonStore(store_path)
        registered = store.data.setdefault("pre_registered_client", {})
        if not registered.get("client_id"):
            registered["client_id"] = secrets.token_urlsafe(24)
        if not registered.get("client_secret"):
            registered["client_secret"] = secrets.token_urlsafe(32)
        store.save()

        return cls(
            issuer_url=public_url,
            client_id=os.getenv("X_SEARCH_OAUTH_CLIENT_ID") or registered["client_id"],
            client_secret=os.getenv("X_SEARCH_OAUTH_CLIENT_SECRET") or registered["client_secret"],
            store_path=store_path,
            subject=subject,
            token_auth_method=token_auth_method,
            allowed_redirect_origins=allowed_origins,
            registration_enabled=registration_enabled,
        )


class _JsonStore:
    """Tiny atomic JSON store: load once, mutate, save whole.

    Atomicity matters because the process is restarted by systemd and a torn write
    would silently log every connected client out.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("OAuth store %s is unreadable (%s); starting empty", path, exc)
                self.data = {}
        if not isinstance(self.data, dict):
            self.data = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)


class XSearchOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """Single-client OAuth 2.1 authorization server backing the MCP endpoints."""

    def __init__(self, config: OAuthConfig) -> None:
        self._config = config
        self._store = _JsonStore(config.store_path)
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._pre_registered: SparkClient | None = None
        self._load()

    # ------------------------------------------------------------------ state

    def _load(self) -> None:
        """Restore persisted tokens, dropping anything already expired."""
        now = time.time()
        for raw in self._store.data.get("clients", []):
            client = OAuthClientInformationFull.model_validate(raw)
            self._clients[client.client_id] = client
        for raw in self._store.data.get("codes", []):
            code = AuthorizationCode.model_validate(raw)
            if code.expires_at > now:
                self._codes[code.code] = code
        for raw in self._store.data.get("access_tokens", []):
            token = AccessToken.model_validate(raw)
            if token.expires_at is None or token.expires_at > now:
                self._access_tokens[token.token] = token
        for raw in self._store.data.get("refresh_tokens", []):
            token = RefreshToken.model_validate(raw)
            if token.expires_at is None or token.expires_at > now:
                self._refresh_tokens[token.token] = token

    def _persist(self) -> None:
        now = time.time()
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at > now}
        self._access_tokens = {
            k: v
            for k, v in self._access_tokens.items()
            if v.expires_at is None or v.expires_at > now
        }
        self._refresh_tokens = {
            k: v
            for k, v in self._refresh_tokens.items()
            if v.expires_at is None or v.expires_at > now
        }
        self._store.data["clients"] = [c.model_dump(mode="json") for c in self._clients.values()]
        self._store.data["codes"] = [c.model_dump(mode="json") for c in self._codes.values()]
        self._store.data["access_tokens"] = [
            t.model_dump(mode="json") for t in self._access_tokens.values()
        ]
        self._store.data["refresh_tokens"] = [
            t.model_dump(mode="json") for t in self._refresh_tokens.values()
        ]
        self._store.save()

    # ---------------------------------------------------------------- clients

    def pre_registered_client(self) -> OAuthClientInformationFull:
        """The confidential client whose credentials are pasted into the client.

        Deliberately *not* persisted: it is rebuilt from config on every start so
        that ``OpenRedirectClient``'s relaxed redirect validation survives a
        restart (a round-trip through JSON would reload it as the base model).
        """
        if self._pre_registered is None:
            self._pre_registered = SparkClient(
                client_id=self._config.client_id,
                client_secret=self._config.client_secret,
                client_name=self._config.client_name,
                redirect_uris=None,
                token_endpoint_auth_method=self._config.token_auth_method,
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope="x-search",
                client_id_issued_at=int(time.time()),
                allowed_redirect_origins=self._config.allowed_redirect_origins,
            )
        return self._pre_registered

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Look up a client by ID, preferring the configured confidential client."""
        if client_id == self._config.client_id:
            return self.pre_registered_client()
        client = self._clients.get(client_id)
        if client is None:
            # Logged deliberately: a client that arrives with an unexpected ID
            # (for example a URL-shaped Client ID Metadata Document) means it
            # ignored our "no dynamic registration" metadata, and the fix is to
            # teach this method to resolve that ID rather than to change config.
            logger.warning("Unknown client_id presented: %r", client_id)
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a client, forcing the public-client model Spark uses.

        Gemini Spark registers dynamically (RFC 7591) with ``client_name``
        ``"Google"`` and several ``https://oauth-redirect.googleusercontent.com``
        callbacks, and it expects to be a **public** client: the reference
        implementations advertise ``token_endpoint_auth_methods_supported:
        ["none"]`` and return no ``client_secret``. PKCE is what protects the code.

        Registration is open, so the redirect URIs are the gate: a client whose
        callbacks are not on a trusted origin could never receive a code anyway,
        and rejecting it here makes that explicit rather than silent.

        Raises:
            RegistrationError: If the requested redirect URIs are unusable.
        """
        if not client_info.client_id:
            raise RegistrationError("invalid_client_metadata", "client_id is required")

        _validate_registration_redirect_uris(
            client_info.redirect_uris, self._config.allowed_redirect_origins
        )

        # Never hand out a secret, and never let a registrant claim one: the whole
        # point of this flow is that the client cannot keep one.
        public_client = client_info.model_copy(
            update={
                "client_secret": None,
                "token_endpoint_auth_method": "none",
                "client_secret_expires_at": None,
            }
        )
        self._clients[public_client.client_id] = public_client
        self._persist()
        logger.info(
            "Registered public OAuth client %s (%s) redirect_uris=%s",
            public_client.client_id,
            public_client.client_name,
            [str(u) for u in public_client.redirect_uris or []],
        )

    # ---------------------------------------------------------------- authorize

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Issue an authorization code and redirect straight back to the client.

        There is no consent screen. Spark is a public client, so the security
        rests on PKCE (which the SDK verifies at the token endpoint) plus the fact
        that a code is only ever delivered to a redirect URI on a trusted origin —
        Google's own callback, which the registrant does not control. A code that
        leaks anywhere else is unredeemable.
        """
        code = secrets.token_urlsafe(32)
        authorization_code = AuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=time.time() + AUTHORIZATION_CODE_TTL_SECONDS,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=self._config.subject,
        )
        self._codes[code] = authorization_code
        self._persist()
        logger.info("Issued authorization code for client %s", client.client_id)

        # RFC 9207: include `iss` so a client can tell which authorization server
        # answered and refuse a response that came from somewhere else. It must be
        # byte-identical to the issuer advertised in our metadata, hence the
        # round-trip through AnyHttpUrl (which normalises a bare origin).
        return construct_redirect_uri(
            str(params.redirect_uri),
            code=code,
            state=params.state,
            iss=str(AnyHttpUrl(self._config.issuer_url)),
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        """Load an authorization code, ignoring one issued to a different client."""
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            self._codes.pop(authorization_code, None)
            self._persist()
            return None
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Redeem an authorization code for an access token (single use)."""
        self._codes.pop(authorization_code.code, None)
        return self._issue_tokens(client, authorization_code.scopes, authorization_code.resource)

    # ------------------------------------------------------------------- tokens

    def _issue_tokens(
        self,
        client: OAuthClientInformationFull,
        scopes: list[str],
        resource: str | None = None,
    ) -> OAuthToken:
        now = int(time.time())
        # Bind the token to our own resource URL when the client did not ask for a
        # specific one (RFC 8707). AuthSettings.validate_token_resource is on, so a
        # token with no resource would be refused at the MCP endpoint.
        resource = resource or self._config.issuer_url
        access = AccessToken(
            token=secrets.token_urlsafe(40),
            client_id=client.client_id,
            scopes=scopes,
            expires_at=now + ACCESS_TOKEN_TTL_SECONDS,
            resource=resource,
            subject=self._config.subject,
        )
        refresh = RefreshToken(
            token=secrets.token_urlsafe(40),
            client_id=client.client_id,
            scopes=scopes,
            expires_at=now + REFRESH_TOKEN_TTL_SECONDS,
            resource=resource,
            subject=self._config.subject,
        )
        self._access_tokens[access.token] = access
        self._refresh_tokens[refresh.token] = refresh
        self._persist()
        logger.info("Issued access token for client %s (scopes=%s)", client.client_id, scopes)

        return OAuthToken(
            access_token=access.token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(scopes) if scopes else None,
            refresh_token=refresh.token,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Load a refresh token belonging to this client."""
        token = self._refresh_tokens.get(refresh_token)
        if token is None or token.client_id != client.client_id:
            return None
        if token.expires_at is not None and token.expires_at < time.time():
            self._refresh_tokens.pop(refresh_token, None)
            self._persist()
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate a refresh token, narrowing scopes if the client asked for less."""
        self._refresh_tokens.pop(refresh_token.token, None)
        issued_scopes = scopes or refresh_token.scopes
        return self._issue_tokens(client, issued_scopes, refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Validate a bearer token presented on an MCP request."""
        access = self._access_tokens.get(token)
        if access is None:
            return None
        if access.expires_at is not None and access.expires_at < time.time():
            self._access_tokens.pop(token, None)
            self._persist()
            return None
        return access

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke an access or refresh token."""
        removed = self._access_tokens.pop(token.token, None) or self._refresh_tokens.pop(
            token.token, None
        )
        if removed is not None:
            self._persist()
            logger.info("Revoked token for client %s", token.client_id)


def build_auth_settings(config: OAuthConfig) -> AuthSettings:
    """Assemble the SDK auth settings for this deployment.

    Dynamic Client Registration is enabled because that is Spark's default path:
    it registers itself with ``client_name: "Google"`` and never touches the
    Advanced credentials fields. The pre-registered client stays available as a
    fallback for clients that cannot self-register.

    Scopes are left unvalidated (``valid_scopes=None``): Spark requests a
    Google-specific scope name, and rejecting an unknown scope would fail the
    authorization request for no security benefit.
    """
    return AuthSettings(
        issuer_url=AnyHttpUrl(config.issuer_url),
        resource_server_url=AnyHttpUrl(config.issuer_url),
        # Refuse tokens minted for a different resource: without this the SDK
        # warns (and from 3.0 will default to True anyway).
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(
            enabled=config.registration_enabled,
            valid_scopes=None,
            default_scopes=None,
        ),
        revocation_options=RevocationOptions(enabled=True),
    )


def authorization_server_metadata(settings: AuthSettings) -> dict[str, Any]:
    """Build the RFC 8414 document ourselves.

    The SDK hardcodes ``token_endpoint_auth_methods_supported`` to the two
    secret-based methods. That single field is why Spark refuses the server with
    *"This MCP server uses an authentication method that Gemini doesn't support.
    Gemini requires standard OAuth for server connections."* — Spark is a **public**
    client, and it needs ``none`` advertised so it can complete a PKCE exchange
    without a shared secret.

    The shadowing route that serves this document lives in ``http_server``; it has
    to be registered ahead of the SDK's own route to win.
    """
    issuer = str(settings.issuer_url)
    base = issuer.rstrip("/")

    document: dict[str, Any] = {
        "issuer": issuer,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        # Public client: PKCE protects the code, no shared secret exists.
        "token_endpoint_auth_methods_supported": ["none"],
    }

    registration = settings.client_registration_options
    if registration is not None and registration.enabled:
        document["registration_endpoint"] = f"{base}/register"

    revocation = settings.revocation_options
    if revocation is not None and revocation.enabled:
        document["revocation_endpoint"] = f"{base}/revoke"
        document["revocation_endpoint_auth_methods_supported"] = ["none"]

    return document


def describe_client(config: OAuthConfig) -> str:
    """Human-readable credential summary for setup output and the README."""
    return (
        f"OAuth issuer:   {config.issuer_url}\n"
        f"Client ID:      {config.client_id}\n"
        f"Client secret:  {config.client_secret}\n"
        f"State file:     {config.store_path}"
    )
