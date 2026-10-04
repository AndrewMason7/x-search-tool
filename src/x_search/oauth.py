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

import asyncio
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
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

#: Gemini Spark completes the flow at Google's own callback origin, so codes are
#: only ever delivered there. Deliberately *not* a bare ``google.com``: that would
#: accept any ``*.google.com`` host, and an open-redirect gadget anywhere on a
#: Google subdomain would then be enough to receive a code.
DEFAULT_ALLOWED_REDIRECT_ORIGINS = ("googleusercontent.com",)

#: Spark is a public client: real traces show it registering with
#: ``token_endpoint_auth_method: "none"`` and sending **no** client secret even
#: when it is given one to paste in. Default to public so a secret-less token
#: exchange succeeds; ``client_secret_post`` / ``client_secret_basic`` remain
#: available for clients that really do authenticate with a shared secret.
TOKEN_AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic")
DEFAULT_TOKEN_AUTH_METHOD = "none"

#: How long a pending authorization request stays valid before the consent page
#: expires. Long enough to read and approve, short enough not to accumulate.
CONSENT_REQUEST_TTL_SECONDS = 600

#: Upper bound on dynamically registered clients. Registration is unauthenticated
#: and every registration rewrites the whole store, so an unbounded list is both a
#: disk-exhaustion and a write-amplification vector.
MAX_REGISTERED_CLIENTS = 200

#: How long a rotated-out refresh token keeps working. Rotation alone breaks
#: clients that hold two live connections: if both see an expired access token at
#: the same moment, the first rotates and the second is told invalid_grant.
#: Gemini Spark opens parallel connections on some turns, so it hits exactly that.
REFRESH_REUSE_GRACE_SECONDS = 120

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
#: urlparse strips the brackets from an IPv6 literal, so the host of
#: ``http://[::1]:8080/cb`` is ``::1``, not ``[::1]``.


def _env_flag(name: str, *, default: bool = False) -> bool:
    """Read a boolean-ish environment variable."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _host_allowed(host: str, allowed_origins: tuple[str, ...]) -> bool:
    """Whether ``host`` is on the allow-list. **Fails closed.**

    An empty or missing allow-list permits nothing. Getting this backwards would
    turn a configuration typo into an open redirector, so the empty case is
    deliberately a denial rather than a wildcard.
    """
    if not host or not allowed_origins:
        return False
    return any(host == origin or host.endswith(f".{origin}") for origin in allowed_origins)


def redirect_uri_problem(
    uri: AnyUrl | str,
    allowed_origins: tuple[str, ...],
    *,
    allow_loopback: bool,
) -> str | None:
    """Return why ``uri`` is an unacceptable redirect target, or None if it is fine.

    Deliberately does NOT special-case anything into acceptance: every path either
    passes every check or is rejected with a reason.
    """
    parsed = urlparse(str(uri))
    host = (parsed.hostname or "").lower().rstrip(".")

    # RFC 6749 3.1.2 forbids userinfo in a redirect URI, and it is a classic
    # redirect-confusion gadget.
    if parsed.username or parsed.password:
        return "redirect_uri must not contain userinfo"
    if parsed.fragment:
        return "redirect_uri must not contain a fragment"

    if host in LOOPBACK_HOSTS:
        if not allow_loopback:
            return "loopback redirect URIs are not accepted on this deployment"
        if parsed.scheme != "http":
            return "loopback redirect URIs must use http"
        return None

    if parsed.scheme != "https":
        return "redirect_uri must use https"

    if not _host_allowed(host, allowed_origins):
        return f"redirect_uri host {host!r} is not permitted on this server"

    return None


class SparkClient(OAuthClientInformationFull):
    """A client whose redirect URIs are validated against a trusted allow-list.

    Note what this can and cannot do. It stops a registrant from naming an
    arbitrary callback host. It does **not** by itself protect the token endpoint:
    an authorization code is returned in the ``Location`` header of the
    authorization response, so a caller that never follows the redirect can read
    the code out of its own response. That is why :meth:`XSearchOAuthProvider.authorize`
    requires an explicit human approval step rather than auto-approving.
    """

    allowed_redirect_origins: tuple[str, ...] = ()
    allow_loopback_redirects: bool = False

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is None:
            return super().validate_redirect_uri(redirect_uri)

        problem = redirect_uri_problem(
            redirect_uri,
            self.allowed_redirect_origins,
            allow_loopback=self.allow_loopback_redirects,
        )
        if problem is not None:
            raise InvalidRedirectUriError(f"{problem}: {redirect_uri}")
        return redirect_uri


def _validate_registration_redirect_uris(
    redirect_uris: list[AnyUrl] | None,
    allowed_origins: tuple[str, ...],
    *,
    allow_loopback: bool,
) -> None:
    """Reject a registration whose redirect URIs could never receive a code.

    Every rejection is logged with the offending URIs: a client that cannot
    register typically shows only a generic error in its own UI, so the server log
    is the only place the real cause is visible.

    Raises:
        RegistrationError: If any redirect URI is unacceptable.
    """
    if not redirect_uris:
        logger.warning("Rejected client registration: no redirect_uris supplied")
        raise RegistrationError("invalid_redirect_uri", "At least one redirect_uri is required")

    for uri in redirect_uris:
        problem = redirect_uri_problem(uri, allowed_origins, allow_loopback=allow_loopback)
        if problem is not None:
            logger.warning(
                "Rejected client registration: %s (redirect_uris=%s, allowed_origins=%s)",
                problem,
                [str(u) for u in redirect_uris],
                list(allowed_origins),
            )
            raise RegistrationError("invalid_redirect_uri", problem)


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
    #: Secret a human must supply on the consent page before a code is issued.
    #: Without this, open registration plus an authorization endpoint that returns
    #: the code to its caller is an unauthenticated path to a token.
    consent_secret: str = ""
    allow_loopback_redirects: bool = False

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
        allow_loopback = _env_flag("X_SEARCH_OAUTH_ALLOW_LOOPBACK", default=False)

        if not allowed_origins:
            raise ValueError(
                "X_SEARCH_OAUTH_ALLOWED_REDIRECT_ORIGINS is empty; refusing to start rather "
                "than accepting redirects to any host. Set it to a comma-separated list of "
                "origins (e.g. googleusercontent.com) or remove the variable for the default."
            )

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

        # The consent secret is what actually stops an anonymous caller: open
        # registration plus an authorization endpoint that hands the code to its
        # caller is otherwise an unauthenticated path to a token.
        if not registered.get("consent_secret"):
            registered["consent_secret"] = secrets.token_urlsafe(24)
        store.save()

        consent_secret = (
            os.getenv("X_SEARCH_CONSENT_SECRET") or registered["consent_secret"]
        ).strip()
        if not consent_secret:
            raise ValueError(
                "The consent secret resolved to an empty value; refusing to start with an "
                "authorization endpoint that nobody has to approve."
            )

        return cls(
            issuer_url=public_url,
            client_id=os.getenv("X_SEARCH_OAUTH_CLIENT_ID") or registered["client_id"],
            client_secret=os.getenv("X_SEARCH_OAUTH_CLIENT_SECRET") or registered["client_secret"],
            store_path=store_path,
            subject=subject,
            token_auth_method=token_auth_method,
            allowed_redirect_origins=allowed_origins,
            registration_enabled=registration_enabled,
            consent_secret=consent_secret,
            allow_loopback_redirects=allow_loopback,
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
        """Write the whole document atomically.

        A unique temp file per write is essential: two concurrent saves sharing a
        fixed ``<path>.tmp`` name race on the rename, and the loser raises
        FileNotFoundError — which, on the token hot path, surfaces as a failed
        request. The file is fsynced before the rename so a power loss cannot leave
        a truncated store behind (os.replace is atomic against readers, but not
        durable on its own).

        Raises:
            OSError: If the write fails. Callers on the request path catch this and
                keep serving from memory rather than failing the request.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.data, indent=2, sort_keys=True)

        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=f".{self.path.name}.", suffix=".tmp"
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise


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
        self._pending: dict[str, tuple[str, AuthorizationParams, float]] = {}
        #: Rotated-out refresh tokens, kept briefly so a second concurrent refresh
        #: is not rejected. Transient by design: losing it on restart only means the
        #: grace window closes early.
        self._rotated_refresh: dict[str, tuple[RefreshToken, float]] = {}
        self._pre_registered: SparkClient | None = None
        # Every mutation is read-modify-write over shared dicts plus a whole-file
        # rewrite. Holding this lock makes each one atomic even if a future change
        # introduces an await in the middle.
        self._lock = asyncio.Lock()
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
        """Prune expired state and write it out, never failing the request.

        A store write is durability, not correctness: if the disk is full the
        request should still succeed from in-memory state rather than 500.
        """
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
        try:
            self._store.save()
        except OSError:
            logger.error(
                "Could not persist OAuth state to %s; continuing from memory",
                self._store.path,
                exc_info=True,
            )

    # ---------------------------------------------------------------- clients

    @property
    def client_name(self) -> str:
        """Display name for the consent page."""
        return self._config.client_name

    def pre_registered_client(self) -> OAuthClientInformationFull:
        """The client whose credentials can be pasted into the client's own UI.

        Deliberately *not* persisted: it is rebuilt from config on every start so
        that ``SparkClient``'s redirect validation survives a restart (a round-trip
        through JSON would reload it as the base model).
        """
        if self._pre_registered is None:
            # Spark never sends a client secret — verified in its real token
            # requests, which carry client_id, code and code_verifier only. So the
            # pre-registered client is public by default; a secret is only attached
            # when the operator explicitly selects a secret-based auth method.
            public = self._config.token_auth_method == "none"
            self._pre_registered = SparkClient(
                client_id=self._config.client_id,
                client_secret=None if public else self._config.client_secret,
                client_name=self._config.client_name,
                redirect_uris=None,
                token_endpoint_auth_method=self._config.token_auth_method,
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope="x-search",
                client_id_issued_at=int(time.time()),
                allowed_redirect_origins=self._config.allowed_redirect_origins,
                allow_loopback_redirects=self._config.allow_loopback_redirects,
            )
        return self._pre_registered

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Look up a client by ID, preferring the configured pre-registered client."""
        if client_id == self._config.client_id:
            return self.pre_registered_client()
        client = self._clients.get(client_id)
        if client is None:
            # Debug, not warning: /authorize is reachable by anyone, so a scanner
            # would otherwise fill the journal with these.
            logger.debug("Unknown client_id presented: %r", client_id)
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a client, forcing the public-client model Spark uses.

        Gemini Spark registers dynamically (RFC 7591) with ``client_name``
        ``"Google"`` and several ``https://oauth-redirect.googleusercontent.com``
        callbacks, and it expects to be a **public** client: the reference
        implementations advertise ``token_endpoint_auth_methods_supported:
        ["none"]`` and return no ``client_secret``. PKCE is what protects the code.

        Registration is open, so the redirect URIs are the only structural gate here. They
        are necessary but **not sufficient**: see :meth:`authorize` for why the
        approval step is what actually protects the token endpoint.

        Raises:
            RegistrationError: If the requested redirect URIs are unusable.
        """
        if not client_info.client_id:
            raise RegistrationError("invalid_client_metadata", "client_id is required")

        _validate_registration_redirect_uris(
            client_info.redirect_uris,
            self._config.allowed_redirect_origins,
            allow_loopback=self._config.allow_loopback_redirects,
        )

        async with self._lock:
            # Registration is unauthenticated and reachable by anyone, so it must
            # not be an unbounded write amplifier: every registration rewrites the
            # whole store.
            if len(self._clients) >= MAX_REGISTERED_CLIENTS:
                self._evict_oldest_clients(MAX_REGISTERED_CLIENTS // 4)

            # Never hand out a secret, and never let a registrant claim one: the
            # whole point of this flow is that the client cannot keep one.
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
            "Registered public OAuth client %s (%s) redirect_uris=%s [total=%d]",
            public_client.client_id,
            public_client.client_name,
            [str(u) for u in public_client.redirect_uris or []],
            len(self._clients),
        )

    def _evict_oldest_clients(self, count: int) -> None:
        """Drop the oldest registrations, oldest first, keeping the newest ones.

        Dynamic registration is unauthenticated, so without a bound the store grows
        without limit and every write re-serialises all of it.
        """
        ordered = sorted(self._clients.items(), key=lambda kv: kv[1].client_id_issued_at or 0)
        for client_id, _ in ordered[:count]:
            self._clients.pop(client_id, None)
        logger.warning("Evicted %d oldest OAuth client registrations", count)

    # ---------------------------------------------------------------- authorize

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Park the request and send the browser to an approval page.

        This deliberately does **not** issue a code. The previous version
        auto-approved and returned the code in the ``Location`` header — which meant
        any caller could read the code out of its own HTTP response without ever
        following the redirect, so the redirect-URI allow-list protected nothing.
        Registration is open, so that was an unauthenticated path to a working
        access token.

        Now a human must present the consent secret on ``/consent`` before
        :meth:`approve_authorization` issues anything.

        Returns:
            The URL of the consent page for this request.
        """
        if not params.code_challenge or not params.code_challenge.strip():
            raise AuthorizeError(
                "invalid_request",
                "code_challenge is required: this server only accepts PKCE S256",
            )

        request_id = secrets.token_urlsafe(24)
        async with self._lock:
            self._prune_pending()
            self._pending[request_id] = (client.client_id, params, time.time())
        logger.info(
            "Authorization request %s parked for client %s; awaiting consent",
            request_id,
            client.client_id,
        )
        return f"{self._config.issuer_url.rstrip('/')}/consent?req={request_id}"

    def _prune_pending(self) -> None:
        """Drop consent requests nobody completed."""
        cutoff = time.time() - CONSENT_REQUEST_TTL_SECONDS
        self._pending = {k: v for k, v in self._pending.items() if v[2] > cutoff}

    async def pending_authorization(self, request_id: str) -> AuthorizationParams | None:
        """Look up a parked authorization request so the page can describe it."""
        async with self._lock:
            self._prune_pending()
            entry = self._pending.get(request_id)
        return entry[1] if entry else None

    async def approve_authorization(
        self,
        request_id: str,
        consent_secret: str,
    ) -> str:
        """Issue a code for a parked request once a human has approved it.

        Args:
            request_id: The value from the consent page.
            consent_secret: What the human typed; compared in constant time.

        Returns:
            The redirect URL back to the client, carrying ``code``, ``state`` and
            ``iss``.

        Raises:
            AuthorizeError: If the secret is wrong, or the request is unknown,
                expired, or already used.
        """
        if not hmac.compare_digest(consent_secret.encode(), self._config.consent_secret.encode()):
            logger.warning("Rejected consent attempt %s: wrong secret", request_id)
            raise AuthorizeError("access_denied", "Incorrect approval secret")

        async with self._lock:
            self._prune_pending()
            entry = self._pending.pop(request_id, None)
            if entry is None:
                raise AuthorizeError(
                    "invalid_request",
                    "This approval link has expired or was already used. Start again.",
                )
            client_id, params, _ = entry
            client = await self.get_client(client_id)
            if client is None:
                raise AuthorizeError("unauthorized_client", "The client is no longer registered")

            code = secrets.token_urlsafe(32)
            self._codes[code] = AuthorizationCode(
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
            self._persist()

        logger.info("Approved authorization request %s for client %s", request_id, client.client_id)

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
        """Redeem an authorization code for an access token, exactly once.

        The pop IS the single-use gate. Previously the result was discarded and
        tokens were issued unconditionally, which was only safe because no await sat
        between loading the code and exchanging it — an accidental property, not an
        enforced one. Any added await or retry would have double-minted tokens.

        Raises:
            TokenError: If the code was already redeemed.
        """
        async with self._lock:
            if self._codes.pop(authorization_code.code, None) is None:
                logger.warning(
                    "Rejected replay of authorization code for client %s", client.client_id
                )
                raise TokenError("invalid_grant", "authorization code already used")
            return self._issue_tokens(
                client, authorization_code.scopes, authorization_code.resource
            )

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
        """Load a refresh token belonging to this client.

        Also accepts a token that was rotated out within the last
        :data:`REFRESH_REUSE_GRACE_SECONDS`, so a client whose two connections
        refresh at the same instant does not get one of them rejected.
        """
        token = self._refresh_tokens.get(refresh_token)
        if token is None:
            rotated = self._rotated_refresh.get(refresh_token)
            if rotated is not None and rotated[1] + REFRESH_REUSE_GRACE_SECONDS > time.time():
                token = rotated[0]
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
        """Rotate a refresh token, narrowing scopes if the client asked for less.

        The rotated-out token stays usable for a short grace window rather than
        being revoked instantly: with two live connections, an instant revoke makes
        the second concurrent refresh fail even though it is legitimate.
        """
        async with self._lock:
            still_current = self._refresh_tokens.pop(refresh_token.token, None)
            if still_current is not None:
                self._rotated_refresh[refresh_token.token] = (still_current, time.time())
            self._prune_rotated_refresh()
            issued_scopes = scopes or refresh_token.scopes
            return self._issue_tokens(client, issued_scopes, refresh_token.resource)

    def _prune_rotated_refresh(self) -> None:
        """Forget rotated-out refresh tokens once their grace window closes."""
        cutoff = time.time() - REFRESH_REUSE_GRACE_SECONDS
        self._rotated_refresh = {k: v for k, v in self._rotated_refresh.items() if v[1] > cutoff}

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
