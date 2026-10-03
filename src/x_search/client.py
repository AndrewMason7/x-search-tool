"""HTTP client for interacting with the X (Twitter) API v2."""

import asyncio
import os
import random
import re
from datetime import datetime
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlparse

import httpx
from dotenv import find_dotenv, load_dotenv

from x_search.models import (
    Author,
    CountBucket,
    Post,
    PostCountsResponse,
    PublicMetrics,
    RateLimitStatus,
    SearchResponse,
)

load_dotenv(find_dotenv(usecwd=True))


class XSearchError(Exception):
    """Base exception for X search errors."""


class XCredentialsError(XSearchError):
    """Authentication credentials missing or invalid in configuration."""


class XValidationError(XSearchError):
    """Input query or argument validation failed."""


class XAPIError(XSearchError):
    """General X API error or network failure."""


class XAPIAuthError(XSearchError):
    """Authentication or authorization failure (HTTP 401/403)."""


class XRateLimitError(XSearchError):
    """Rate limit exceeded (HTTP 429)."""

    def __init__(self, message: str, rate_limit: RateLimitStatus | None = None) -> None:
        super().__init__(message)
        self.rate_limit = rate_limit


# FIX #E3.1 & #E2.2 (per Raj & Natasha): Pre-compiled regexes with length bounds & clean boundary isolation
_POST_URL_PATTERN = re.compile(r"(?:^|/)status(?:es)?/(\d{1,30})(?:[/?#]|$)")
_NUMERIC_ID_PATTERN = re.compile(r"^\d{1,30}$")
_MAX_POST_INPUT_LEN = 512
_ALLOWED_DOMAINS = {"x.com", "www.x.com", "twitter.com", "www.twitter.com"}
_ALLOWED_SORT_ORDERS = {"recency", "relevancy"}


def extract_post_id(post_id_or_url: str) -> str:
    """Extract numeric post ID from a raw ID or an X/Twitter URL."""
    cleaned = post_id_or_url.strip().strip("<>\"'")
    if not cleaned or len(cleaned) > _MAX_POST_INPUT_LEN:
        raise XValidationError(f"Invalid post ID or URL: {post_id_or_url}")

    # Match pure numeric string
    if _NUMERIC_ID_PATTERN.fullmatch(cleaned):
        return cleaned

    # Match URL pattern with domain verification
    try:
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        domain = (parsed.hostname or "").lower()
        if domain and domain not in _ALLOWED_DOMAINS:
            raise XValidationError(f"Invalid post ID or URL: untrusted domain '{domain}'")

        match = _POST_URL_PATTERN.search(parsed.path)
        if match:
            return match.group(1)
    except Exception as err:
        if isinstance(err, XValidationError):
            raise
        raise XValidationError(f"Invalid post ID or URL: {post_id_or_url}") from err

    raise XValidationError(f"Invalid post ID or URL: {post_id_or_url}")


# FIX #E2.1 (per Natasha): Strict RFC 3339 / ISO 8601 UTC timestamp validation helper
def validate_iso_timestamp(param_name: str, ts_str: str) -> str:
    """Validate that timestamp string conforms to RFC 3339 / ISO 8601 with timezone."""
    cleaned = ts_str.strip()
    if not cleaned:
        raise XValidationError(f"Timestamp '{param_name}' cannot be empty.")
    try:
        dt = datetime.fromisoformat(cleaned)
        # RFC 3339 requires time and timezone offset (e.g. 'Z' or '+00:00')
        if dt.tzinfo is None:
            raise ValueError("Missing timezone offset")
        if "T" not in cleaned and " " not in cleaned:
            raise ValueError("Date-only strings not allowed for X API RFC 3339 timestamps")
        return cleaned
    except ValueError as e:
        raise XValidationError(
            f"Invalid '{param_name}' timestamp format: '{ts_str}'. Expected RFC 3339 with timezone (e.g. '2026-01-01T00:00:00Z')."
        ) from e


def validate_time_range(start_time: str | None, end_time: str | None) -> None:
    """Validate that start_time is chronologically before end_time."""
    if start_time and end_time:
        st_dt = datetime.fromisoformat(start_time)
        et_dt = datetime.fromisoformat(end_time)
        if st_dt >= et_dt:
            raise XValidationError(
                f"Invalid time range: start_time ('{start_time}') must be earlier than end_time ('{end_time}')."
            )


class XClient:
    """Client for X API v2 recent search, full-archive search, counts, and post endpoints."""

    BASE_URL = "https://api.x.com/2"

    def __init__(
        self,
        bearer_token: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 15.0,
        max_retries: int = 2,
        backoff_base: float = 0.2,
    ) -> None:
        token = (
            bearer_token or os.getenv("X_BEARER_TOKEN") or os.getenv("TWITTER_BEARER_TOKEN") or ""
        ).strip()
        if not token:
            raise XCredentialsError(
                "X_BEARER_TOKEN or TWITTER_BEARER_TOKEN environment variable not set. "
                "Please configure your X Bearer Token."
            )
        self._bearer_token = token
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        # FIX #E1.1 (per Marcus): Track rate limits per endpoint category
        self._rate_limits: dict[str, RateLimitStatus] = {}

        # FIX #H4.1 (per Tyler): Pre-cached static base headers
        self._headers = {
            "Authorization": f"Bearer {self._bearer_token}",
            "User-Agent": "x-search-tool/0.2.0",
            "Accept": "application/json",
        }

        # FIX #E4.1 & #H4.1 (per Maya & Tyler): Persistent connection pool & client reuse
        self._external_client = http_client
        self._internal_client: httpx.AsyncClient | None = None
        # FIX #H1.1 (per Kyle): Event-loop-bound lock reference
        self._client_lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None

    @property
    def bearer_token(self) -> str:
        """Returns the configured Bearer Token."""
        return self._bearer_token

    # FIX #E2.1 (per Natasha): Redact bearer token in string & repr representations
    def __repr__(self) -> str:
        masked = (
            f"{self._bearer_token[:4]}...{self._bearer_token[-4:]}"
            if len(self._bearer_token) > 8
            else "****"
        )
        return f"<XClient base_url={self.BASE_URL!r} token={masked!r}>"

    def __str__(self) -> str:
        return self.__repr__()

    # FIX #H1.1 (per Kyle): Event loop lock affinity checking
    def _get_lock(self) -> asyncio.Lock:
        try:
            curr_loop = asyncio.get_running_loop()
        except RuntimeError:
            curr_loop = None
        if self._client_lock is None or self._lock_loop is not curr_loop:
            self._client_lock = asyncio.Lock()
            self._lock_loop = curr_loop
        return self._client_lock

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Returns the shared connection-pooled HTTP client."""
        if self._external_client:
            return self._external_client
        if self._internal_client is None or self._internal_client.is_closed:
            async with self._get_lock():
                if self._internal_client is None or self._internal_client.is_closed:
                    self._internal_client = httpx.AsyncClient(
                        timeout=self._timeout,
                        limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
                    )
        return self._internal_client

    async def aclose(self) -> None:
        """Close managed network resources."""
        async with self._get_lock():
            if self._internal_client and not self._internal_client.is_closed:
                await self._internal_client.aclose()
                self._internal_client = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def _get_headers(self) -> dict[str, str]:
        return self._headers

    # FIX #E1.1 & #E4.2 (per Marcus & Maya): Per-endpoint rate limit status with Retry-After support
    def _update_rate_limit(self, endpoint_key: str, headers: httpx.Headers) -> None:
        status = RateLimitStatus.from_headers(headers)
        self._rate_limits[endpoint_key] = status
        self._rate_limits["_last"] = status

    def get_rate_limit_status(self, endpoint_key: str = "search") -> RateLimitStatus:
        """Returns the rate limit status for a specific endpoint category or most recent."""
        return (
            self._rate_limits.get(endpoint_key)
            or self._rate_limits.get("_last")
            or RateLimitStatus()
        )

    def _parse_error_response(self, response: httpx.Response) -> str:
        try:
            data = response.json()
            if isinstance(data, dict):
                if "errors" in data and isinstance(data["errors"], list) and data["errors"]:
                    err = data["errors"][0]
                    if isinstance(err, dict) and "message" in err:
                        return str(err["message"])
                if "detail" in data:
                    return str(data["detail"])
                if "title" in data:
                    return str(data["title"])
            return response.text
        except (ValueError, KeyError):
            return response.text or f"HTTP {response.status_code}"

    # FIX #E4.1 (per Maya): Extract Retry-After seconds from response headers
    def _extract_retry_after(self, headers: httpx.Headers) -> float | None:
        retry_after = headers.get("retry-after")
        if not retry_after:
            return None
        stripped = retry_after.strip()
        if stripped.isdigit():
            return float(stripped)
        return None

    # FIX #E4.1, #E4.2 & #E3.1 (per Maya & Raj): Exponential backoff with jitter and Retry-After header respect
    async def _send_request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        endpoint_key: str = "search",
    ) -> dict[str, Any]:
        client = await self._get_http_client()
        headers = self._get_headers()

        attempt = 0
        while True:
            try:
                res = await client.request(method, url, headers=headers, params=params)
                self._update_rate_limit(endpoint_key, res.headers)

                # Retry on transient server errors (500, 502, 503, 504)
                if res.status_code in (500, 502, 503, 504) and attempt < self._max_retries:
                    attempt += 1
                    retry_after = self._extract_retry_after(res.headers)
                    if retry_after is not None:
                        sleep_time = min(retry_after, 60.0) + random.uniform(0.01, 0.05)
                    else:
                        sleep_time = (self._backoff_base * (2**attempt)) + random.uniform(0.01, 0.05)
                    await asyncio.sleep(sleep_time)
                    continue

                return self._handle_response(res, endpoint_key=endpoint_key)

            except (httpx.ConnectError, httpx.TimeoutException, httpx.ProtocolError) as e:
                if attempt < self._max_retries:
                    attempt += 1
                    sleep_time = (self._backoff_base * (2**attempt)) + random.uniform(0.01, 0.05)
                    await asyncio.sleep(sleep_time)
                    continue
                raise XAPIError(f"Network error communicating with X API: {e}") from e
            except httpx.RequestError as e:
                raise XAPIError(f"Network error communicating with X API: {e}") from e

    def _handle_response(self, res: httpx.Response, endpoint_key: str = "search") -> dict[str, Any]:
        if res.status_code == 200:
            return res.json()

        error_msg = self._parse_error_response(res)
        if res.status_code in (401, 403):
            raise XAPIAuthError(f"Unauthorized ({res.status_code}): {error_msg}")
        if res.status_code == 429:
            raise XRateLimitError(
                f"Rate limit exceeded (429): {error_msg}",
                rate_limit=self.get_rate_limit_status(endpoint_key),
            )
        raise XAPIError(f"X API Error ({res.status_code}): {error_msg}")

    def _parse_users(self, data: dict[str, Any]) -> dict[str, Author]:
        users_map: dict[str, Author] = {}
        includes = data.get("includes")
        if isinstance(includes, dict):
            raw_users = includes.get("users")
            if isinstance(raw_users, list):
                for u in raw_users:
                    if isinstance(u, dict) and "id" in u:
                        verified = bool(u.get("verified", False)) or (
                            bool(u.get("verified_type")) and u.get("verified_type") != "none"
                        )
                        users_map[str(u["id"])] = Author(
                            id=str(u["id"]),
                            username=u.get("username", ""),
                            name=u.get("name", ""),
                            verified=verified,
                            profile_image_url=u.get("profile_image_url"),
                        )
        return users_map

    def _parse_post(self, item: dict[str, Any], users_map: dict[str, Author]) -> Post:
        author_id = item.get("author_id")
        author = users_map.get(str(author_id)) if author_id else None

        metrics = None
        if "public_metrics" in item and isinstance(item["public_metrics"], dict):
            pm = item["public_metrics"]
            metrics = PublicMetrics(
                retweet_count=pm.get("retweet_count", 0),
                reply_count=pm.get("reply_count", 0),
                like_count=pm.get("like_count", 0),
                quote_count=pm.get("quote_count", 0),
                impression_count=pm.get("impression_count"),
            )

        created_at = None
        if item.get("created_at"):
            try:
                created_at = datetime.fromisoformat(item["created_at"])
            except (ValueError, TypeError):
                created_at = None

        return Post(
            id=str(item["id"]),
            text=item.get("text", ""),
            created_at=created_at,
            author=author,
            metrics=metrics,
            edit_history_tweet_ids=item.get("edit_history_tweet_ids", []),
        )

    async def search_recent(
        self,
        query: str,
        max_results: int = 10,
        next_token: str | None = None,
        sort_order: str = "recency",
    ) -> SearchResponse:
        """Search recent posts (last 7 days) on X."""
        clean_query = query.strip()
        if not clean_query:
            raise XValidationError("Search query cannot be empty.")
        if len(clean_query) > 512:
            raise XValidationError(
                f"Search query exceeds X API limit of 512 characters (length: {len(clean_query)})."
            )
        # FIX #H3.1 (per Karen): Strict validation for sort_order
        if sort_order not in _ALLOWED_SORT_ORDERS:
            raise XValidationError(
                f"Invalid sort_order '{sort_order}'. Must be one of: {sorted(_ALLOWED_SORT_ORDERS)}"
            )

        clamped_max = max(10, min(max_results, 100))
        params: dict[str, Any] = {
            "query": clean_query,
            "max_results": clamped_max,
            "tweet.fields": "created_at,public_metrics,author_id,edit_history_tweet_ids",
            "expansions": "author_id",
            "user.fields": "username,name,verified,profile_image_url",
            "sort_order": sort_order,
        }
        if next_token and next_token.strip():
            params["next_token"] = next_token.strip()

        url = f"{self.BASE_URL}/tweets/search/recent"
        payload = await self._send_request("GET", url, params=params, endpoint_key="search")

        users_map = self._parse_users(payload)
        posts: list[Post] = []
        raw_posts = payload.get("data")
        if isinstance(raw_posts, list):
            for item in raw_posts:
                if isinstance(item, dict) and "id" in item:
                    posts.append(self._parse_post(item, users_map))

        meta = payload.get("meta") or {}
        return SearchResponse(
            posts=posts,
            result_count=meta.get("result_count", len(posts)),
            newest_id=meta.get("newest_id"),
            oldest_id=meta.get("oldest_id"),
            next_token=meta.get("next_token"),
        )

    async def get_post(self, post_id_or_url: str) -> Post:
        """Fetch details for a single post by ID or URL."""
        post_id = extract_post_id(post_id_or_url)
        params: dict[str, Any] = {
            "tweet.fields": "created_at,public_metrics,author_id,edit_history_tweet_ids",
            "expansions": "author_id",
            "user.fields": "username,name,verified,profile_image_url",
        }
        url = f"{self.BASE_URL}/tweets/{post_id}"
        payload = await self._send_request("GET", url, params=params, endpoint_key="tweets")

        data = payload.get("data")
        if not data or not isinstance(data, dict):
            raise XAPIError(f"Post not found: {post_id}")

        users_map = self._parse_users(payload)
        return self._parse_post(data, users_map)

    async def search_all(
        self,
        query: str,
        start_time: str | None = None,
        end_time: str | None = None,
        max_results: int = 10,
        next_token: str | None = None,
        sort_order: str = "recency",
    ) -> SearchResponse:
        """Search full historical post archive (2006 to present) on X."""
        clean_query = query.strip()
        if not clean_query:
            raise XValidationError("Search query cannot be empty.")
        if len(clean_query) > 1024:
            raise XValidationError(
                f"Search query exceeds full-archive limit of 1024 characters (length: {len(clean_query)})."
            )
        # FIX #H3.1 (per Karen): Strict validation for sort_order
        if sort_order not in _ALLOWED_SORT_ORDERS:
            raise XValidationError(
                f"Invalid sort_order '{sort_order}'. Must be one of: {sorted(_ALLOWED_SORT_ORDERS)}"
            )

        clamped_max = max(10, min(max_results, 500))
        params: dict[str, Any] = {
            "query": clean_query,
            "max_results": clamped_max,
            "tweet.fields": "created_at,public_metrics,author_id,edit_history_tweet_ids",
            "expansions": "author_id",
            "user.fields": "username,name,verified,profile_image_url",
            "sort_order": sort_order,
        }
        validated_start = None
        validated_end = None
        if start_time and start_time.strip():
            validated_start = validate_iso_timestamp("start_time", start_time)
            params["start_time"] = validated_start
        if end_time and end_time.strip():
            validated_end = validate_iso_timestamp("end_time", end_time)
            params["end_time"] = validated_end
        # FIX #E3.1 & #E2.1 (per Raj & Natasha): Fail fast on inverted time ranges
        validate_time_range(validated_start, validated_end)

        if next_token and next_token.strip():
            params["next_token"] = next_token.strip()

        url = f"{self.BASE_URL}/tweets/search/all"
        payload = await self._send_request("GET", url, params=params, endpoint_key="search_all")

        users_map = self._parse_users(payload)
        posts: list[Post] = []
        raw_posts = payload.get("data")
        if isinstance(raw_posts, list):
            for item in raw_posts:
                if isinstance(item, dict) and "id" in item:
                    posts.append(self._parse_post(item, users_map))

        meta = payload.get("meta") or {}
        return SearchResponse(
            posts=posts,
            result_count=meta.get("result_count", len(posts)),
            newest_id=meta.get("newest_id"),
            oldest_id=meta.get("oldest_id"),
            next_token=meta.get("next_token"),
        )

    async def get_counts(
        self,
        query: str,
        granularity: str = "day",
        start_time: str | None = None,
        end_time: str | None = None,
        full_archive: bool = False,
        next_token: str | None = None,
    ) -> PostCountsResponse:
        """Get post volume counts grouped by day, hour, or minute."""
        clean_query = query.strip()
        if not clean_query:
            raise XValidationError("Query cannot be empty.")
        clean_granularity = granularity.strip().lower()
        if clean_granularity not in ("day", "hour", "minute"):
            raise XValidationError(
                f"Invalid granularity: '{granularity}'. Must be 'day', 'hour', or 'minute'."
            )

        endpoint = "all" if full_archive else "recent"
        url = f"{self.BASE_URL}/tweets/counts/{endpoint}"
        params: dict[str, Any] = {
            "query": clean_query,
            "granularity": clean_granularity,
        }
        validated_start = None
        validated_end = None
        if start_time and start_time.strip():
            validated_start = validate_iso_timestamp("start_time", start_time)
            params["start_time"] = validated_start
        if end_time and end_time.strip():
            validated_end = validate_iso_timestamp("end_time", end_time)
            params["end_time"] = validated_end
        # FIX #E3.1 & #E2.1 (per Raj & Natasha): Fail fast on inverted time ranges
        validate_time_range(validated_start, validated_end)

        if next_token and next_token.strip():
            params["next_token"] = next_token.strip()

        payload = await self._send_request("GET", url, params=params, endpoint_key="counts")

        buckets: list[CountBucket] = []
        raw_data = payload.get("data")
        if isinstance(raw_data, list):
            for b in raw_data:
                if isinstance(b, dict) and "start" in b and "end" in b:
                    try:
                        start_dt = datetime.fromisoformat(b["start"])
                        end_dt = datetime.fromisoformat(b["end"])
                        buckets.append(
                            CountBucket(
                                start=start_dt,
                                end=end_dt,
                                tweet_count=int(b.get("tweet_count", 0)),
                            )
                        )
                    except (ValueError, TypeError):
                        continue

        meta = payload.get("meta") or {}
        # FIX #E4.1 (per Maya): Defensive null guard prevents int(None) crash on null meta values
        raw_total = meta.get("total_tweet_count")
        if raw_total is not None:
            try:
                total_count = int(raw_total)
            except (ValueError, TypeError):
                total_count = sum(b.tweet_count for b in buckets)
        else:
            total_count = sum(b.tweet_count for b in buckets)

        return PostCountsResponse(
            total_count=total_count,
            granularity=granularity,
            buckets=buckets,
            next_token=meta.get("next_token"),
        )
