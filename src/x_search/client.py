"""HTTP client for interacting with the X (Twitter) API v2."""

import os
import re
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from dotenv import load_dotenv

from x_search.models import Author, Post, PublicMetrics, RateLimitStatus, SearchResponse

load_dotenv()


class XSearchError(Exception):
    """Base exception for X search errors."""


class XAPIError(XSearchError):
    """General X API error."""


class XAPIAuthError(XSearchError):
    """Authentication or authorization failure (HTTP 401/403)."""


class XRateLimitError(XSearchError):
    """Rate limit exceeded (HTTP 429)."""


def extract_post_id(post_id_or_url: str) -> str:
    """Extract numeric post ID from a raw ID or an X/Twitter URL."""
    cleaned = post_id_or_url.strip()

    # Match URL pattern like https://x.com/user/status/1234567890
    match = re.search(r"status/(\d+)", cleaned)
    if match:
        return match.group(1)

    # Match pure numeric string
    if re.fullmatch(r"\d+", cleaned):
        return cleaned

    raise ValueError(f"Invalid post ID or URL: {post_id_or_url}")


class XClient:
    """Client for X API v2 recent search and post endpoints."""

    BASE_URL = "https://api.x.com/2"

    def __init__(
        self,
        bearer_token: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        token = bearer_token or os.getenv("X_BEARER_TOKEN") or os.getenv("TWITTER_BEARER_TOKEN")
        if not token:
            raise ValueError(
                "X_BEARER_TOKEN or TWITTER_BEARER_TOKEN environment variable not set. "
                "Please configure your X Bearer Token."
            )
        self.bearer_token = token
        self._external_client = http_client
        self._last_rate_limit = RateLimitStatus()

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "User-Agent": "x-search-tool/0.1.0",
            "Accept": "application/json",
        }

    def _update_rate_limit(self, headers: httpx.Headers) -> None:
        limit = headers.get("x-rate-limit-limit")
        remaining = headers.get("x-rate-limit-remaining")
        reset = headers.get("x-rate-limit-reset")

        limit_int = int(limit) if limit and limit.isdigit() else None
        remaining_int = int(remaining) if remaining and remaining.isdigit() else None

        reset_at: datetime | None = None
        reset_seconds: int | None = None
        if reset and reset.isdigit():
            reset_ts = int(reset)
            reset_at = datetime.fromtimestamp(reset_ts, UTC)
            reset_seconds = max(0, int(reset_ts - time.time()))

        self._last_rate_limit = RateLimitStatus(
            limit=limit_int,
            remaining=remaining_int,
            reset_at=reset_at,
            reset_seconds=reset_seconds,
        )

    def get_rate_limit_status(self) -> RateLimitStatus:
        """Returns the most recent rate limit status."""
        return self._last_rate_limit

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

    def _parse_users(self, data: dict[str, Any]) -> dict[str, Author]:
        users_map: dict[str, Author] = {}
        includes = data.get("includes", {})
        if isinstance(includes, dict) and "users" in includes:
            for u in includes["users"]:
                if isinstance(u, dict) and "id" in u:
                    users_map[str(u["id"])] = Author(
                        id=str(u["id"]),
                        username=u.get("username", ""),
                        name=u.get("name", ""),
                        verified=bool(u.get("verified", False)),
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

    async def _send_request(
        self, method: str, url: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        headers = self._get_headers()
        if self._external_client:
            res = await self._external_client.request(method, url, headers=headers, params=params)
            self._update_rate_limit(res.headers)
            return self._handle_response(res)

        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.request(method, url, headers=headers, params=params)
            self._update_rate_limit(res.headers)
            return self._handle_response(res)

    def _handle_response(self, res: httpx.Response) -> dict[str, Any]:
        if res.status_code == 200:
            return res.json()

        error_msg = self._parse_error_response(res)
        if res.status_code in (401, 403):
            raise XAPIAuthError(f"Unauthorized ({res.status_code}): {error_msg}")
        if res.status_code == 429:
            raise XRateLimitError(f"Rate limit exceeded (429): {error_msg}")
        raise XAPIError(f"X API Error ({res.status_code}): {error_msg}")

    async def search_recent(
        self,
        query: str,
        max_results: int = 10,
        next_token: str | None = None,
        sort_order: str = "recency",
    ) -> SearchResponse:
        """Search recent posts (last 7 days) on X."""
        clamped_max = max(10, min(max_results, 100))
        params: dict[str, Any] = {
            "query": query,
            "max_results": clamped_max,
            "tweet.fields": "created_at,public_metrics,author_id,edit_history_tweet_ids",
            "expansions": "author_id",
            "user.fields": "username,name,verified,profile_image_url",
            "sort_order": sort_order,
        }
        if next_token:
            params["next_token"] = next_token

        url = f"{self.BASE_URL}/tweets/search/recent"
        payload = await self._send_request("GET", url, params=params)

        users_map = self._parse_users(payload)
        posts: list[Post] = []
        raw_posts = payload.get("data", [])
        if isinstance(raw_posts, list):
            for item in raw_posts:
                if isinstance(item, dict) and "id" in item:
                    posts.append(self._parse_post(item, users_map))

        meta = payload.get("meta", {})
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
        payload = await self._send_request("GET", url, params=params)

        data = payload.get("data")
        if not data or not isinstance(data, dict):
            raise XAPIError(f"Post not found: {post_id}")

        users_map = self._parse_users(payload)
        return self._parse_post(data, users_map)
