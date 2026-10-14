"""Shared test fixtures, isolation hooks, and sample API v2 responses."""

import os
from collections.abc import AsyncGenerator, Callable
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from x_search.client import XClient


@pytest.fixture(autouse=True)
def isolate_from_ambient_search_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop the ambient shell from changing what these tests exercise.

    ``x_search.server`` builds its module-level server at import time from
    ``X_SEARCH_*`` environment variables. A stray ``X_SEARCH_PUBLIC_URL`` in the
    developer's shell would silently turn every non-OAuth test into an
    OAuth-enabled one, and tests that construct their own config would inherit an
    unexpected store path. Clear the whole namespace so each test states its own.
    """
    for name in list(os.environ):
        if name.startswith("X_SEARCH_"):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def reset_server_singleton() -> Any:
    """Ensure x_search.server._client_instance is reset before and after each test."""
    import x_search.server as server_mod

    server_mod._client_instance = None
    yield
    server_mod._client_instance = None


@pytest.fixture
def make_test_client() -> Callable[..., XClient]:
    """Factory fixture returning an XClient configured with zero-delay retries for fast testing."""

    def _factory(
        handler: Callable[[httpx.Request], httpx.Response] | None = None,
        bearer_token: str = "test_token",
        max_retries: int = 2,
        backoff_base: float = 0.0001,  # Sub-millisecond backoff prevents test sleep thrashing
        timeout: float = 5.0,
    ) -> XClient:
        transport = httpx.MockTransport(handler) if handler else None
        http_client = httpx.AsyncClient(transport=transport) if transport else None
        return XClient(
            bearer_token=bearer_token,
            http_client=http_client,
            max_retries=max_retries,
            backoff_base=backoff_base,
            timeout=timeout,
        )

    return _factory


@pytest.fixture
def mock_server_client() -> AsyncGenerator[AsyncMock, None]:
    """Provides a mocked XClient pre-injected into x_search.server.get_client."""
    mock_client = AsyncMock(spec=XClient)
    with patch("x_search.server.get_client", return_value=mock_client):
        yield mock_client


@pytest.fixture
def sample_search_json() -> dict[str, Any]:
    return {
        "data": [
            {
                "id": "1840000000000000001",
                "text": "Excited to share our new research paper on AI agents! #Python #AI",
                "created_at": "2026-10-02T15:30:00.000Z",
                "author_id": "2244994945",
                "edit_history_tweet_ids": ["1840000000000000001"],
                "public_metrics": {
                    "retweet_count": 142,
                    "reply_count": 35,
                    "like_count": 890,
                    "quote_count": 12,
                    "impression_count": 25400,
                },
            },
            {
                "id": "1840000000000000002",
                "text": "Python 3.13 free-threading is a game changer for multi-core performance.",
                "created_at": "2026-10-02T16:00:00.000Z",
                "author_id": "44196397",
                "edit_history_tweet_ids": ["1840000000000000002"],
                "public_metrics": {
                    "retweet_count": 55,
                    "reply_count": 8,
                    "like_count": 310,
                    "quote_count": 4,
                    "impression_count": 8900,
                },
            },
        ],
        "includes": {
            "users": [
                {
                    "id": "2244994945",
                    "name": "AI Researcher",
                    "username": "airesearcher",
                    "verified": True,
                    "profile_image_url": "https://pbs.twimg.com/profile_images/1/avatar.png",
                },
                {
                    "id": "44196397",
                    "name": "Python Core",
                    "username": "ThePSF",
                    "verified": True,
                },
            ]
        },
        "meta": {
            "newest_id": "1840000000000000002",
            "oldest_id": "1840000000000000001",
            "result_count": 2,
            "next_token": "b26v89c19zqg8o3fo7gesq314yb9l2l4ptqy",
        },
    }


@pytest.fixture
def sample_single_post_json() -> dict[str, Any]:
    return {
        "data": {
            "id": "1840000000000000001",
            "text": "Excited to share our new research paper on AI agents! #Python #AI",
            "created_at": "2026-10-02T15:30:00.000Z",
            "author_id": "2244994945",
            "edit_history_tweet_ids": ["1840000000000000001"],
            "public_metrics": {
                "retweet_count": 142,
                "reply_count": 35,
                "like_count": 890,
                "quote_count": 12,
                "impression_count": 25400,
            },
        },
        "includes": {
            "users": [
                {
                    "id": "2244994945",
                    "name": "AI Researcher",
                    "username": "airesearcher",
                    "verified": True,
                    "profile_image_url": "https://pbs.twimg.com/profile_images/1/avatar.png",
                }
            ]
        },
    }
