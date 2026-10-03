"""Unit tests for FastMCP server tool handlers and formatting."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from x_search.client import (
    XAPIAuthError,
    XCredentialsError,
    XRateLimitError,
    XValidationError,
)
from x_search.models import Author, Post, PublicMetrics, RateLimitStatus, SearchResponse
from x_search.server import check_rate_limits, format_post, get_post, search_recent_posts


def test_format_post():
    author = Author(id="123", username="testuser", name="Test User", verified=True)
    metrics = PublicMetrics(like_count=42, retweet_count=7, reply_count=3)
    created_at = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    post = Post(
        id="999",
        text="Hello world!\nLine two of tweet.",
        author=author,
        metrics=metrics,
        created_at=created_at,
    )
    formatted = format_post(post)
    assert "@testuser" in formatted
    assert "Test User" in formatted
    assert "> Hello world!" in formatted
    assert "> Line two of tweet." in formatted
    assert "42" in formatted
    assert "https://x.com/testuser/status/999" in formatted


@pytest.mark.asyncio
async def test_search_recent_posts_tool_success():
    author = Author(id="123", username="testuser", name="Test User")
    post = Post(id="999", text="Hello AI", author=author)
    mock_resp = SearchResponse(posts=[post], result_count=1, next_token="token_xyz")

    with patch("x_search.server.get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.search_recent.return_value = mock_resp
        mock_get_client.return_value = mock_client

        output = await search_recent_posts("Hello AI", max_results=10)
        assert "@testuser" in output
        assert "Hello AI" in output
        assert "token_xyz" in output


@pytest.mark.asyncio
async def test_search_recent_posts_tool_empty():
    mock_resp = SearchResponse(posts=[], result_count=0)

    with patch("x_search.server.get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.search_recent.return_value = mock_resp
        mock_get_client.return_value = mock_client

        output = await search_recent_posts("nonexistent_query_xyz")
        assert "No recent posts found" in output


@pytest.mark.asyncio
async def test_search_recent_posts_missing_token():
    with patch(
        "x_search.server.get_client",
        side_effect=XCredentialsError("Bearer token not set"),
    ):
        output = await search_recent_posts("test")
        assert "Error: Missing X API Credentials" in output
        assert "X_BEARER_TOKEN" in output


@pytest.mark.asyncio
async def test_search_recent_posts_validation_error():
    with patch(
        "x_search.server.get_client",
        side_effect=XValidationError("Query too long"),
    ):
        output = await search_recent_posts("test")
        assert "Invalid Input" in output
        assert "Query too long" in output


from datetime import timedelta


@pytest.mark.asyncio
async def test_search_recent_posts_rate_limited():
    future = datetime.now(UTC) + timedelta(seconds=300)
    status = RateLimitStatus(limit=180, remaining=0, reset_at=future)
    with patch("x_search.server.get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.search_recent.side_effect = XRateLimitError(
            "Rate limit exceeded", rate_limit=status
        )
        mock_get_client.return_value = mock_client

        output = await search_recent_posts("test")
        assert "Rate Limit Exceeded" in output
        assert "Countdown to Reset" in output


@pytest.mark.asyncio
async def test_search_recent_posts_auth_error():
    with patch("x_search.server.get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.search_recent.side_effect = XAPIAuthError("Unauthorized token")
        mock_get_client.return_value = mock_client

        output = await search_recent_posts("test")
        assert "Authentication Failure" in output


@pytest.mark.asyncio
async def test_get_post_tool_success():
    author = Author(id="123", username="testuser", name="Test User")
    post = Post(id="999", text="Specific tweet content", author=author)

    with patch("x_search.server.get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.get_post.return_value = post
        mock_get_client.return_value = mock_client

        output = await get_post("999")
        assert "@testuser" in output
        assert "Specific tweet content" in output


@pytest.mark.asyncio
async def test_get_post_missing_token():
    with patch(
        "x_search.server.get_client",
        side_effect=XCredentialsError("Bearer token not set"),
    ):
        output = await get_post("999")
        assert "Error: Missing X API Credentials" in output
        assert "Invalid Input" not in output


@pytest.mark.asyncio
async def test_check_rate_limits_missing_token():
    with patch(
        "x_search.server.get_client",
        side_effect=XCredentialsError("Bearer token not set"),
    ):
        output = await check_rate_limits()
        assert "Error: Missing X API Credentials" in output


@pytest.mark.asyncio
async def test_check_rate_limits_tool():
    future = datetime.now(UTC) + timedelta(seconds=420)
    status = RateLimitStatus(limit=180, remaining=150, reset_at=future)

    with patch("x_search.server.get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.get_rate_limit_status = MagicMock(return_value=status)
        mock_get_client.return_value = mock_client

        output = await check_rate_limits()
        assert "150 / 180" in output
        assert "Countdown:" in output
