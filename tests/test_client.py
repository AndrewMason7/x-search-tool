"""Unit tests for X API v2 client."""

from typing import Any

import httpx
import pytest

from x_search.client import XAPIAuthError, XAPIError, XClient, XRateLimitError


def test_missing_credentials(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("TWITTER_BEARER_TOKEN", raising=False)
    with pytest.raises(ValueError, match="Bearer Token"):
        XClient(bearer_token=None)


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("X_BEARER_TOKEN", "mock_env_token")
    client = XClient()
    assert client.bearer_token == "mock_env_token"


def test_credentials_fallback_twitter_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("TWITTER_BEARER_TOKEN", "mock_fallback_token")
    client = XClient()
    assert client.bearer_token == "mock_fallback_token"


@pytest.mark.asyncio
async def test_search_recent_success(sample_search_json: dict[str, Any]):
    headers = {
        "x-rate-limit-limit": "180",
        "x-rate-limit-remaining": "175",
        "x-rate-limit-reset": "1790000000",
        "content-type": "application/json",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2/tweets/search/recent"
        assert request.headers["Authorization"] == "Bearer test_token"
        assert "query=python" in str(request.url)
        assert "max_results=10" in str(request.url)
        assert "author_id" in str(request.url)
        return httpx.Response(200, json=sample_search_json, headers=headers)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        res = await client.search_recent(query="python", max_results=10)

        assert res.result_count == 2
        assert len(res.posts) == 2

        first_post = res.posts[0]
        assert first_post.id == "1840000000000000001"
        assert first_post.text.startswith("Excited to share")
        assert first_post.author is not None
        assert first_post.author.username == "airesearcher"
        assert first_post.author.name == "AI Researcher"
        assert first_post.author.verified is True
        assert first_post.metrics is not None
        assert first_post.metrics.like_count == 890
        assert first_post.url == "https://x.com/airesearcher/status/1840000000000000001"

        second_post = res.posts[1]
        assert second_post.author is not None
        assert second_post.author.username == "ThePSF"

        assert res.next_token == "b26v89c19zqg8o3fo7gesq314yb9l2l4ptqy"

        rate_limit = client.get_rate_limit_status()
        assert rate_limit.limit == 180
        assert rate_limit.remaining == 175
        assert rate_limit.reset_at is not None


@pytest.mark.asyncio
async def test_search_recent_clamps_max_results(sample_search_json: dict[str, Any]):
    captured_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_urls.append(str(request.url))
        return httpx.Response(200, json=sample_search_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)

        await client.search_recent(query="test", max_results=3)
        assert "max_results=10" in captured_urls[0]

        await client.search_recent(query="test", max_results=250)
        assert "max_results=100" in captured_urls[1]


@pytest.mark.asyncio
async def test_search_recent_auth_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Unauthorized", "detail": "Unauthorized access"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="bad_token", http_client=http_client)
        with pytest.raises(XAPIAuthError, match="Unauthorized"):
            await client.search_recent(query="test")


@pytest.mark.asyncio
async def test_search_recent_rate_limit_error():
    headers = {
        "x-rate-limit-limit": "180",
        "x-rate-limit-remaining": "0",
        "x-rate-limit-reset": "1790000000",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"title": "Too Many Requests", "detail": "Rate limit exceeded"},
            headers=headers,
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XRateLimitError, match="Rate limit exceeded"):
            await client.search_recent(query="test")

        rate_limit = client.get_rate_limit_status()
        assert rate_limit.remaining == 0


@pytest.mark.asyncio
async def test_search_recent_bad_request():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"errors": [{"message": "There were errors with your query: [has:invalid]"}]},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XAPIError, match="has:invalid"):
            await client.search_recent(query="has:invalid")


@pytest.mark.asyncio
async def test_get_post_by_id(sample_single_post_json: dict[str, Any]):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2/tweets/1840000000000000001"
        return httpx.Response(200, json=sample_single_post_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        post = await client.get_post("1840000000000000001")
        assert post is not None
        assert post.id == "1840000000000000001"
        assert post.author is not None
        assert post.author.username == "airesearcher"


@pytest.mark.asyncio
async def test_get_post_by_url(sample_single_post_json: dict[str, Any]):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2/tweets/1840000000000000001"
        return httpx.Response(200, json=sample_single_post_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)

        # x.com URL
        post1 = await client.get_post("https://x.com/user/status/1840000000000000001")
        assert post1.id == "1840000000000000001"

        # twitter.com URL
        post2 = await client.get_post("https://twitter.com/user/status/1840000000000000001?s=20")
        assert post2.id == "1840000000000000001"


@pytest.mark.asyncio
async def test_get_post_invalid_identifier():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(ValueError, match="Invalid post ID or URL"):
            await client.get_post("not_a_valid_id_or_url")
