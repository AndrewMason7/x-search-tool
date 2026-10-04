"""Unit tests for X API v2 client."""

from typing import Any

import httpx
import pytest

from x_search.client import (
    XAPIAuthError,
    XAPIError,
    XClient,
    XCredentialsError,
    XRateLimitError,
    XValidationError,
    extract_post_id,
    validate_iso_timestamp,
    validate_time_range,
)


def test_missing_credentials(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("TWITTER_BEARER_TOKEN", raising=False)
    with pytest.raises(XCredentialsError, match="Bearer Token"):
        XClient(bearer_token=None)


def test_whitespace_only_credentials(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("TWITTER_BEARER_TOKEN", raising=False)
    with pytest.raises(XCredentialsError, match="Bearer Token"):
        XClient(bearer_token="   ")


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

        # Plural /statuses/ URL and markdown brackets
        post3 = await client.get_post("<https://twitter.com/user/statuses/1840000000000000001>")
        assert post3.id == "1840000000000000001"


@pytest.mark.asyncio
async def test_get_post_invalid_identifier():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XValidationError, match="Invalid post ID or URL"):
            await client.get_post("not_a_valid_id_or_url")


@pytest.mark.asyncio
async def test_search_recent_empty_query():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XValidationError, match="query cannot be empty"):
            await client.search_recent(query="   ")


@pytest.mark.asyncio
async def test_search_recent_query_too_long():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        long_query = "python " * 80  # > 512 chars
        with pytest.raises(XValidationError, match="512 characters"):
            await client.search_recent(query=long_query)


@pytest.mark.asyncio
async def test_search_recent_nullable_fields():
    payload = {
        "data": [
            {
                "id": "1840000000000000001",
                "text": "Post with no author hydration",
                "author_id": "999",
            }
        ],
        "includes": {"users": None},
        "meta": None,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        res = await client.search_recent(query="test")
        assert len(res.posts) == 1
        assert res.posts[0].author is None
        assert res.result_count == 1


@pytest.mark.asyncio
async def test_search_recent_network_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Connection timed out")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(
            bearer_token="test_token",
            http_client=http_client,
            backoff_base=0.0001,
        )
        with pytest.raises(XAPIError, match="Network error"):
            await client.search_recent(query="test")


@pytest.mark.asyncio
async def test_search_all_success(sample_search_json: dict[str, Any]):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2/tweets/search/all"
        assert "start_time=2020-01-01T00%3A00%3A00Z" in str(request.url)
        assert "end_time=2020-12-31T23%3A59%3A59Z" in str(request.url)
        assert "max_results=200" in str(request.url)
        return httpx.Response(200, json=sample_search_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        res = await client.search_all(
            query="python",
            start_time="2020-01-01T00:00:00Z",
            end_time="2020-12-31T23:59:59Z",
            max_results=200,
        )
        assert len(res.posts) == 2
        assert res.posts[0].author is not None


@pytest.mark.asyncio
async def test_search_all_clamps_max_results(sample_search_json: dict[str, Any]):
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(200, json=sample_search_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        await client.search_all(query="python", max_results=5)
        assert "max_results=10" in captured[0]

        await client.search_all(query="python", max_results=800)
        assert "max_results=500" in captured[1]


@pytest.mark.asyncio
async def test_search_all_query_length_limit():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        too_long = "python " * 150  # > 1024 chars
        with pytest.raises(XValidationError, match="1024 characters"):
            await client.search_all(query=too_long)


@pytest.mark.asyncio
async def test_get_counts_recent_success():
    payload = {
        "data": [
            {
                "end": "2026-10-02T00:00:00.000Z",
                "start": "2026-10-01T00:00:00.000Z",
                "tweet_count": 520,
            }
        ],
        "meta": {"total_tweet_count": 520},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2/tweets/counts/recent"
        assert "granularity=day" in str(request.url)
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        counts = await client.get_counts(query="python", granularity="day")
        assert counts.total_count == 520
        assert counts.granularity == "day"
        assert len(counts.buckets) == 1
        assert counts.buckets[0].tweet_count == 520


@pytest.mark.asyncio
async def test_get_counts_full_archive_success():
    payload = {
        "data": [
            {
                "end": "2010-01-02T00:00:00.000Z",
                "start": "2010-01-01T00:00:00.000Z",
                "tweet_count": 42,
            }
        ],
        "meta": {"total_tweet_count": 42},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2/tweets/counts/all"
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        counts = await client.get_counts(query="python", full_archive=True)
        assert counts.total_count == 42


@pytest.mark.asyncio
async def test_get_counts_invalid_granularity():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XValidationError, match="Invalid granularity"):
            await client.get_counts(query="python", granularity="month")


def test_client_repr_masks_token():
    client = XClient(bearer_token="AAAAAAAAAAAAAAAAAAAAAMLArwAAAAAAgExampleSecretToken123456789")
    repr_str = repr(client)
    str_str = str(client)
    assert "AAAA...6789" in repr_str
    assert "gExampleSecretToken" not in repr_str
    assert "gExampleSecretToken" not in str_str


def test_extract_post_id_untrusted_domain():
    from x_search.client import extract_post_id

    with pytest.raises(XValidationError, match="untrusted domain"):
        extract_post_id("https://phishing-site.ru/user/status/9876543210")


def test_extract_post_id_too_long():
    from x_search.client import extract_post_id

    with pytest.raises(XValidationError, match="Invalid post ID or URL"):
        extract_post_id("1" * 600)


@pytest.mark.asyncio
async def test_client_persistent_pooling():
    client = XClient(bearer_token="test_token")
    try:
        http1 = await client._get_http_client()
        http2 = await client._get_http_client()
        assert http1 is http2
        assert not http1.is_closed
    finally:
        await client.aclose()
        assert http1.is_closed


@pytest.mark.asyncio
async def test_client_context_manager():
    async with XClient(bearer_token="test_token") as client:
        http = await client._get_http_client()
        assert not http.is_closed
    assert http.is_closed


@pytest.mark.asyncio
async def test_client_transient_retry_success(sample_single_post_json: dict[str, Any]):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(200, json=sample_single_post_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(
            bearer_token="test_token",
            http_client=http_client,
            max_retries=2,
            backoff_base=0.01,
        )
        post = await client.get_post("1840000000000000001")
        assert calls == 2
        assert post.id == "1840000000000000001"


@pytest.mark.asyncio
async def test_get_counts_null_meta_total_tweet_count():
    # Simulates zero-match response where X API sets total_tweet_count to null
    payload: dict[str, Any] = {
        "data": [],
        "meta": {"total_tweet_count": None},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        counts = await client.get_counts(query="nonexistent_trend")
        assert counts.total_count == 0
        assert len(counts.buckets) == 0


def test_validate_iso_timestamp_valid_and_invalid():
    assert validate_iso_timestamp("start_time", "2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"
    assert (
        validate_iso_timestamp("start_time", "2026-10-03T12:00:00+00:00")
        == "2026-10-03T12:00:00+00:00"
    )

    with pytest.raises(XValidationError, match="Invalid 'start_time' timestamp format"):
        validate_iso_timestamp("start_time", "yesterday")

    with pytest.raises(XValidationError, match="cannot be empty"):
        validate_iso_timestamp("start_time", "   ")


@pytest.mark.asyncio
async def test_search_all_invalid_start_time():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XValidationError, match="Invalid 'start_time' timestamp format"):
            await client.search_all(query="python", start_time="yesterday")


@pytest.mark.asyncio
async def test_client_transient_retry_remote_protocol_error(
    sample_single_post_json: dict[str, Any],
):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.RemoteProtocolError("Server disconnected without response")
        return httpx.Response(200, json=sample_single_post_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(
            bearer_token="test_token",
            http_client=http_client,
            max_retries=2,
            backoff_base=0.0001,
        )
        post = await client.get_post("1840000000000000001")
        assert calls == 2
        assert post.id == "1840000000000000001"


def test_validate_iso_timestamp_rfc3339_strictness():
    # Valid with UTC 'Z' or offset
    assert validate_iso_timestamp("start_time", "2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"
    assert (
        validate_iso_timestamp("start_time", "2026-01-01T00:00:00+00:00")
        == "2026-01-01T00:00:00+00:00"
    )

    # Date-only string must fail
    with pytest.raises(XValidationError, match="Expected RFC 3339 with timezone"):
        validate_iso_timestamp("start_time", "2026-01-01")

    # Naive timestamp without timezone must fail
    with pytest.raises(XValidationError, match="Expected RFC 3339 with timezone"):
        validate_iso_timestamp("start_time", "2026-01-01T12:00:00")


def test_validate_time_range_bounds():
    # Valid chronological order
    validate_time_range("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")

    # Inverted order raises validation error
    with pytest.raises(XValidationError, match="must be earlier than end_time"):
        validate_time_range("2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z")

    # Equal timestamps raise validation error
    with pytest.raises(XValidationError, match="must be earlier than end_time"):
        validate_time_range("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")


def test_extract_post_id_boundary_and_length():
    # Valid bounded IDs
    assert extract_post_id("https://x.com/user/status/1840000000000000001") == "1840000000000000001"
    assert (
        extract_post_id("https://x.com/user/status/1840000000000000001?s=20")
        == "1840000000000000001"
    )

    # Overly long numeric ID (> 30 digits) rejected
    with pytest.raises(XValidationError, match="Invalid post ID or URL"):
        extract_post_id("https://x.com/user/status/" + "9" * 35)

    # Trailing alpha garbage in URL path rejected
    with pytest.raises(XValidationError, match="Invalid post ID or URL"):
        extract_post_id("https://x.com/user/status/1840000000000000001bad")


@pytest.mark.asyncio
async def test_sort_order_validation():
    async with httpx.AsyncClient() as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        with pytest.raises(XValidationError, match="Invalid sort_order"):
            await client.search_recent(query="test", sort_order="invalid_order")

        with pytest.raises(XValidationError, match="Invalid sort_order"):
            await client.search_all(query="test", sort_order="random_order")


@pytest.mark.asyncio
async def test_retry_after_on_transient_503(sample_single_post_json: dict[str, Any]):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, headers={"retry-after": "0"})
        return httpx.Response(200, json=sample_single_post_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(
            bearer_token="test_token",
            http_client=http_client,
            max_retries=2,
            backoff_base=0.0001,
        )
        post = await client.get_post("1840000000000000001")
        assert calls == 2
        assert post.id == "1840000000000000001"


@pytest.mark.asyncio
async def test_search_recent_unicode_and_emojis(sample_search_json: dict[str, Any]):
    captured_query = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_query
        captured_query = str(request.url)
        return httpx.Response(200, json=sample_search_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(bearer_token="test_token", http_client=http_client)
        res = await client.search_recent(query="🚀 #AI 日本語 🐍")
        assert len(res.posts) == 2
        assert "%F0%9F%9A%80" in captured_query or "🚀" in captured_query


@pytest.mark.asyncio
async def test_retry_on_read_and_write_errors(sample_single_post_json: dict[str, Any]):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ReadError("Connection reset by peer", request=request)
        if calls == 2:
            raise httpx.WriteError("Broken pipe", request=request)
        return httpx.Response(200, json=sample_single_post_json)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = XClient(
            bearer_token="test_token",
            http_client=http_client,
            max_retries=3,
            backoff_base=0.0001,
        )
        post = await client.get_post("1840000000000000001")
        assert calls == 3
        assert post.id == "1840000000000000001"


def test_calculate_backoff_jitter():
    client = XClient(bearer_token="test_token", backoff_base=1.0)
    # retry-after has positive jitter added when > 0
    val_after = client._calculate_backoff(1, retry_after=5.5)
    assert 5.5 <= val_after <= 6.0

    # retry_after == 0 has 0 jitter
    assert client._calculate_backoff(1, retry_after=0.0) == 0.0

    # Full jitter ensures 0.0 <= backoff <= ceiling
    # attempt 1: cap = min(30.0, 1.0 * 2^1) = 2.0
    for _ in range(20):
        val = client._calculate_backoff(1)
        assert 0.01 <= val <= 2.0

    # attempt 3: cap = min(30.0, 1.0 * 2^3) = 8.0
    for _ in range(20):
        val = client._calculate_backoff(3)
        assert 0.01 <= val <= 8.0


