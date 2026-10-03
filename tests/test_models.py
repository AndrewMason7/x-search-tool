from datetime import UTC, datetime

from x_search.models import Author, Post, PublicMetrics, RateLimitStatus, SearchResponse


def test_author_model():
    author = Author(
        id="12345",
        username="elonmusk",
        name="Elon Musk",
        verified=True,
        profile_image_url="https://pbs.twimg.com/profile_images/1/pic.jpg",
    )
    assert author.id == "12345"
    assert author.username == "elonmusk"
    assert author.name == "Elon Musk"
    assert author.verified is True
    assert author.profile_image_url == "https://pbs.twimg.com/profile_images/1/pic.jpg"


def test_author_defaults():
    author = Author(id="12345", username="user1", name="User One")
    assert author.verified is False
    assert author.profile_image_url is None


def test_public_metrics_defaults():
    metrics = PublicMetrics()
    assert metrics.like_count == 0
    assert metrics.retweet_count == 0
    assert metrics.reply_count == 0
    assert metrics.quote_count == 0
    assert metrics.impression_count is None


def test_post_url_with_author():
    author = Author(id="100", username="jack", name="Jack")
    post = Post(
        id="20",
        text="just setting up my twttr",
        author=author,
    )
    assert post.url == "https://x.com/jack/status/20"


def test_post_url_without_author():
    post = Post(
        id="20",
        text="just setting up my twttr",
        author=None,
    )
    assert post.url == "https://x.com/i/status/20"


def test_search_response_model():
    author = Author(id="100", username="jack", name="Jack")
    post = Post(id="20", text="hello", author=author)
    res = SearchResponse(
        posts=[post],
        result_count=1,
        newest_id="20",
        oldest_id="20",
        next_token="token_abc",
    )
    assert len(res.posts) == 1
    assert res.result_count == 1
    assert res.next_token == "token_abc"


from datetime import timedelta


def test_rate_limit_status():
    future = datetime.now(UTC) + timedelta(seconds=900)
    status = RateLimitStatus(limit=180, remaining=179, reset_at=future)
    assert status.limit == 180
    assert status.remaining == 179
    assert status.reset_at == future
    assert status.reset_seconds is not None
    assert 895 <= status.reset_seconds <= 900


def test_rate_limit_status_naive_datetime():
    naive_future = datetime.now() + timedelta(seconds=600)  # noqa: DTZ005
    status = RateLimitStatus(limit=100, remaining=50, reset_at=naive_future)
    # Must not raise TypeError when subtracting
    assert status.reset_seconds is not None
    assert 590 <= status.reset_seconds <= 605


def test_post_counts_models():
    from x_search.models import CountBucket, PostCountsResponse

    start = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2026, 10, 2, 0, 0, 0, tzinfo=UTC)
    bucket = CountBucket(start=start, end=end, tweet_count=1520)
    assert bucket.tweet_count == 1520

    resp = PostCountsResponse(
        total_count=1520,
        granularity="day",
        buckets=[bucket],
        next_token="token_count",
    )
    assert resp.total_count == 1520
    assert resp.granularity == "day"
    assert len(resp.buckets) == 1
    assert resp.next_token == "token_count"


def test_rate_limit_from_headers_retry_after_delta():
    headers = {"retry-after": "120"}
    status = RateLimitStatus.from_headers(headers)
    assert status.reset_seconds is not None
    assert 115 <= status.reset_seconds <= 120


def test_rate_limit_from_headers_retry_after_date():
    future_dt = datetime.now(UTC) + timedelta(seconds=180)
    headers = {"retry-after": future_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")}
    status = RateLimitStatus.from_headers(headers)
    assert status.reset_seconds is not None
    assert 170 <= status.reset_seconds <= 185


def test_models_are_frozen():
    import pytest
    from pydantic import ValidationError

    author = Author(id="1", username="u", name="n")
    with pytest.raises(ValidationError):
        author.username = "mutated"  # type: ignore[misc]
