from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from x_search.models import (
    Author,
    CountBucket,
    Post,
    PostCountsResponse,
    PublicMetrics,
    RateLimitStatus,
    SearchResponse,
)


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


# FIX #E4.1 (per Maya): Deterministic assertion testing on calculated reset_at boundaries
def test_rate_limit_from_headers_retry_after_delta():
    headers = {"retry-after": "120"}
    before = datetime.now(UTC)
    status = RateLimitStatus.from_headers(headers)
    after = datetime.now(UTC)
    assert status.reset_at is not None
    # Verify reset_at falls squarely within [before + 120s, after + 120s]
    assert before + timedelta(seconds=120) <= status.reset_at <= after + timedelta(seconds=120)
    assert status.reset_seconds is not None
    assert 118 <= status.reset_seconds <= 120


def test_rate_limit_from_headers_retry_after_date():
    target_dt = (datetime.now(UTC) + timedelta(seconds=180)).replace(microsecond=0)
    headers = {"retry-after": target_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")}
    status = RateLimitStatus.from_headers(headers)
    assert status.reset_at is not None
    assert abs((status.reset_at - target_dt).total_seconds()) <= 1.0
    assert status.reset_seconds is not None
    assert 178 <= status.reset_seconds <= 180


def test_rate_limit_from_headers_invalid_retry_after():
    # Negative or non-numeric/non-date headers should result in None
    status = RateLimitStatus.from_headers({"retry-after": "-50"})
    assert status.reset_at is None
    assert status.reset_seconds is None

    status_bad = RateLimitStatus.from_headers({"retry-after": "invalid_date_format"})
    assert status_bad.reset_at is None
    assert status_bad.reset_seconds is None


def test_models_are_frozen():
    author = Author(id="1", username="u", name="n")
    with pytest.raises(ValidationError):
        author.username = "mutated"  # type: ignore[misc]
