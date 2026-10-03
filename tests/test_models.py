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
