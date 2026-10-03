"""Domain models for X (Twitter) search and posts."""

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Author(BaseModel):
    """Author profile representation."""

    model_config = ConfigDict(frozen=True)

    id: str
    username: str
    name: str
    verified: bool = False
    profile_image_url: str | None = None


class PublicMetrics(BaseModel):
    """Engagement metrics for a post."""

    model_config = ConfigDict(frozen=True)

    retweet_count: int = 0
    reply_count: int = 0
    like_count: int = 0
    quote_count: int = 0
    impression_count: int | None = None


class Post(BaseModel):
    """Individual X post (tweet)."""

    model_config = ConfigDict(frozen=True)

    id: str
    text: str
    created_at: datetime | None = None
    author: Author | None = None
    metrics: PublicMetrics | None = None
    edit_history_tweet_ids: list[str] = Field(default_factory=list)

    @property
    def url(self) -> str:
        """Returns the canonical URL for the post."""
        if self.author and self.author.username:
            return f"https://x.com/{self.author.username}/status/{self.id}"
        return f"https://x.com/i/status/{self.id}"


class SearchResponse(BaseModel):
    """Response structure for search queries."""

    model_config = ConfigDict(frozen=True)

    posts: list[Post] = Field(default_factory=list)
    result_count: int = 0
    newest_id: str | None = None
    oldest_id: str | None = None
    next_token: str | None = None


class RateLimitStatus(BaseModel):
    """Rate limit headers snapshot."""

    model_config = ConfigDict(frozen=True)

    limit: int | None = None
    remaining: int | None = None
    reset_at: datetime | None = None

    @property
    def reset_seconds(self) -> int | None:
        """Dynamically computes the remaining seconds until reset safely."""
        if not self.reset_at:
            return None
        reset_target = self.reset_at.astimezone(UTC)
        now = datetime.now(UTC)
        diff = (reset_target - now).total_seconds()
        return max(0, int(diff))

    @classmethod
    def from_headers(cls, headers: Any) -> "RateLimitStatus":
        """Parse rate limit headers including x-rate-limit and standard Retry-After."""
        limit_val = headers.get("x-rate-limit-limit")
        remaining_val = headers.get("x-rate-limit-remaining")
        reset_val = headers.get("x-rate-limit-reset")
        retry_after = headers.get("retry-after")

        limit = int(limit_val) if limit_val and limit_val.isdigit() else None
        remaining = int(remaining_val) if remaining_val and remaining_val.isdigit() else None

        reset_at: datetime | None = None
        if reset_val and reset_val.isdigit():
            reset_at = datetime.fromtimestamp(int(reset_val), UTC)
        elif retry_after:
            stripped = retry_after.strip()
            if stripped.isdigit():
                delta_sec = int(stripped)
                reset_at = datetime.fromtimestamp(datetime.now(UTC).timestamp() + delta_sec, UTC)
            else:
                try:
                    reset_at = parsedate_to_datetime(stripped).astimezone(UTC)
                except Exception:  # noqa: BLE001
                    reset_at = None

        return cls(limit=limit, remaining=remaining, reset_at=reset_at)


class CountBucket(BaseModel):
    """Time-bucket post volume count."""

    model_config = ConfigDict(frozen=True)

    start: datetime
    end: datetime
    tweet_count: int


class PostCountsResponse(BaseModel):
    """Aggregated post counts volume timeseries."""

    model_config = ConfigDict(frozen=True)

    total_count: int = 0
    granularity: str = "day"
    buckets: list[CountBucket] = Field(default_factory=list)
    next_token: str | None = None
