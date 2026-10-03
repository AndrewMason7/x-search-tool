"""Domain models for X (Twitter) search and posts."""

from datetime import datetime

from pydantic import BaseModel, Field


class Author(BaseModel):
    """Author profile representation."""

    id: str
    username: str
    name: str
    verified: bool = False
    profile_image_url: str | None = None


class PublicMetrics(BaseModel):
    """Engagement metrics for a post."""

    retweet_count: int = 0
    reply_count: int = 0
    like_count: int = 0
    quote_count: int = 0
    impression_count: int | None = None


class Post(BaseModel):
    """Individual X post (tweet)."""

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
    """Response structure for recent search queries."""

    posts: list[Post] = Field(default_factory=list)
    result_count: int = 0
    newest_id: str | None = None
    oldest_id: str | None = None
    next_token: str | None = None


class RateLimitStatus(BaseModel):
    """Rate limit headers snapshot."""

    limit: int | None = None
    remaining: int | None = None
    reset_at: datetime | None = None
    reset_seconds: int | None = None
