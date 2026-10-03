"""FastMCP server exposing tools for searching X (Twitter) and inspecting posts."""

import functools
from collections.abc import Callable, Coroutine
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

from x_search.client import (
    XAPIAuthError,
    XAPIError,
    XClient,
    XCredentialsError,
    XRateLimitError,
    XValidationError,
)
from x_search.models import Post, PostCountsResponse, SearchResponse

mcp = MCPServer(
    "x-search",
    description="X (Twitter) recent search, full-archive search, post lookup, and rate limit suite",
)

_client_instance: XClient | None = None

CREDENTIALS_HELP = (
    "### Error: Missing X API Credentials\n\n"
    "The X API Bearer Token is not configured.\n\n"
    "**Setup instructions:**\n"
    "1. Set `X_BEARER_TOKEN` (or `TWITTER_BEARER_TOKEN`) in your environment, or\n"
    "2. Add `X_BEARER_TOKEN=your_token` to a `.env` file in the tool directory."
)


def get_client() -> XClient:
    """Returns or creates the singleton XClient instance."""
    global _client_instance
    if _client_instance is None:
        _client_instance = XClient()
    return _client_instance


# FIX #E5.1 & #E1.1 (per Tom & Marcus): Contextual MCP error boundary decorator with customizable auth help
def mcp_error_boundary(
    func: Callable[..., Coroutine[Any, Any, str]] | None = None,
    *,
    auth_help: str | None = None,
) -> Any:
    """Decorator converting client exceptions into clean, formatted user guidance with custom hints."""

    def decorator(
        f: Callable[..., Coroutine[Any, Any, str]],
    ) -> Callable[..., Coroutine[Any, Any, str]]:
        @functools.wraps(f)
        async def wrapper(*args: Any, **kwargs: Any) -> str:
            try:
                return await f(*args, **kwargs)
            except XCredentialsError:
                return CREDENTIALS_HELP
            except XValidationError as e:
                return f"### Invalid Input\n\n{e}"
            except XRateLimitError as e:
                countdown = (
                    f"\n\n**Countdown to Reset:** ~{e.rate_limit.reset_seconds} seconds"
                    if e.rate_limit and e.rate_limit.reset_seconds is not None
                    else ""
                )
                return (
                    f"### Rate Limit Exceeded\n\n{e}{countdown}\n"
                    "Please wait until the rate limit window resets before querying again."
                )
            except XAPIAuthError as e:
                hint = (
                    auth_help
                    or "Please verify that your X Bearer Token is valid and has search permissions."
                )
                return f"### Authentication Failure\n\n{e}\n{hint}"
            except XAPIError as e:
                return f"### X API Error\n\n{e}"
            except Exception as e:  # noqa: BLE001
                return f"### Unexpected Error\n\n{e}"

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


def format_post(post: Post) -> str:
    """Format an individual Post into readable Markdown."""
    author_line = "Anonymous"
    if post.author:
        badge = " ✓" if post.author.verified else ""
        author_line = f"**{post.author.name}** (@{post.author.username}{badge})"

    created = (
        post.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if post.created_at else "Unknown date"
    )

    metrics_str = ""
    if post.metrics:
        parts = [
            f"❤️ {post.metrics.like_count:,} likes",
            f"🔁 {post.metrics.retweet_count:,} reposts",
            f"💬 {post.metrics.reply_count:,} replies",
        ]
        if post.metrics.impression_count is not None:
            parts.append(f"👁️ {post.metrics.impression_count:,} views")
        metrics_str = " | ".join(parts)

    quote_body = "\n".join(f"> {line}" for line in post.text.strip().splitlines())

    lines = [
        f"### {author_line}",
        quote_body,
        "",
        f"- **Date:** {created}",
    ]
    if metrics_str:
        lines.append(f"- **Engagement:** {metrics_str}")
    lines.append(f"- **URL:** {post.url}")

    return "\n".join(lines)


# FIX #E5.1 (per Tom): Semantic scope parameter eliminates claiming 2006 historical tweets are "recent"
def format_search_response(res: SearchResponse, scope_label: str = "recent") -> str:
    """Format SearchResponse into a structured Markdown document."""
    label = f" {scope_label}" if scope_label else ""
    if not res.posts:
        return f"No{label} posts found matching your search query."

    out: list[str] = [
        f"Found **{res.result_count}**{label} post{'s' if res.result_count != 1 else ''}:\n"
    ]
    for i, post in enumerate(res.posts, 1):
        out.append(f"#### Post {i}")
        out.append(format_post(post))
        out.append("\n---\n")

    if res.next_token:
        out.append(
            f"\n> **Next Page Token:** `{res.next_token}`\n"
            "> Pass this token as `next_token` to load the next page of results."
        )

    return "\n".join(out)


def format_post_counts(res: PostCountsResponse, query: str, full_archive: bool) -> str:
    """Format post counts timeseries into markdown table."""
    scope = "Full Archive (2006–Present)" if full_archive else "Recent (Last 7 Days)"
    out = [
        "### X Post Volume Counts\n",
        f"- **Query:** `{query}`",
        f"- **Total Posts:** {res.total_count:,}",
        f"- **Granularity:** {res.granularity}",
        f"- **Scope:** {scope}\n",
    ]
    if not res.buckets:
        out.append("No bucket counts returned for the specified window.")
        return "\n".join(out)

    out.append("| Start Time (UTC) | End Time (UTC) | Post Count |")
    out.append("| :--- | :--- | :--- |")
    for b in res.buckets:
        start_str = b.start.strftime("%Y-%m-%d %H:%M:%S")
        end_str = b.end.strftime("%Y-%m-%d %H:%M:%S")
        out.append(f"| {start_str} | {end_str} | {b.tweet_count:,} |")

    return "\n".join(out)


@mcp.tool()
@mcp_error_boundary
async def search_recent_posts(
    query: str,
    max_results: int = 10,
    next_token: str | None = None,
) -> str:
    """Search recent posts (last 7 days) on X (Twitter).

    Supports search operators such as:
    - from:username (posts by user)
    - @username (mentions of user)
    - #hashtag (posts containing hashtag)
    - "exact phrase" (exact phrase match)
    - url:domain.com (links to domain)
    - lang:en (language filter)
    - -is:retweet (exclude retweets)
    - -is:reply (exclude replies)
    - has:images / has:media (media filters)

    Args:
        query: The search query string with optional operators.
        max_results: Number of posts to retrieve (10 to 100, default 10).
        next_token: Optional pagination token from a previous search.
    """
    client = get_client()
    res = await client.search_recent(
        query=query,
        max_results=max_results,
        next_token=next_token,
    )
    return format_search_response(res, scope_label="recent")


@mcp.tool()
@mcp_error_boundary
async def get_post(post_id_or_url: str) -> str:
    """Fetch details and metrics for a specific post by ID or URL.

    Args:
        post_id_or_url: A numeric post ID (e.g. '1840000000000000001') or a URL
                        (e.g. 'https://x.com/username/status/1840000000000000001').
    """
    client = get_client()
    post = await client.get_post(post_id_or_url)
    return format_post(post)


@mcp.tool()
@mcp_error_boundary
async def check_rate_limits() -> str:
    """Check the remaining request quota and reset time for the X API search endpoint."""
    client = get_client()
    status = client.get_rate_limit_status()
    if status.limit is None:
        return (
            "### Rate Limit Status\n\n"
            "No requests have been executed yet in this session. "
            "Rate limit headers will be populated upon the first API call."
        )

    reset_str = status.reset_at.strftime("%Y-%m-%d %H:%M:%S UTC") if status.reset_at else "Unknown"
    return (
        "### X Search API Rate Limit Status\n\n"
        f"- **Remaining Quota:** {status.remaining} / {status.limit} requests\n"
        f"- **Resets At:** {reset_str}\n"
        f"- **Countdown:** ~{status.reset_seconds} seconds\n"
    )


@mcp.tool()
@mcp_error_boundary(
    auth_help="Full-archive search requires an X developer account tier with archive access (Pro or Academic)."
)
async def search_full_archive_posts(
    query: str,
    start_time: str | None = None,
    end_time: str | None = None,
    max_results: int = 10,
    next_token: str | None = None,
    sort_order: str = "recency",
) -> str:
    """Search the complete historical archive of posts on X (Twitter) from March 2006 to present.

    Note: Requires an X API account tier with full-archive search access.

    Args:
        query: Search query string (up to 1024 characters). Supports boolean operators.
        start_time: Oldest UTC timestamp in ISO 8601 format (e.g. '2020-01-01T00:00:00Z').
        end_time: Most recent UTC timestamp in ISO 8601 format (e.g. '2020-12-31T23:59:59Z').
        max_results: Posts per page (10 to 500, default 10).
        next_token: Pagination token from previous search result.
        sort_order: 'recency' or 'relevancy' (default 'recency').
    """
    client = get_client()
    res = await client.search_all(
        query=query,
        start_time=start_time,
        end_time=end_time,
        max_results=max_results,
        next_token=next_token,
        sort_order=sort_order,
    )
    return format_search_response(res, scope_label="")


@mcp.tool()
@mcp_error_boundary
async def get_post_counts(
    query: str,
    granularity: str = "day",
    start_time: str | None = None,
    end_time: str | None = None,
    full_archive: bool = False,
) -> str:
    """Analyze post volume and trend counts on X without fetching individual posts.

    Args:
        query: Search query to count matching posts.
        granularity: Time bucket grouping: 'day', 'hour', or 'minute' (default: 'day').
        start_time: Oldest UTC timestamp in ISO 8601 format (e.g. '2026-09-01T00:00:00Z').
        end_time: Most recent UTC timestamp in ISO 8601 format.
        full_archive: Set to True for historical counts back to 2006 (requires archive access).
                      Default False queries the last 7 days.
    """
    client = get_client()
    res = await client.get_counts(
        query=query,
        granularity=granularity,
        start_time=start_time,
        end_time=end_time,
        full_archive=full_archive,
    )
    return format_post_counts(res, query=query, full_archive=full_archive)
