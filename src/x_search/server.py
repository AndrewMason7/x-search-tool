try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

from x_search.client import XAPIAuthError, XAPIError, XClient, XRateLimitError
from x_search.models import Post, SearchResponse

mcp = MCPServer(
    "x-search",
    description="X (Twitter) recent search, post lookup, and rate limit inspection suite",
)

_client_instance: XClient | None = None


def get_client() -> XClient:
    """Returns or creates the singleton XClient instance."""
    global _client_instance
    if _client_instance is None:
        _client_instance = XClient()
    return _client_instance


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

    lines = [
        f"### {author_line}",
        f"> {post.text.strip()}",
        "",
        f"- **Date:** {created}",
    ]
    if metrics_str:
        lines.append(f"- **Engagement:** {metrics_str}")
    lines.append(f"- **URL:** {post.url}")

    return "\n".join(lines)


def format_search_response(res: SearchResponse) -> str:
    """Format SearchResponse into a structured Markdown document."""
    if not res.posts:
        return "No recent posts found matching your search query."

    out: list[str] = [
        f"Found **{res.result_count}** recent post{'s' if res.result_count != 1 else ''}:\n"
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


@mcp.tool()
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
    try:
        client = get_client()
        res = await client.search_recent(
            query=query,
            max_results=max_results,
            next_token=next_token,
        )
        return format_search_response(res)
    except ValueError as e:
        return (
            "### Error: Missing X API Credentials\n\n"
            f"{e}\n\n"
            "To use X search, set the `X_BEARER_TOKEN` (or `TWITTER_BEARER_TOKEN`) "
            "environment variable or add it to `.env` in the tool directory."
        )
    except XRateLimitError as e:
        return f"### Rate Limit Exceeded\n\n{e}\nPlease wait until the rate limit window resets before querying again."
    except XAPIAuthError as e:
        return f"### Authentication Failure\n\n{e}\nPlease verify that your X Bearer Token is valid and has search permissions."
    except XAPIError as e:
        return f"### X API Error\n\n{e}"
    except Exception as e:  # noqa: BLE001
        return f"### Unexpected Error\n\nFailed to complete search: {e}"


@mcp.tool()
async def get_post(post_id_or_url: str) -> str:
    """Fetch details and metrics for a specific post by ID or URL.

    Args:
        post_id_or_url: A numeric post ID (e.g. '1840000000000000001') or a URL
                        (e.g. 'https://x.com/username/status/1840000000000000001').
    """
    try:
        client = get_client()
        post = await client.get_post(post_id_or_url)
        return format_post(post)
    except ValueError as e:
        return f"### Invalid Input\n\n{e}"
    except XRateLimitError as e:
        return f"### Rate Limit Exceeded\n\n{e}"
    except XAPIAuthError as e:
        return f"### Authentication Failure\n\n{e}"
    except XAPIError as e:
        return f"### Post Lookup Failed\n\n{e}"
    except Exception as e:  # noqa: BLE001
        return f"### Unexpected Error\n\n{e}"


@mcp.tool()
async def check_rate_limits() -> str:
    """Check the remaining request quota and reset time for the X API search endpoint."""
    try:
        client = get_client()
        status = client.get_rate_limit_status()
        if status.limit is None:
            return (
                "### Rate Limit Status\n\n"
                "No requests have been executed yet in this session. "
                "Rate limit headers will be populated upon the first API call."
            )

        reset_str = (
            status.reset_at.strftime("%Y-%m-%d %H:%M:%S UTC") if status.reset_at else "Unknown"
        )
        return (
            "### X Search API Rate Limit Status\n\n"
            f"- **Remaining Quota:** {status.remaining} / {status.limit} requests\n"
            f"- **Resets At:** {reset_str}\n"
            f"- **Countdown:** ~{status.reset_seconds} seconds\n"
        )
    except Exception as e:  # noqa: BLE001
        return f"### Unable to check rate limits\n\n{e}"
