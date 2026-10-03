---
name: x-search
description: Search recent posts and full historical archives (2006 to present) on X (Twitter), analyze post volume trends, inspect engagement metrics, lookup posts by ID or URL, and manage search pagination and rate limits.
---

# X (Twitter) Search Tool Skill

Use this skill when searching X (Twitter) for recent discussions, historical archives, volume trends, sentiment, news, code releases, or specific posts.

## Available Tools

The `x-search` MCP server provides five primary tools:

1. `search_recent_posts(query: str, max_results: int = 10, next_token: str | None = None, sort_order: str = "recency") -> str`
   - Searches posts published within the last 7 days.
   - Supports `'recency'` or `'relevancy'` sort order.
   - Returns hydrated author details, publication timestamps, engagement metrics (likes, reposts, replies, views), and post URLs.

2. `search_full_archive_posts(query: str, start_time: str | None = None, end_time: str | None = None, max_results: int = 10, next_token: str | None = None, sort_order: str = "recency") -> str`
   - Searches the complete historical archive of posts dating back to **March 2006**.
   - Supports ISO 8601 UTC timestamp bounds (`start_time`, `end_time`, e.g. `2015-01-01T00:00:00Z`).
   - Supports up to `max_results=500` per page.
   - Allows longer queries (up to 1,024 characters).

3. `get_post_counts(query: str, granularity: str = "day", start_time: str | None = None, end_time: str | None = None, full_archive: bool = False) -> str`
   - Returns aggregated post volume and trend timeseries without loading individual posts.
   - `granularity`: `'day'`, `'hour'`, or `'minute'`.
   - `full_archive`: Set to `True` for historical counts back to 2006 (or `False` for the last 7 days).

4. `get_post(post_id_or_url: str) -> str`
   - Fetches full details for a specific post using either a numeric status ID (e.g. `1840000000000000001`) or a link (`https://x.com/username/status/...` or `https://twitter.com/...`).

5. `check_rate_limits(endpoint: str = "search") -> str`
   - Returns the remaining request quota, reset timestamp, and countdown for X API endpoints.
   - `endpoint`: `'search'` (recent search), `'search_all'` (full archive), `'tweets'` (post lookup), or `'counts'` (post volume). Defaults to `'search'`.

---

## Query Construction & Operators

Crafting effective X search queries is critical for retrieving relevant signal and filtering out noise. Always use the following query operators:

| Operator | Syntax Example | Description |
| :--- | :--- | :--- |
| **Keyword match** | `python` | Matches posts containing the word "python" (case-insensitive) |
| **Exact phrase** | `"machine learning"` | Matches the exact sequence of words |
| **From user** | `from:OpenAI` | Posts authored by `@OpenAI` |
| **To user** | `to:sama` | Direct replies to `@sama` |
| **User mention** | `@karpathy` | Posts mentioning `@karpathy` |
| **Hashtag** | `#LLM` | Posts tagged with `#LLM` |
| **Language filter** | `lang:en` | Restricts results to English (ISO 639-1 code) |
| **Exclude retweets** | `-is:retweet` | **Crucial:** Filters out reposts to avoid duplicate noise |
| **Exclude replies** | `-is:reply` | Filters out thread replies to surface top-level original posts |
| **Has media** | `has:media` | Posts containing images, GIFs, or videos |
| **Has images** | `has:images` | Posts containing image attachments |
| **Has links** | `has:links` | Posts with external URL links |
| **Link domain** | `url:github.com` | Posts linking to a specific domain |

### Recommended Query Recipes

1. **General Topic Discovery (Clean Signal):**
   ```text
   "deepseek" lang:en -is:retweet -is:reply
   ```

2. **Historical Research (Full Archive):**
   - Tool: `search_full_archive_posts`
   - Query: `"transformer" "attention is all you need" -is:retweet`
   - `start_time`: `2017-06-01T00:00:00Z`
   - `end_time`: `2017-12-31T23:59:59Z`

3. **Buzz & Trend Analysis (Post Counts):**
   - Tool: `get_post_counts`
   - Query: `Python lang:en -is:retweet`
   - `granularity`: `day`

4. **Releases or Repositories:**
   ```text
   python "fastmcp" url:github.com -is:retweet
   ```

5. **High-Profile Announcements:**
   ```text
   from:AnthropicAI -is:retweet
   ```

---

## Pagination Workflow

When a search query has multiple pages of results, the tool includes a `Next Page Token` in the output footer:
```markdown
> **Next Page Token:** `b26v89c19zqg8o3juziyb9ub9pvacff385ixrmapgi9a5`
```

To fetch the next batch:
- Call `search_recent_posts` or `search_full_archive_posts` with `next_token="b26v89c19zqg8o3juziyb9ub9pvacff385ixrmapgi9a5"`.
- Retain the exact same query parameters.

---

## Authentication & Rate Limit Handling

- The tool requires `X_BEARER_TOKEN` (or `TWITTER_BEARER_TOKEN`) set in the environment or a `.env` file.
- If a `429 Rate Limit Exceeded` message is returned, inspect `check_rate_limits()` to identify the exact seconds remaining before the rate limit window resets.
- Full-archive search and counts endpoints operate under their own rate limits.
