---
name: x-search
description: Search recent posts on X (Twitter) using X API v2, inspect engagement metrics, lookup posts by ID or URL, and manage search pagination and rate limits.
---

# X (Twitter) Search Tool Skill

Use this skill when searching X (Twitter) for recent discussions, news, code releases, sentiment, or specific posts and threads.

## Available Tools

The `x-search` MCP server provides three primary tools:

1. `search_recent_posts(query: str, max_results: int = 10, next_token: str | None = None) -> str`
   - Searches posts published within the last 7 days.
   - Returns hydrated author details, publication timestamps, engagement metrics (likes, reposts, replies, views), and post URLs.
2. `get_post(post_id_or_url: str) -> str`
   - Fetches full details for a specific post using either a numeric status ID (e.g. `1840000000000000001`) or a link (`https://x.com/username/status/...` or `https://twitter.com/...`).
3. `check_rate_limits() -> str`
   - Returns the remaining request quota, reset timestamp, and countdown for the X search API endpoint.

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

2. **Releases or Repositories:**
   ```text
   python "fastmcp" url:github.com -is:retweet
   ```

3. **High-Profile Announcements:**
   ```text
   from:AnthropicAI -is:retweet
   ```

4. **Media and Visual Demonstrations:**
   ```text
   "robotics" has:media lang:en -is:retweet
   ```

---

## Pagination Workflow

When a query has multiple pages of results, `search_recent_posts` includes a `Next Page Token` in the output footer:
```markdown
> **Next Page Token:** `b26v89c19zqg8o3fo7gesq314yb9l2l4ptqy`
```

To fetch the next batch:
- Call `search_recent_posts(query=..., next_token="b26v89c19zqg8o3fo7gesq314yb9l2l4ptqy")`.
- Retain the exact same query parameters.

---

## Authentication & Rate Limit Handling

- The tool requires `X_BEARER_TOKEN` (or `TWITTER_BEARER_TOKEN`) set in the environment or a `.env` file.
- If a `429 Rate Limit Exceeded` message is returned, inspect `check_rate_limits()` to identify the exact seconds remaining before the rate limit window resets.
- Avoid hammering the endpoint with repetitive identical queries.
