# X (Twitter) Search Tool & MCP Server

An asynchronous Model Context Protocol (MCP) server and Antigravity plugin for searching recent and historical posts on X (Twitter), analyzing tweet volume trends, inspecting engagement metrics, looking up individual posts, and managing rate limits via the X API v2.

---

## Features

- **Recent Search (v2):** Search posts from the last 7 days with rich operator support (`from:`, `to:`, `@mention`, `#hashtag`, `url:`, `lang:en`, `-is:retweet`, `-is:reply`, `has:media`).
- **Full-Archive Search (v2):** Search all historical posts back to **March 2006** with UTC timestamp bounds (`start_time`, `end_time`) and up to 500 results per page.
- **Post Counts API:** Retrieve time-series post volume trends and aggregate counts grouped by `day`, `hour`, or `minute` for recent or full-archive data.
- **Hydrated Data:** Automatic resolution of author handles, verified badges, profile pictures, and engagement metrics (likes, reposts, replies, views).
- **Post Lookup:** Fetch single posts using either numeric status IDs or full URLs (`https://x.com/...` or `https://twitter.com/...`).
- **Rate Limit Tracking:** Real-time quota tracking (`x-rate-limit-remaining`, `x-rate-limit-reset`) with actionable countdowns.
- **FastMCP & stdio:** Built on the official Python MCP SDK with stdio transport.
- **Agent Skill & Antigravity Plugin:** Bundled with `plugin.json`, `mcp_config.json`, and `skills/x-search/SKILL.md` for instant agent adoption.

---

## Quickstart & Installation

### 1. Prerequisites
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) package manager
- An X API Developer App Bearer Token (obtain from [developer.x.com](https://developer.x.com/en/portal/dashboard))

### 2. Configure Credentials
Copy `.env.example` to `.env` and set your Bearer Token:
```bash
cp .env.example .env
# Edit .env and paste your token:
# X_BEARER_TOKEN="your_token_here"
```
Or export it in your shell environment:
```bash
export X_BEARER_TOKEN="your_token_here"
```

### 3. Install Dependencies
```bash
uv sync
```

---

## Usage as an Antigravity Plugin

To install this tool directly into Antigravity:
1. Copy or symlink the repository directory to `~/.gemini/config/plugins/x-search`:
   ```bash
   # From the repository root:
   cp -R . ~/.gemini/config/plugins/x-search
   # Or create a symbolic link:
   ln -s "$(pwd)" ~/.gemini/config/plugins/x-search
   ```
2. Restart Antigravity or reload plugins. The `x-search` skill and tools will be available automatically to all agents.

---

## Usage with Other MCP Hosts (Claude Code, Cursor, Windsurf)

Add the following entry to your `mcp.json` or `mcp_config.json`:

```json
{
  "mcpServers": {
    "x-search": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/x-search-tool",
        "x-search"
      ],
      "env": {
        "X_BEARER_TOKEN": "YOUR_BEARER_TOKEN"
      }
    }
  }
}
```

---

## MCP Tools Reference

### `search_recent_posts`
Searches posts from the last 7 days.
- `query` (str): Search query with optional boolean operators (e.g., `"deepseek" lang:en -is:retweet`).
- `max_results` (int, optional): Number of posts to return (10 to 100, default: 10).
- `next_token` (str, optional): Pagination token for loading subsequent pages.

### `search_full_archive_posts`
Searches historical posts from March 2006 to present.
- `query` (str): Search query string (up to 1024 characters).
- `start_time` (str, optional): Oldest UTC timestamp in ISO 8601 format (`2020-01-01T00:00:00Z`).
- `end_time` (str, optional): Most recent UTC timestamp in ISO 8601 format.
- `max_results` (int, optional): 10 to 500 (default: 10).
- `next_token` (str, optional): Pagination token.
- `sort_order` (str, optional): `'recency'` or `'relevancy'`.

### `get_post_counts`
Analyzes tweet volume trends without fetching individual posts.
- `query` (str): Search query to count matching posts.
- `granularity` (str, optional): `'day'`, `'hour'`, or `'minute'` (default: `'day'`).
- `start_time` (str, optional): ISO 8601 UTC timestamp.
- `end_time` (str, optional): ISO 8601 UTC timestamp.
- `full_archive` (bool, optional): `True` for historical counts back to 2006; `False` for the last 7 days (default).

### `get_post`
Retrieves detailed information for a single post.
- `post_id_or_url` (str): Numeric status ID or full status URL.

### `check_rate_limits`
Returns remaining API requests and countdown seconds until rate limit reset.

---

## Testing & Quality

Run the automated test suite:
```bash
uv run pytest -v
```

Run code formatting and linting:
```bash
uv run ruff check .
uv run ruff format --check .
```
