# X (Twitter) Search Tool & MCP Server

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

An asynchronous Model Context Protocol (MCP) server and Antigravity plugin for searching recent and historical posts on X (Twitter), analyzing tweet volume trends, inspecting engagement metrics, looking up individual posts, and managing rate limits via the X API v2.

---

## Features

- **Recent Search (v2):** Search posts from the last 7 days with rich operator support (`from:`, `to:`, `@mention`, `#hashtag`, `url:`, `lang:en`, `-is:retweet`, `-is:reply`, `has:media`).
- **Full-Archive Search (v2):** Search all historical posts back to **March 2006** with UTC timestamp bounds (`start_time`, `end_time`) and up to 500 results per page.
- **Post Counts API:** Retrieve time-series post volume trends and aggregate counts grouped by `day`, `hour`, or `minute` for recent or full-archive data.
- **Hydrated Data:** Automatic resolution of author handles, verified badges, profile pictures, and engagement metrics (likes, reposts, replies, views).
- **Post Lookup:** Fetch single posts using either numeric status IDs or full URLs (`https://x.com/...` or `https://twitter.com/...`).
- **Rate Limit Tracking:** Real-time quota tracking (`x-rate-limit-remaining`, `x-rate-limit-reset`) with actionable countdowns and per-endpoint isolation.
- **FastMCP & stdio:** Built on the official Python MCP SDK with stdio transport.
- **Agent Skill & Antigravity Plugin:** Bundled with `plugin.json`, `mcp_config.json`, and `skills/x-search/SKILL.md` for seamless agent workflows.

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

## Antigravity Plugin Installation

Install the plugin directly into Antigravity using the `agy` CLI:

```bash
# From within the repository directory:
agy plugin install .

# Or specify the directory path:
agy plugin install /path/to/x-search-tool
```

### Verification & Management
```bash
# Validate plugin structure (skills, MCP servers, manifests)
agy plugin validate .

# List installed plugins
agy plugin list

# Enable or disable
agy plugin enable x-search
agy plugin disable x-search
```

Once installed, the `x-search` skill and MCP server are automatically active for all Antigravity agent sessions.

---

## Usage with Other MCP Hosts (Claude Code, Cursor, Windsurf)

### Claude Code CLI
```bash
claude mcp add x-search uv -- run --directory /path/to/x-search-tool x-search
```

### MCP Configuration File (`mcp.json` / `mcp_config.json`)
Add the following entry to your MCP configuration:

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
- `sort_order` (str, optional): `'recency'` or `'relevancy'` (default: `'recency'`).

### `search_full_archive_posts`
Searches historical posts from March 2006 to present (requires Pro/Academic API tier).
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
- `post_id_or_url` (str): Numeric status ID (e.g., `'1840000000000000001'`) or full status URL (`'https://x.com/user/status/1840000000000000001'`).

### `check_rate_limits`
Returns remaining API requests and countdown seconds until rate limit reset.
- `endpoint` (str, optional): Endpoint category to inspect: `'search'` (recent search, default), `'search_all'` (full archive), `'tweets'` (post lookup), or `'counts'` (post volume counts).

---

## Testing & Quality

Run the automated test suite (68 tests):
```bash
uv run pytest -v
```

Run code formatting and linting:
```bash
uv run ruff check .
uv run ruff format --check .
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
