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
- **Official MCP SDK, stdio by default:** Runs over stdin/stdout for local hosts, with optional Streamable-HTTP and SSE transports for remote/web clients (Google Gemini Spark, hosted agents).
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

## Remote / Network Deployment (Streamable-HTTP + SSE)

Local hosts launch this server over **stdio**, which is the default and needs no
configuration. Remote clients cannot spawn a subprocess: they need a public HTTPS
endpoint speaking JSON-RPC over POST (Streamable-HTTP) or Server-Sent Events.

```bash
# Streamable-HTTP + SSE on one port, no auth (put a reverse proxy in front)
x-search --transport both --host 127.0.0.1 --port 8091

# Same, but every request must carry a bearer token
X_SEARCH_HTTP_TOKEN="$(openssl rand -hex 32)" \
  x-search --transport both --host 127.0.0.1 --port 8091
```

| Endpoint | Purpose |
|---|---|
| `POST /mcp` | Streamable-HTTP JSON-RPC (the modern transport) |
| `GET /sse`, `POST /messages/` | Legacy HTTP+SSE transport |
| `GET /health` | Liveness probe, always unauthenticated |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 probe, answered with `{}` so clients stop probing |

### Options

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--transport` | `X_SEARCH_TRANSPORT` | `stdio` | `stdio`, `sse`, `streamable-http`, or `both` |
| `--host` | `X_SEARCH_HOST` | `127.0.0.1` | Bind address for network transports |
| `--port` | `X_SEARCH_PORT` | `8091` | Bind port for network transports |
| `--path` | `X_SEARCH_PATH` | `/mcp` | Streamable-HTTP endpoint path |
| `--stateless` | `X_SEARCH_STATELESS` | off | Omit `Mcp-Session-Id`; friendlier behind a proxy |
| `--bearer-token` | `X_SEARCH_HTTP_TOKEN` | unset | Requires a static `Authorization: Bearer` token on every request; an explicitly empty value is rejected rather than silently disabling auth. Incompatible with the OAuth layer below |

### Connecting Google Gemini Spark

Gemini Spark's custom connected apps are **OAuth-only**. When you paste an MCP
server URL it performs protected-resource discovery (RFC 9728), then
authorization-server discovery (RFC 8414), then an authorization-code flow with
PKCE. A server that answers "no authorization server here" is rejected with
*"This URL does not appear to be a valid MCP server"* — even when its JSON-RPC
endpoint is perfectly healthy.

Setting `X_SEARCH_PUBLIC_URL` makes this server its own OAuth 2.1 authorization
server:

```bash
X_SEARCH_PUBLIC_URL="https://mcp.example.com" \
X_SEARCH_OAUTH_STORE="$HOME/.config/xsearch-oauth.json" \
  x-search --transport both --host 127.0.0.1 --port 8091
```

On first start it generates a client ID and secret and persists them. Spark does
**not** need them: it registers itself.

Then, in **Settings & help → Connected Apps → Custom apps for Spark → Add a
custom app**, enter the MCP server URL and click **Next**:

```
https://mcp.example.com/mcp
```

**Leave "Advanced features" collapsed.** That manual-credentials path is only for
servers without Dynamic Client Registration; this server advertises
`registration_endpoint`, so Spark registers itself.

#### Why the two metadata fields matter

Two fields in `/.well-known/oauth-authorization-server` decide whether Spark
accepts the server at all:

| Field | Required value | What happens otherwise |
|---|---|---|
| `token_endpoint_auth_methods_supported` | must include `"none"` | Spark is a **public** client. Advertise only `client_secret_post` / `client_secret_basic` and it refuses with *"This MCP server uses an authentication method that Gemini doesn't support."* |
| `registration_endpoint` | present | Without it Spark cannot self-register and falls back to asking for a client ID and secret |

The MCP SDK hardcodes the first field to the two secret-based methods, so
`x_search.http_server` **shadows** the SDK's metadata route with its own document
(`x_search.oauth.authorization_server_metadata`).

#### What keeps open registration safe

Registration is open to anyone, so the gate is the redirect URI. Registrations are
only accepted from Google-owned origins — the suffix match covers
`oauth-redirect.googleusercontent.com`, `oauth-redirect-sandbox.googleusercontent.com`
and `oauth-redirect-test.googleusercontent.com`, which is where all six of Spark's
real redirect URIs live (override with
`X_SEARCH_OAUTH_ALLOWED_REDIRECT_ORIGINS`). A hostile registrant cannot receive
the authorization code because it does not control that origin, and PKCE — which
Spark always sends — protects the code even if it leaked. Registered clients are
stored with **no** client secret and `token_endpoint_auth_method: "none"`.

Spark is a public client: real traces show it sending `client_id`, `code`,
`code_verifier` and `redirect_uri` to `/token` and **no client secret**, even when
it was given one to paste in. The pre-registered client is therefore public by
default. Set `X_SEARCH_OAUTH_TOKEN_AUTH_METHOD=client_secret_post` (or
`client_secret_basic`) only if you need a genuinely confidential client.

#### Reverse proxy

Serve the whole origin — MCP *and* OAuth — from one host, because the issuer URL
in the metadata has to be the URL clients actually reach:

```caddy
:8092 {
    @root_get { method GET; path / }
    respond @root_get "x-search MCP endpoint" 200

    @health path /health
    respond @health "ok" 200

    @post_root { method POST; path / }
    rewrite @post_root /mcp

    @post_sse { method POST; path /sse }
    rewrite @post_sse /mcp

    reverse_proxy 127.0.0.1:8091 {
        header_up Accept "application/json, text/event-stream, */*"
        flush_interval -1
    }
}
```

Expose port 8092 through a Cloudflare Tunnel to get the HTTPS URL. Two
operational notes:

- Do **not** front this with a WAF rule that blocks non-browser user agents —
  MCP clients are servers, not browsers.
- The generated client secret is the credential. Rotate it by deleting the store
  file and re-adding the app in Gemini.

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
