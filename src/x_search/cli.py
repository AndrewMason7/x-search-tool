"""Command-line entry point for the x-search MCP server.

Default behaviour (no arguments) is unchanged: speak MCP over stdin/stdout, which
is how local hosts such as Hermes, Claude Desktop and Cursor launch this server.

Pass ``--transport`` to serve over the network instead, for remote/web clients:

    x-search --transport streamable-http --host 127.0.0.1 --port 8091
    x-search --transport both --host 0.0.0.0 --port 8091 --bearer-token "$TOKEN"

Every option also has an ``X_SEARCH_*`` environment-variable fallback so it can
be driven from a systemd unit without arguments.
"""

from __future__ import annotations

import argparse
import os
import sys

from x_search.http_server import (
    DEFAULT_HOST,
    DEFAULT_MESSAGE_PATH,
    DEFAULT_PORT,
    DEFAULT_SSE_PATH,
    DEFAULT_STREAMABLE_HTTP_PATH,
    run_http_server,
)
from x_search.server import configure_logging, mcp

TRANSPORT_CHOICES = ("stdio", "sse", "streamable-http", "both")
HTTP_TRANSPORTS = ("sse", "streamable-http", "both")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="x-search",
        description="X (Twitter) search MCP server (stdio by default, HTTP/SSE on request).",
    )
    parser.add_argument(
        "--transport",
        nargs="+",
        choices=TRANSPORT_CHOICES,
        default=[os.getenv("X_SEARCH_TRANSPORT", "stdio")],
        help=(
            "Transport(s) to serve. 'stdio' (default) for local MCP hosts; "
            "'streamable-http' for modern remote clients; 'sse' for legacy HTTP+SSE; "
            "'both' mounts both network transports on one port."
        ),
    )
    parser.add_argument(
        "--host",
        default=os.getenv("X_SEARCH_HOST", DEFAULT_HOST),
        help=f"Bind address for HTTP transports (default: {DEFAULT_HOST}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("X_SEARCH_PORT", str(DEFAULT_PORT))),
        help=f"Bind port for HTTP transports (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--path",
        default=os.getenv("X_SEARCH_PATH", DEFAULT_STREAMABLE_HTTP_PATH),
        help=f"Streamable-HTTP endpoint path (default: {DEFAULT_STREAMABLE_HTTP_PATH}).",
    )
    parser.add_argument(
        "--sse-path",
        default=os.getenv("X_SEARCH_SSE_PATH", DEFAULT_SSE_PATH),
        help=f"SSE stream path (default: {DEFAULT_SSE_PATH}).",
    )
    parser.add_argument(
        "--message-path",
        default=os.getenv("X_SEARCH_MESSAGE_PATH", DEFAULT_MESSAGE_PATH),
        help=f"SSE client-to-server message path (default: {DEFAULT_MESSAGE_PATH}).",
    )
    parser.add_argument(
        "--stateless",
        action="store_true",
        default=_env_bool("X_SEARCH_STATELESS"),
        help=(
            "Do not issue Mcp-Session-Id headers on the streamable transport. "
            "More forgiving behind a reverse proxy and with clients that do not "
            "replay session IDs."
        ),
    )
    parser.add_argument(
        "--bearer-token",
        default=os.getenv("X_SEARCH_HTTP_TOKEN"),
        help=(
            "Require 'Authorization: Bearer <token>' on all HTTP requests except "
            "/health. Defaults to $X_SEARCH_HTTP_TOKEN; leave unset to disable. An "
            "explicitly empty value is rejected rather than silently disabling auth."
        ),
    )
    parser.add_argument(
        "--access-log",
        action="store_true",
        default=_env_bool("X_SEARCH_ACCESS_LOG"),
        help="Log every HTTP request to stderr.",
    )
    return parser


def main() -> None:
    """Run the MCP server over the transport(s) selected on the command line."""
    args = build_parser().parse_args()
    configure_logging()

    if "stdio" in args.transport:
        if len(args.transport) > 1:
            print(
                "error: 'stdio' cannot be combined with network transports; "
                "run one process per transport.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        mcp.run(transport="stdio")
        return

    if not any(t in HTTP_TRANSPORTS for t in args.transport):
        print(f"error: unsupported transport selection {args.transport!r}", file=sys.stderr)
        raise SystemExit(2)

    run_http_server(
        mcp,
        host=args.host,
        port=args.port,
        enable_streamable_http="streamable-http" in args.transport or "both" in args.transport,
        enable_sse="sse" in args.transport or "both" in args.transport,
        streamable_http_path=args.path,
        sse_path=args.sse_path,
        message_path=args.message_path,
        stateless_http=args.stateless,
        bearer_token=args.bearer_token,
        access_log=args.access_log,
    )


if __name__ == "__main__":
    main()
