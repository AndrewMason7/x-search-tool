"""CLI entrypoint for x-search MCP server."""

from x_search.server import configure_logging, mcp


def main() -> None:
    """Run the FastMCP server over standard I/O."""
    configure_logging()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
