"""CLI entrypoint for x-search MCP server."""

from x_search.server import mcp


def main() -> None:
    """Run the FastMCP server over standard I/O."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
