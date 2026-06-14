#!/usr/bin/env python3
"""Example agent #3 — drive the kit over MCP, the way an external agent would.

Examples #1 and #2 import the kit in-process. A real agent usually talks to it over the
Model Context Protocol instead: it spawns the server, discovers the tools, and calls them.
This script does exactly that against a local stdio server — the same path Claude Code and
other MCP clients use.

    pip install "mcp[cli]"
    python mcp_client.py [path/to/scrypto/package]

It calls only the cheap, no-API tools (static_scan, get_checklist, gate) so it runs without
an ANTHROPIC_API_KEY. Point it at your own package, or let it use the bundled fixture.
"""
import asyncio
import json
import os
import sys

KIT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER = os.path.join(KIT_ROOT, "bin", "mcp_server.py")
DEFAULT_PKG = os.path.join(KIT_ROOT, "examples", "vulnerable-vault")


def _unwrap(result):
    """Pull a plain Python value out of an MCP CallToolResult (structured or JSON text)."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        # FastMCP wraps non-dict returns as {"result": ...}
        return structured.get("result", structured)
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text is not None:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return None


async def run(pkg):
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        print('the MCP SDK is required: pip install "mcp[cli]"', file=sys.stderr)
        return 1

    params = StdioServerParameters(command=sys.executable, args=[SERVER], env=os.environ.copy())
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("tools the server exposes:")
            for t in tools.tools:
                print(f"  - {t.name}")

            print(f"\ncall static_scan({os.path.relpath(pkg, KIT_ROOT)}):")
            scan = _unwrap(await session.call_tool("static_scan", {"package_path": pkg}))
            print(f"  {scan['count']} finding(s): {scan['counts']}")

            print("\ncall get_checklist() -> first line:")
            checklist = _unwrap(await session.call_tool("get_checklist", {}))
            print(f"  {checklist.splitlines()[0]}")

            # The gate wants a report.json on disk; write the scan out and gate it.
            report_path = os.path.join(KIT_ROOT, "audit-reports", "_mcp_client_demo.json")
            sys.path.insert(0, os.path.join(KIT_ROOT, "bin"))
            import sak_lib  # type: ignore
            with open(report_path, "w", encoding="utf-8") as fh:
                json.dump(sak_lib.build_report(scan["findings"]), fh)
            try:
                print("\ncall gate(report, fail_on=high):")
                verdict = _unwrap(await session.call_tool(
                    "gate", {"report_path": report_path, "fail_on": "high"}))
                print(f"  passed={verdict['passed']} worst={verdict['worst']}")
            finally:
                os.remove(report_path)
    return 0


def main():
    pkg = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PKG
    return asyncio.run(run(pkg))


if __name__ == "__main__":
    sys.exit(main())
