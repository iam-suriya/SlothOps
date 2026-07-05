"""
test_mcp_server.py — a standalone MCP CLIENT that connects to mcp_server.py
over stdio and calls all 3 tools in sequence, exactly the way an ADK agent
(or any other MCP client) would. This is the fastest way to prove the MCP
layer works correctly BEFORE wiring up the heavier ADK agent layer on top.

Run:  python agent_system/test_mcp_server.py [config_path]
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def main(config_path: str):
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(PROJECT_ROOT, "agent_system", "mcp_server.py")],
        cwd=PROJECT_ROOT,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Discovered tools:", [t.name for t in tools.tools])
            print()

            print("--- calling extract_incident ---")
            r1 = await session.call_tool("extract_incident", {"config_path": config_path})
            r1_data = json.loads(r1.content[0].text)
            print(r1_data)
            if r1_data.get("status") != "ok":
                print("Stopping: extraction did not succeed.")
                return

            print("\n--- calling reduce_report ---")
            r2 = await session.call_tool("reduce_report", {"report_path": r1_data["report_path"]})
            r2_data = json.loads(r2.content[0].text)
            print(r2_data)
            if r2_data.get("status") != "ok":
                print("Stopping: reduction did not succeed.")
                return

            print("\n--- calling analyze_incident_tool ---")
            r3 = await session.call_tool(
                "analyze_incident_tool",
                {"reduced_path": r2_data["reduced_path"], "config_path": config_path},
            )
            r3_data = json.loads(r3.content[0].text)
            print(json.dumps(r3_data, indent=2))


if __name__ == "__main__":
    config = sys.argv[1] if len(sys.argv) > 1 else "sample_data/log_anomaly.properties"
    asyncio.run(main(config))
