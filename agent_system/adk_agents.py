"""
adk_agents.py — the multi-agent layer, built on Google's Agent Development
Kit (ADK), that turns the 3 MCP tools in mcp_server.py into 3 cooperating
agents instead of 3 functions a human calls by hand.

ARCHITECTURE
    log_triage_coordinator (SequentialAgent)
        │
        ├─ extraction_agent (LlmAgent) ── McpToolset scoped to ONLY extract_incident
        ├─ reduction_agent  (LlmAgent) ── McpToolset scoped to ONLY reduce_report
        └─ analyst_agent    (LlmAgent) ── McpToolset scoped to ONLY analyze_incident_tool

SequentialAgent runs its sub_agents in order and shares one session, so each
agent can read what the previous one produced. Each agent gets its OWN
McpToolset connection filtered (via tool_filter) to exactly the one tool it
needs -- this is the least-privilege security property in practice, not just
a comment: the extraction agent's LLM literally cannot call analyze_incident_tool
even if a prompt-injected log line tried to talk it into doing so, because
the tool isn't in its toolset at all.

STATE PASSING BETWEEN AGENTS
  Each agent's after_tool_callback captures the MCP tool's raw JSON return
  value directly into session state (extraction_result / reduction_result /
  analysis_result). The NEXT agent's instruction references that state with
  ADK's {state_key} templating so it knows which path to pass to its own
  tool call. This is more robust than trusting the LLM to retype a file path
  correctly in prose -- the ground-truth value goes into state programmatically,
  the LLM only has to read it back out.

RUNNING THIS
  Needs a live model call (Gemini by default), so it needs GOOGLE_API_KEY set
  and outbound internet access to generativelanguage.googleapis.com. It will
  NOT run inside a network-locked sandbox -- use test_mcp_server.py instead
  to verify the underlying tool chain without touching the LLM at all.

    python agent_system/adk_agents.py sample_data/log_anomaly.properties
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

from agent_system.security import AGENT_TOOL_SCOPES
from agent_system.agent_skills import build_skill_toolset

MODEL = "gemini-2.5-flash"  # cheap/fast tier -- consistent with the cost-control principle used throughout this project
MCP_SERVER_PATH = os.path.join(PROJECT_ROOT, "agent_system", "mcp_server.py")


def _toolset_for(agent_key: str) -> McpToolset:
    """Builds an MCP connection scoped (via tool_filter) to only the tool(s)
    listed for agent_key in security.AGENT_TOOL_SCOPES -- the single source
    of truth for least-privilege tool access in this project."""
    return McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=sys.executable,
                args=[MCP_SERVER_PATH],
                cwd=PROJECT_ROOT,
            ),
            timeout=30.0,
        ),
        tool_filter=AGENT_TOOL_SCOPES[agent_key],
    )


def _make_capture_callback(state_key: str):
    """Returns an after_tool_callback that writes the MCP tool's raw JSON
    return value into session state under state_key, so the next agent in
    the SequentialAgent chain can read it via {state_key} instruction
    templating -- ground truth captured programmatically, not re-typed by
    the LLM."""

    def _callback(tool, args, context, tool_response):
        context.state[state_key] = tool_response
        return None  # returning None leaves the tool's actual response to the model untouched

    return _callback


extraction_agent = LlmAgent(
    name="extraction_agent",
    model=MODEL,
    description="Extracts a time-correlated incident report from raw logs.",
    instruction=(
        'Call the extract_incident tool with config_path="{config_path}". '
        "After calling it, reply with ONLY the raw JSON object the tool returned -- "
        "no commentary, no markdown fences, nothing else."
    ),
    tools=[_toolset_for("extraction_agent")],
    after_tool_callback=_make_capture_callback("extraction_result"),
)

reduction_agent = LlmAgent(
    name="reduction_agent",
    model=MODEL,
    description="Shrinks an incident report so it's cheap to hand to an LLM.",
    instruction=(
        "The previous stage's result is: {extraction_result}. "
        "Find the report_path field in that JSON and call the reduce_report tool "
        "with that exact report_path. Reply with ONLY the raw JSON object the tool "
        "returned -- no commentary, no markdown fences, nothing else."
    ),
    tools=[_toolset_for("reduction_agent")],
    after_tool_callback=_make_capture_callback("reduction_result"),
)

analyst_agent = LlmAgent(
    name="analyst_agent",
    model=MODEL,
    description=(
        "Produces a short, non-technical incident summary for QA testers and "
        "marketing/business stakeholders -- no stack traces, no jargon."
    ),
    instruction=(
        "If the log-triage skill is available, load it first and follow its "
        "guidance on tone, severity, and what makes a good tester/marketing summary. "
        "The previous stage's result is: {reduction_result}. "
        'Find the reduced_path field in that JSON and call the analyze_incident_tool '
        'tool with that reduced_path and config_path="{config_path}". Reply with '
        "ONLY the raw JSON the tool returned -- no commentary, no markdown fences."
    ),
    # Two toolsets: the one MCP tool this agent is allowed to call (least
    # privilege, from AGENT_TOOL_SCOPES), plus the log-triage Agent Skill so
    # it can pull up the published methodology/tone guidance at runtime
    # instead of that knowledge only living in this Python file.
    tools=[_toolset_for("analyst_agent"), build_skill_toolset()],
    after_tool_callback=_make_capture_callback("analysis_result"),
)

log_triage_coordinator = SequentialAgent(
    name="log_triage_coordinator",
    description=(
        "Coordinates extraction_agent -> reduction_agent -> analyst_agent to turn "
        "raw multi-source logs (Apache/Tomcat/Lambda) into a plain-English incident "
        "summary, end to end, with no human running scripts by hand in between."
    ),
    sub_agents=[extraction_agent, reduction_agent, analyst_agent],
)


async def run_pipeline(config_path: str = "sample_data/log_anomaly.properties"):
    """Runs the full 3-agent pipeline against config_path and prints the
    final analyst output. Requires GOOGLE_API_KEY and outbound internet
    access -- see the module docstring."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    runner = InMemoryRunner(agent=log_triage_coordinator, app_name="log_triage")
    session = await runner.session_service.create_session(
        app_name="log_triage", user_id="demo_user", state={"config_path": config_path}
    )

    final_text = None
    async for event in runner.run_async(
        user_id="demo_user",
        session_id=session.id,
        new_message=types.Content(role="user", parts=[types.Part(text="Run the log triage pipeline.")]),
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if getattr(part, "text", None):
                    final_text = part.text
                    print(f"[{event.author}] {part.text}")

    return final_text


if __name__ == "__main__":
    import asyncio

    config = sys.argv[1] if len(sys.argv) > 1 else "sample_data/log_anomaly.properties"
    asyncio.run(run_pipeline(config))
