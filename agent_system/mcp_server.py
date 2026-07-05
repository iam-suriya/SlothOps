"""
mcp_server.py — exposes the 3-stage log-triage pipeline as MCP tools, so any
MCP-speaking agent (an ADK agent, Claude, or any other MCP client) can call
it without knowing anything about the Python internals underneath.

This file contains NO new analysis logic. Every tool below is a thin wrapper
around a function that already existed and was already verified:
    extract_incident    -> log_anamoly.run_log_analysis()
    reduce_report        -> reduce_for_llm.reduce_file()
    analyze_incident_tool -> analyze_incident.analyze()

WHY WRAP THEM INSTEAD OF LEAVING THEM AS SCRIPTS
  A human runs 3 scripts by hand, in order, passing the output path of one as
  the input to the next. An MCP tool turns each stage into something an AGENT
  can discover (by name + description + schema) and call autonomously as part
  of its own reasoning -- which is the actual "agent" behavior this capstone
  is judged on, not just having an LLM summarize text.

SECURITY NOTE
  Every tool here runs its inputs through agent_system/security.py before
  touching the filesystem or an LLM: safe_path() blocks path traversal,
  enforce_size_limit() blocks oversized files, and sanitize_for_prompt() /
  UNTRUSTED_DATA_NOTICE guard against prompt injection from log content
  before it reaches analyze_incident.py's LLM call. An agent calling these
  tools is not a trusted human at a terminal -- these checks assume the
  inputs could be adversarial.

HOW TO RUN STANDALONE (for testing without an agent)
    python agent_system/mcp_server.py
  This starts the server on stdio, waiting for an MCP client to connect.
  It's normally launched automatically by adk_agents.py via StdioConnectionParams,
  not run directly by a person.
"""
import os
import sys

# Make the project root (one level up) importable, since this file lives in
# agent_system/ but needs the sibling modules at the project root.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP

from log_anamoly import run_log_analysis
from reduce_for_llm import reduce_file
from analyze_incident import analyze, load_llm_settings
from agent_system.security import safe_path, enforce_size_limit, SecurityError

mcp = FastMCP(
    "log-triage-tools",
    instructions=(
        "Tools for a 3-stage log incident triage pipeline: extract a "
        "time-correlated incident report from raw logs, reduce it for cheap "
        "LLM consumption, then produce a non-technical summary for QA "
        "testers and marketing/business stakeholders. Call them in that "
        "order -- each tool's output path is the next tool's input."
    ),
)


@mcp.tool()
def extract_incident(config_path: str = "log_anomaly.properties") -> dict:
    """Stage 1: scans the log folders named in config_path, finds any
    ERROR/WARN/EXCEPTION-style trigger lines, time-correlates them across
    every log source, and writes one incident report.

    Args:
        config_path: path to a log_anomaly.properties file, relative to the project root.

    Returns:
        {"status": "ok", "report_path": "..."} on success,
        {"status": "no_incident"} if no triggers were found,
        {"status": "error", "message": "..."} if the input failed a security check.
    """
    try:
        safe_config_path = safe_path(config_path, PROJECT_ROOT)
    except SecurityError as e:
        return {"status": "error", "message": str(e)}

    report_path = run_log_analysis(safe_config_path)
    if not report_path:
        return {"status": "no_incident"}
    return {"status": "ok", "report_path": report_path}


@mcp.tool()
def reduce_report(report_path: str) -> dict:
    """Stage 2: shrinks an incident report (folds stack traces, trims noisy
    payload lines, collapses repeated lines) so it's cheap to hand to an LLM.

    Args:
        report_path: path to the incident report produced by extract_incident
            (an absolute /tmp/incident_*.txt path -- not confined to the
            project root, since that's where stage 1 intentionally writes).

    Returns:
        {"status": "ok", "reduced_path": "..."} on success,
        {"status": "error", "message": "..."} on a security or file error.
    """
    try:
        enforce_size_limit(report_path)
    except (SecurityError, OSError) as e:
        return {"status": "error", "message": str(e)}

    try:
        reduced_path = reduce_file(report_path)
    except Exception as e:
        return {"status": "error", "message": f"reduce_file failed: {e}"}
    return {"status": "ok", "reduced_path": reduced_path}


@mcp.tool()
def analyze_incident_tool(reduced_path: str, config_path: str = "log_anomaly.properties") -> dict:
    """Stage 3: sends the reduced report to an LLM and gets back a short,
    non-technical summary for QA testers and marketing/business stakeholders
    (what broke, customer impact, severity, how to verify the fix, status).

    Provider/mock/token-budget settings come from the [LLM] section of
    config_path -- see analyze_incident.py's load_llm_settings(). Untrusted
    log content is sanitized against prompt injection before it reaches the
    model (see agent_system/security.py).

    Args:
        reduced_path: path to the reduced report produced by reduce_report.
        config_path: path to log_anomaly.properties, for the [LLM] settings.

    Returns:
        The parsed {"incidents": [...]} summary, or
        {"status": "error", "message": "..."} on failure.
    """
    try:
        enforce_size_limit(reduced_path)
        safe_config_path = safe_path(config_path, PROJECT_ROOT)
    except SecurityError as e:
        return {"status": "error", "message": str(e)}

    provider, mock, max_tokens = load_llm_settings(safe_config_path)
    raw = analyze(reduced_path, provider=provider, mock=mock, max_tokens=max_tokens)

    import json
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "error", "message": "model did not return valid JSON", "raw": raw}


if __name__ == "__main__":
    mcp.run()  # stdio transport -- an agent (or adk_agents.py) launches this as a subprocess
