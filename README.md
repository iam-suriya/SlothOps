# SlothOps

A multi-agent log incident triage system: point it at raw logs from multiple
sources (a reverse proxy, an app server, a serverless function), and it
correlates them into one incident, shrinks it for cheap LLM consumption, and
produces a plain-English summary for QA testers and marketing/business
stakeholders — no stack traces, no jargon.

Built for the **AI Agents: Intensive Vibe Coding Capstone** (Freestyle
track), demonstrating four concepts: **MCP servers**, **multi-agent systems
(Google ADK)**, **agent skills**, and **security features**.

## Why this exists

The 3-stage pipeline (extract → reduce → analyze) started as a set of
scripts a human runs by hand in sequence. This project wraps that pipeline
as MCP tools and puts a multi-agent system (built on Google's Agent
Development Kit) in front of it, so an agent — not a person — decides when
to call each stage. Everything downstream is designed around one constraint
that mattered as much as the architecture: **do this without burning
tokens or leaking secrets.**

## Architecture

```
log_triage_coordinator (ADK SequentialAgent)
    │
    ├─ extraction_agent  ── MCP tool: extract_incident   (log_anamoly.py)
    ├─ reduction_agent   ── MCP tool: reduce_report       (reduce_for_llm.py)
    └─ analyst_agent      ── MCP tool: analyze_incident_tool (analyze_incident.py)
                          └─ Agent Skill: log-triage (published methodology + security notes)
```

Each agent connects to `agent_system/mcp_server.py` with its MCP toolset
filtered (`tool_filter`) to exactly the one tool it needs — least-privilege
access enforced by the framework, not just documented.

| Stage | File | What it does |
|---|---|---|
| 1. Extract | `log_anamoly.py` | Scans Apache/Tomcat/Lambda-style logs for ERROR/WARN/EXCEPTION triggers, time-correlates them (±2 min) across every source, writes one incident report |
| 2. Reduce | `reduce_for_llm.py` | Folds long stack traces, trims noisy payload lines, collapses repeated lines — shrinks the report before it costs any tokens |
| 3. Analyze | `analyze_incident.py` | Sends the reduced report to an LLM (Anthropic / OpenAI / Google, auto-detected or configured), returns a structured, non-technical summary |

## The four concepts, and where the evidence is

| Concept | Where | Evidence |
|---|---|---|
| **MCP servers** | `agent_system/mcp_server.py` | 3 pipeline stages exposed as MCP tools; `agent_system/test_mcp_server.py` proves a real MCP client can discover and call them in sequence |
| **Multi-agent systems (ADK)** | `agent_system/adk_agents.py` | 3 `LlmAgent`s + a `SequentialAgent` coordinator, each scoped to one MCP tool via `tool_filter` |
| **Agent skills** | `agent_system/skills/log-triage/SKILL.md` | A real ADK-native Agent Skill (same `SKILL.md` format used by Claude's own skill system), loaded via `google.adk.skills.load_skill_from_dir` and attached to `analyst_agent` |
| **Security features** | `agent_system/security.py` | Prompt-injection detection/neutralization on untrusted log content, path-traversal guards, file-size caps, least-privilege tool scoping — all exercised by `agent_system/run_demo.py`, including an adversarial test case with two planted injection attempts |

Run `python agent_system/run_demo.py` for a single script that produces
observable evidence for all four.

## Quickstart

```bash
pip install -r requirements.txt   # or: pip install python-dateutil mcp google-adk

# 1. Run the pipeline directly (no agents, just the 3 scripts)
python log_anamoly.py                                    # writes /tmp/incident_*.txt
python reduce_for_llm.py /tmp/incident_<timestamp>.txt    # writes *_reduced.txt
python analyze_incident.py /tmp/incident_<timestamp>_reduced.txt

# 2. Or run the full agent demo (MCP + security + skills, no LLM call needed)
python agent_system/run_demo.py

# 3. Or run the real ADK multi-agent pipeline (needs GOOGLE_API_KEY + internet)
python agent_system/adk_agents.py
```

By default everything runs in **mock mode** (`[LLM] mock = True` in
`log_anomaly.properties`) — zero API calls, zero tokens spent, so the whole
pipeline is demoable with no key at all. Flip `mock = False` and set
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` once you want real
LLM output.

## The sample data is 100% synthetic

Everything under `logs/`, `apache_logs/`, and `sample_data/` describes a
fictional company, **SlothStay Vacation Exchange**. The domain
(`services.slothstay.example`) uses the reserved `.example` TLD, IPs use
the RFC 5737 documentation ranges, and the API key is an obvious
placeholder. Regenerate it any time with:

```bash
python sample_data/generate_synthetic_logs.py
```

No real company data is anywhere in this repository.

## Project structure

```
log_anamoly.py                 # stage 1: extraction + time correlation
reduce_for_llm.py               # stage 2: token-reduction
analyze_incident.py             # stage 3: LLM summarization
log_anomaly.properties          # config: log folders, keywords, [LLM] settings
logs/, apache_logs/             # synthetic demo logs (default config points here)
sample_data/                    # the generator + a self-contained copy of the demo data
agent_system/
  mcp_server.py                  # MCP tools wrapping the 3 stages
  adk_agents.py                  # ADK multi-agent orchestration
  agent_skills.py                # loads the log-triage Agent Skill
  security.py                    # prompt-injection defense, path/size guards, tool scoping
  skills/log-triage/SKILL.md      # the published Agent Skill
  run_demo.py                    # single script demonstrating all 4 concepts
  test_mcp_server.py              # MCP-client-only test (no ADK/LLM needed)
```

## License

CC0 — see the synthetic sample data's own disclaimer above; use this
however you like.
