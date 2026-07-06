"""
build_notebook.py — generates SlothOps_Capstone.ipynb: a self-contained
Kaggle notebook that clones this repo, runs the real pipeline, and renders
the before/after and timeline charts LIVE from computed numbers (not static
images), per the recommendation to lean into Kaggle's EDA/visualization
strengths.

This script is a build tool, not part of the shipped project -- it's not
imported by anything else here.

Run:  python build_notebook.py
Then execute with nbclient to embed real outputs before uploading to Kaggle:
    python -c "from build_notebook import execute; execute()"
"""
import nbformat as nbf

nb = nbf.v4.new_notebook()
nb["metadata"]["kernelspec"] = {
    "display_name": "Python 3",
    "language": "python",
    "name": "python3",
}
nb["metadata"]["language_info"] = {"name": "python"}
cells = []


def md(text):
    cells.append(nbf.v4.new_markdown_cell(text))


def code(text):
    cells.append(nbf.v4.new_code_cell(text))


md("""\
# SlothOps — Multi-Agent Log Incident Triage

**AI Agents: Intensive Vibe Coding Capstone (Freestyle track)**

Point this at raw logs from multiple sources (a reverse proxy, an app server,
a serverless function) and it correlates them into one incident, shrinks the
result for cheap LLM consumption, and produces a plain-English summary for
QA testers and marketing/business stakeholders — no stack traces, no jargon.

This notebook demonstrates four capstone concepts end to end, with real,
computed evidence for each (not claims):

| Concept | Where |
|---|---|
| **MCP servers** | `agent_system/mcp_server.py` |
| **Multi-agent systems (Google ADK)** | `agent_system/adk_agents.py` |
| **Agent skills** | `agent_system/skills/log-triage/SKILL.md` |
| **Security features** | `agent_system/security.py` |

Source: https://github.com/iam-suriya/SlothOps (CC0 license)
""")

code("""\
import os
if not os.path.exists('SlothOps'):
    !git clone -q https://github.com/iam-suriya/SlothOps.git
else:
    # Kaggle's /kaggle/working persists across "Restart and run all" within the
    # same draft session -- without this, a SlothOps/ folder cloned earlier
    # (before a later push) would silently stick around stale, and any new
    # files/folders added since (like extended_incidents_v2/) would be missing
    # even though the repo on GitHub has them.
    !cd SlothOps && git fetch -q origin main && git reset -q --hard origin/main
%cd SlothOps
!pip install -q -r requirements.txt
""")

md("""\
## 1. The dataset — pick which sample set to run

Every log file here is **100% synthetic** — a fictional company, "SlothStay
Vacation Exchange." The domain uses the reserved `.example` TLD, IPs use the
RFC 5737 documentation ranges, and API keys are obvious placeholders.

Two sample sets ship with this repo. Change **`DATASET`** in the cell below
to switch, then use the "Restart and run all cells" menu — everything
downstream (the timeline chart, reduction numbers, LLM summary, MCP/ADK
demos) reads from whichever one you pick, live.

| `DATASET` value | Config file used | Incidents |
|---|---|---|
| `"default"` | `log_anomaly.properties` | whatever the repo's main config currently points to |
| `"sample1"` | `sample_data/log_anomaly.properties` | 3: Lambda timeout, repeated Tomcat burst, cross-file exception |
| `"sample2"` | `extended_incidents_v2/log_anomaly_v2.properties` | 5: adds connection-pool exhaustion + thread deadlock |
""")

code("""\
# ── Change this one line, then Restart and run all cells ──
DATASET = "default"   # "default" | "sample1" | "sample2"

CONFIG_PATHS = {
    "default": "log_anomaly.properties",
    "sample1": "sample_data/log_anomaly.properties",
    "sample2": "extended_incidents_v2/log_anomaly_v2.properties",
}
CONFIG_PATH = CONFIG_PATHS[DATASET]
print(f"DATASET = {DATASET!r}  ->  using config: {CONFIG_PATH}")
""")

code("""\
import configparser
import os

settings = configparser.ConfigParser()
settings.read(CONFIG_PATH)
log_dir = settings["SETTINGS"]["log_folder"]
rr_dir = settings["SETTINGS"]["request_response_log_folder"]

sources = {}
for label, directory in [("Apache combined log (reverse proxy)", rr_dir),
                          ("Tomcat/Catalina + AWS Lambda/CloudWatch logs (app server + serverless)", log_dir)]:
    if not os.path.isdir(directory):
        continue
    for fname in sorted(os.listdir(directory)):
        if fname.endswith((".log", ".txt")):
            sources[f"{label}: {fname}"] = os.path.join(directory, fname)

for label, path in sources.items():
    with open(path, encoding="utf-8-sig") as f:
        lines = f.readlines()
    print(f"--- {label} ---")
    print(f"{path}: {len(lines)} lines")
    print(lines[0].strip()[:160])
    print()
""")

md("""\
## 2. Stage 1 — Extraction & time correlation

`log_anamoly.py` scans all three log folders for ERROR/WARN/EXCEPTION/timeout
triggers, then correlates every log line within ±2 minutes of any trigger
across **all three sources** into one incident report — this is what lets a
Lambda timeout, the Tomcat slow-response warning it caused, and the Apache
504 it produced downstream all show up together, even though they're in
three separate files.
""")

code("""\
from log_anamoly import run_log_analysis

report_path = run_log_analysis(CONFIG_PATH)
print("\\nIncident report written to:", report_path)

with open(report_path, encoding="utf-8-sig") as f:
    raw_lines = f.readlines()
print(f"{len(raw_lines)} lines in the raw correlated report.")
""")

md("""\
### A quick look at the timeline

Real EDA for log data isn't histograms of tabular features — it's *when did
things happen, and on which source*. This plots every correlated line's
timestamp, colored by source, with the actual trigger lines (ERROR/WARN/
EXCEPTION) highlighted — the three incident clusters should be visible.
""")

code("""\
import re
import matplotlib.pyplot as plt
from datetime import datetime
from log_anamoly import get_time_from_line

records = []
for line in raw_lines:
    m = re.match(r"^\\[([^\\]]+)\\]\\s(.*)$", line)
    if not m:
        continue
    source, msg = m.groups()
    ts = get_time_from_line(msg)
    if not ts:
        continue
    is_trigger = any(k in msg.lower() for k in ("error", "severe", "exception", "warn", "timed out"))
    records.append((ts, source, is_trigger))

colors = {"apache-access.log": "#1f77b4", "tomcat.log": "#ff7f0e", "lambda.log": "#2ca02c"}
fig, ax = plt.subplots(figsize=(11, 3.5))
for source in colors:
    xs = [r[0] for r in records if r[1] == source and not r[2]]
    ax.scatter(xs, [source] * len(xs), color=colors[source], alpha=0.4, s=20, label=f"{source} (normal)")
    xs_trig = [r[0] for r in records if r[1] == source and r[2]]
    ax.scatter(xs_trig, [source] * len(xs_trig), color=colors[source], marker="x", s=90, label=f"{source} (trigger)")
ax.set_title("Correlated incident timeline across all 3 log sources")
ax.set_xlabel("Time")
fig.autofmt_xdate()
ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=8)
plt.tight_layout()
plt.savefig("assets/timeline_chart.png", dpi=110)
plt.show()
""")

md("""\
## 3. Stage 2 — Reduction

`reduce_for_llm.py` folds long stack traces to their top/bottom frames, trims
noisy payload lines, and collapses repeated lines *before* anything is sent
to an LLM. The numbers below are computed live against the report generated
above, not hardcoded.
""")

code("""\
import io
import re
import contextlib
from reduce_for_llm import reduce_file

# reduce_file() prints its own authoritative before/after numbers (measured
# internally, after stack-folding has already run) -- capture that stdout
# and parse it directly instead of re-deriving the math a second, slightly
# different way. This guarantees the chart below matches the script's own
# reported numbers exactly, by construction.
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    reduced_path = reduce_file(report_path)
report_text = buf.getvalue()
print(report_text)

lines_before, lines_after = map(int, re.search(r"lines\\s*:\\s*([\\d,]+)\\s*->\\s*([\\d,]+)", report_text).groups())
chars_before, chars_after = (int(x.replace(",", "")) for x in
                              re.search(r"chars\\s*:\\s*([\\d,]+)\\s*->\\s*([\\d,]+)", report_text).groups())
""")

code("""\
import matplotlib.pyplot as plt

metrics = ["Lines", "Characters"]
before_vals = [lines_before, chars_before]
after_vals = [lines_after, chars_after]

fig, ax = plt.subplots(figsize=(6, 4))
x = range(len(metrics))
width = 0.35
bars1 = ax.bar([i - width/2 for i in x], before_vals, width, label="Before reduce", color="#d62728")
bars2 = ax.bar([i + width/2 for i in x], after_vals, width, label="After reduce", color="#2ca02c")
ax.set_xticks(list(x))
ax.set_xticklabels(metrics)
ax.set_title("Token-reduction stage: before vs. after (computed live)")
ax.legend()
for bars in (bars1, bars2):
    for b in bars:
        ax.annotate(f"{int(b.get_height()):,}", (b.get_x() + b.get_width()/2, b.get_height()),
                    ha="center", va="bottom", fontsize=8)
plt.tight_layout()
plt.savefig("assets/reduction_chart_live.png", dpi=110)
plt.show()
""")

md("""\
## 4. Stage 3 — LLM analysis (mock mode by default)

`analyze_incident.py` sends the reduced report to an LLM and gets back a
structured, non-technical summary. This notebook runs in **mock mode**
(`[LLM] mock = True`) by default — zero tokens spent, zero API key required
— so it's fully reproducible for anyone running this notebook cold. Flip
`mock = False` in whichever config `CONFIG_PATH` points to and set
`GOOGLE_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` in the Kaggle
notebook's Secrets to get a real LLM-generated summary instead.
""")

code("""\
import json
import pandas as pd
from analyze_incident import analyze, load_llm_settings

provider, mock, max_tokens = load_llm_settings(CONFIG_PATH)
raw = analyze(reduced_path, provider=provider, mock=mock, max_tokens=max_tokens)
result = json.loads(raw)

df = pd.DataFrame(result["incidents"])
df
""")

code("""\
import matplotlib.pyplot as plt

severity_counts = df["severity"].value_counts().reindex(["High", "Medium", "Low"]).fillna(0)
fig, ax = plt.subplots(figsize=(4, 4))
colors = {"High": "#d62728", "Medium": "#ff7f0e", "Low": "#2ca02c"}
ax.pie(severity_counts, labels=severity_counts.index, autopct="%1.0f%%",
       colors=[colors[s] for s in severity_counts.index])
ax.set_title(f"Severity breakdown ({len(df)} incidents found)")
plt.tight_layout()
plt.savefig("assets/severity_chart.png", dpi=110)
plt.show()
""")

md("""\
## 5. Security — prompt-injection defense against adversarial input

Log content is untrusted data. `agent_system/security.py` scans it for
prompt-injection patterns before it ever reaches an LLM prompt. This runs
the pipeline's own adversarial test case — a reduced report with two planted
injection attempts disguised as log lines — through the exact same code path
`analyze_incident.py` uses in production.
""")

code("""\
from agent_system.security import sanitize_for_prompt

with open("agent_system/hard_test_incident_reduced.txt", encoding="utf-8-sig") as f:
    adversarial_text = f.read()

sanitized, flagged = sanitize_for_prompt(adversarial_text)
print(f"Flagged and neutralized {flagged} prompt-injection attempt(s) before they could reach the LLM.\\n")
for line in sanitized.splitlines():
    if "[SECURITY:" in line:
        print(line)
""")

md("""\
## 6. MCP servers — a real MCP client calling the pipeline as tools

This connects an actual MCP client to `agent_system/mcp_server.py` over
stdio and calls all 3 pipeline stages in sequence — exactly what happens
when an agent (not a human running scripts) drives this pipeline.
""")

code("""\
import asyncio, json, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def demo_mcp():
    params = StdioServerParameters(command=sys.executable, args=["agent_system/mcp_server.py"], cwd=".")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("MCP tools discovered:", [t.name for t in tools.tools])

            r1 = json.loads((await session.call_tool("extract_incident", {"config_path": CONFIG_PATH})).content[0].text)
            print("extract_incident ->", r1)
            r2 = json.loads((await session.call_tool("reduce_report", {"report_path": r1["report_path"]})).content[0].text)
            print("reduce_report    ->", r2)
            r3 = json.loads((await session.call_tool("analyze_incident_tool", {"reduced_path": r2["reduced_path"], "config_path": CONFIG_PATH})).content[0].text)
            print(f"analyze_incident_tool -> {len(r3['incidents'])} incidents summarized")

await demo_mcp()
""")

md("""\
## 7. Multi-agent systems (Google ADK) + Agent Skills

Three ADK `LlmAgent`s, each connected to the MCP server above with its
toolset filtered (`tool_filter`) to exactly ONE tool — least-privilege
access enforced by the framework — coordinated by a `SequentialAgent`. The
analyst agent also carries a real ADK-native **Agent Skill**
(`SKILL.md` — the same format used by Claude's own skill system).

A live run needs a model API key + outbound internet to
`generativelanguage.googleapis.com` (set `GOOGLE_API_KEY` via Kaggle
Secrets to actually execute it: `python agent_system/adk_agents.py`).
Constructing the agents below needs neither, and proves the wiring itself
is correct.
""")

code("""\
import agent_system.adk_agents as aa

print("Coordinator:", aa.log_triage_coordinator.name)
for agent in aa.log_triage_coordinator.sub_agents:
    tool_types = [type(t).__name__ for t in agent.tools]
    print(f"  - {agent.name}: model={agent.model}, tools={tool_types}")

from agent_system.agent_skills import load_log_triage_skill
skill = load_log_triage_skill()
print("\\nLoaded Agent Skill:", skill.frontmatter.name)
print("License:", skill.frontmatter.license)
print("Allowed tools:", skill.frontmatter.allowed_tools)
""")

md("""\
## Conclusion

Starting from three log-triage scripts a human ran by hand, this project
wraps them as MCP tools, puts a security layer in front of untrusted log
content, coordinates them with an ADK multi-agent system, and publishes the
methodology as a reusable Agent Skill — while keeping the original
cost-control goal (mock-mode-first, capped tokens, one LLM call per
incident batch, not per incident) intact throughout.

**Limitations:** the ADK agents' live reasoning wasn't exercised inside this
notebook's execution environment when it was authored (network-restricted
sandbox) — the wiring is verified to construct correctly and to reach the
real model API call boundary; a full live run needs a Kaggle Secret with a
valid `GOOGLE_API_KEY`.

**Future work:** real-time log streaming from CloudWatch/ELK instead of
static files, pushing summaries straight to Slack/PagerDuty/Jira, replacing
the heuristic line-folding with a learned relevance scorer, and broader
log-format coverage (nginx, structured JSON, Kubernetes events).

Source: https://github.com/iam-suriya/SlothOps — CC0 1.0 Universal.
""")

nb["cells"] = cells
nbf.write(nb, "SlothOps_Capstone.ipynb")
print("wrote SlothOps_Capstone.ipynb with", len(cells), "cells")


def execute():
    from nbclient import NotebookClient
    nb2 = nbf.read("SlothOps_Capstone.ipynb", as_version=4)
    client = NotebookClient(nb2, timeout=600, kernel_name="python3")
    client.execute()
    nbf.write(nb2, "SlothOps_Capstone.ipynb")
    print("executed and saved with real outputs embedded")


if __name__ == "__main__":
    pass
