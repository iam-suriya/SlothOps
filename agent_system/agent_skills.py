"""
agent_skills.py — loads the log-triage Agent Skill (agent_system/skills/log_triage/SKILL.md)
using ADK's own native Skills feature (google.adk.skills / google.adk.tools.skill_toolset)
and exposes a SkillToolset any agent can be given.

WHY A "SKILL" AND NOT JUST MORE INSTRUCTION TEXT
  Everything the skill's SKILL.md says COULD have been pasted directly into
  extraction_agent/reduction_agent/analyst_agent's instruction strings in
  adk_agents.py. Publishing it as a Skill instead means:
    - It's discoverable and reusable by a DIFFERENT agent that has never
      seen this codebase -- point any ADK agent (or Claude, which uses the
      exact same SKILL.md convention) at this folder and it can pick up the
      same playbook.
    - It's versioned and self-contained (frontmatter has a license and
      version, separate from the agent code that happens to use it today).
    - It documents the security expectations (untrusted log content,
      path-traversal guards) as part of the capability itself, not as a
      comment only the original author will ever read.

This module is deliberately small: ADK does the SKILL.md parsing
(google.adk.skills.load_skill_from_dir) and the tool-calling machinery
(google.adk.tools.skill_toolset.SkillToolset) that lets an LlmAgent call
load_skill / load_skill_resource to read it at runtime.
"""
import os

from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

SKILLS_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_TRIAGE_SKILL_DIR = os.path.join(SKILLS_DIR, "skills", "log-triage")


def load_log_triage_skill():
    """Parses agent_system/skills/log_triage/SKILL.md into an ADK Skill object."""
    return load_skill_from_dir(LOG_TRIAGE_SKILL_DIR)


def build_skill_toolset() -> SkillToolset:
    """Returns a SkillToolset exposing the log-triage skill's load_skill /
    load_skill_resource tools. Add this to any LlmAgent's `tools=[...]` list
    to give it the ability to discover and read the skill at runtime."""
    skill = load_log_triage_skill()
    return SkillToolset(skills=[skill])


if __name__ == "__main__":
    # Quick manual check: parse the skill and print its metadata, no agent needed.
    skill = load_log_triage_skill()
    print("name:", skill.frontmatter.name)
    print("description:", skill.frontmatter.description)
    print("license:", skill.frontmatter.license)
    print("allowed_tools:", skill.frontmatter.allowed_tools)
    print("metadata:", skill.frontmatter.metadata)
    print()
    print("--- instructions body (first 300 chars) ---")
    print(skill.instructions[:300])
