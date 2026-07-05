"""
analyze_incident.py — turns a reduced, correlated incident report into a short,
NON-technical summary for two audiences: QA testers and marketing/business
stakeholders. No stack traces, no class names, no jargon in the output.

WHERE THIS FITS IN THE PIPELINE
  log_anamoly.py     -> finds + time-correlates the incident across log sources
  reduce_for_llm.py  -> shrinks it so it's cheap to hand to an LLM
  analyze_incident.py (this file) -> the actual LLM call + a compact answer:
      what broke, who it affected, how bad it was, how to verify the fix,
      and current status.

COST CONTROL (the point was to burn as few tokens as possible)
  - Feeds the LLM the *reduced* report (output of reduce_for_llm.py), never the raw one.
  - Uses a small/cheap model by default (Claude Haiku / GPT-4o-mini).
  - Caps the response length and asks for one-sentence fields only, one JSON
    object back, no markdown, no restating the logs.
  - ONE call summarizes every incident in the report -- not one call each.
  - No API key configured? Runs in --mock mode automatically: zero tokens
    spent, returns a realistic example so the rest of the pipeline/notebook
    is still fully demoable.

PROVIDERS
  Auto-detects which key is set, checked in this order:
  ANTHROPIC_API_KEY -> OPENAI_API_KEY -> GOOGLE_API_KEY.
  Override with --provider anthropic|openai|google. No key set -> mock mode.

USAGE
  python analyze_incident.py /tmp/incident_..._reduced.txt
  python analyze_incident.py /tmp/incident_..._reduced.txt --provider anthropic
  python analyze_incident.py /tmp/incident_..._reduced.txt --provider google
  python analyze_incident.py /tmp/incident_..._reduced.txt --mock
"""
import argparse
import configparser
import json
import os

DEFAULT_MODELS = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai": "gpt-4o-mini",
    "google": "gemini-2.5-flash",  # check https://ai.google.dev/gemini-api/docs/models for the current cheapest model name
}

SCHEMA_INSTRUCTIONS = """You are summarizing a production incident from correlated application logs \
for two audiences who are NOT engineers: QA testers who need to know what to re-test, \
and a marketing/business stakeholder who needs to know customer impact. \
Do not use code, stack traces, class names, exception names, or technical jargon.

Respond with ONLY a JSON object (no markdown fences, no extra text) matching exactly this shape:

{
  "incidents": [
    {
      "incident_id": "short label, e.g. INC-1",
      "when": "date/time range, from the logs",
      "what_broke": "one plain-English sentence",
      "customer_impact": "one plain-English sentence: who/what was affected and for how long",
      "severity": "High | Medium | Low",
      "how_to_verify_fix": "one sentence a tester can act on",
      "status": "one short phrase, e.g. Needs retest / Resolved / Recurring"
    }
  ]
}

List one object per distinct incident found in the log excerpt. Keep every value to one short \
sentence. Do not repeat the same information across fields. Do not include any text outside the \
JSON object."""


def load_llm_settings(config_file):
    """Reads the [LLM] section of log_anomaly.properties, if present.
    Returns (provider, mock, max_tokens) with sensible fallbacks when the
    section, the file, or individual keys are missing."""
    provider, mock, max_tokens = None, False, 700
    if config_file and os.path.exists(config_file):
        settings = configparser.ConfigParser()
        settings.read(config_file)
        if settings.has_section("LLM"):
            raw_provider = settings.get("LLM", "provider", fallback="auto").strip().lower()
            provider = None if raw_provider in ("", "auto") else raw_provider
            mock = settings.getboolean("LLM", "mock", fallback=False)
            max_tokens = settings.getint("LLM", "max_tokens", fallback=700)
    return provider, mock, max_tokens


def build_prompt(log_excerpt: str) -> tuple[str, int]:
    """Wraps the (already reduced) log excerpt with the JSON-schema instructions
    above. Kept as one string so it's obvious exactly what gets sent -- and
    therefore exactly what gets billed -- to the LLM.

    Security: log content is untrusted (see agent_system/security.py's module
    docstring for why). Before it goes anywhere near the prompt, this:
      1. hard-caps its size (truncate_for_prompt) as a last-resort cost/DoS guard,
      2. scans it for prompt-injection patterns and neutralizes any matches
         (sanitize_for_prompt), and
      3. prepends an explicit "this is data, not instructions" notice
         (UNTRUSTED_DATA_NOTICE) as defense in depth on top of (2).

    Falls back to using the excerpt as-is (no sanitization) only if the
    security module can't be imported, e.g. this file is used standalone
    outside the full project layout -- logged loudly so that's never silent.

    Returns (prompt, flagged_count) so the caller can report how many
    suspicious lines were caught.
    """
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from agent_system.security import sanitize_for_prompt, truncate_for_prompt, UNTRUSTED_DATA_NOTICE
        capped = truncate_for_prompt(log_excerpt)
        sanitized, flagged = sanitize_for_prompt(capped)
        prompt = (
            f"{SCHEMA_INSTRUCTIONS}\n\n{UNTRUSTED_DATA_NOTICE}\n\n"
            f"--- LOG EXCERPT ---\n{sanitized}\n--- END LOG EXCERPT ---"
        )
        return prompt, flagged
    except ImportError:
        print("Warning: agent_system.security not importable -- sending log excerpt WITHOUT "
              "prompt-injection sanitization. This should not happen in the full project layout.")
        return f"{SCHEMA_INSTRUCTIONS}\n\n--- LOG EXCERPT ---\n{log_excerpt}\n--- END LOG EXCERPT ---", 0


def call_anthropic(prompt, model, max_tokens):
    """One-shot call to the Anthropic Messages API. Imported lazily (inside
    the function, not at module load) so the `anthropic` package is only
    required if you actually pick this provider -- mock mode never needs it."""
    import anthropic
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    resp = client.messages.create(
        model=model, max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def call_openai(prompt, model, max_tokens):
    """One-shot call to the OpenAI Chat Completions API. Same lazy-import
    reasoning as call_anthropic -- `openai` is only required if you pick this
    provider."""
    import openai
    client = openai.OpenAI()  # reads OPENAI_API_KEY from env
    resp = client.chat.completions.create(
        model=model, max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content


def call_google(prompt, model, max_tokens):
    """One-shot call to the Google Gemini API via the google-genai SDK (the
    current unified SDK -- NOT the older, now-superseded google-generativeai
    package). Same lazy-import reasoning as call_anthropic/call_openai -- the
    package is only required if you pick this provider.

    pip install google-genai
    """
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"))
    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(max_output_tokens=max_tokens),
    )
    return resp.text


def mock_response():
    """Zero-token stand-in so the pipeline is demoable without an API key."""
    return json.dumps({
        "incidents": [
            {
                "incident_id": "INC-1",
                "when": "2026-07-04 09:05-09:06 UTC",
                "what_broke": "Listings search timed out for one partner, so their search results didn't load.",
                "customer_impact": "One partner's listings search failed for about a minute; no data was lost.",
                "severity": "Medium",
                "how_to_verify_fix": "Re-run a listings search for that partner and confirm results return within 3 seconds.",
                "status": "Needs retest",
            },
            {
                "incident_id": "INC-2",
                "when": "2026-07-04 09:13-09:14 UTC",
                "what_broke": "A backend queue filled up and started rejecting new requests for about a minute.",
                "customer_impact": "Some search requests briefly failed during that minute; retries succeeded.",
                "severity": "Low",
                "how_to_verify_fix": "Send repeated requests during peak load and confirm none are rejected.",
                "status": "Needs retest",
            },
            {
                "incident_id": "INC-3",
                "when": "2026-07-04 09:23 UTC",
                "what_broke": "A single listings search request was dropped due to a backend overload condition.",
                "customer_impact": "One partner saw a failed search; a retry would have succeeded.",
                "severity": "Low",
                "how_to_verify_fix": "Trigger the same search again and confirm it succeeds without error.",
                "status": "Resolved",
            },
        ],
        "_mock": True,
    }, indent=2)


REQUIRED_KEY = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google": "GOOGLE_API_KEY",
}


def analyze(in_path, provider=None, mock=False, max_tokens=700):
    """Reads the reduced incident file at in_path and returns the LLM's raw
    JSON string response (or the mock JSON string if mock=True or no usable
    API key is configured).

    provider=None means "auto-detect": prefer Anthropic if ANTHROPIC_API_KEY
    is set, else OpenAI if OPENAI_API_KEY is set, else Google if
    GOOGLE_API_KEY is set. If none of the three exist, falls back to mock.

    provider="anthropic"/"openai"/"google" (explicit, e.g. from --provider or
    the [LLM] provider setting) is honored as-is -- it does NOT silently swap
    to a different provider just because a different key happens to be set.
    If the key that specific provider needs is missing, this falls back to
    mock with a warning rather than crashing with an SDK auth error.
    """
    with open(in_path, "r", encoding="utf-8-sig") as f:
        log_excerpt = f.read()

    # Sanitization runs unconditionally, mock or not -- this is a security
    # check on untrusted input, not an LLM-cost optimization, so it must not
    # be skippable just by being in mock mode. This is also how the
    # prompt-injection defense gets demonstrated without spending any tokens.
    prompt, flagged = build_prompt(log_excerpt)
    if flagged:
        print(f"Security: neutralized {flagged} log line(s) that looked like prompt-injection attempts before sending to the LLM.")

    if mock:
        return mock_response()

    if provider is None:
        # Auto-detect: first key found, in this priority order.
        for candidate, env_var in REQUIRED_KEY.items():
            if os.environ.get(env_var):
                provider = candidate
                break
        else:
            return mock_response()  # nothing configured anywhere -- quietly go to mock

    # A provider is now set, either explicitly or via auto-detect above.
    # Check THAT provider's specific key, not just "is any key set anywhere".
    required_env_var = REQUIRED_KEY[provider]
    if not os.environ.get(required_env_var):
        print(f"Warning: provider '{provider}' was requested but {required_env_var} is not set. "
              f"Falling back to mock mode instead of failing.")
        return mock_response()

    model = DEFAULT_MODELS[provider]

    if provider == "anthropic":
        return call_anthropic(prompt, model, max_tokens)
    elif provider == "openai":
        return call_openai(prompt, model, max_tokens)
    elif provider == "google":
        return call_google(prompt, model, max_tokens)
    raise ValueError(f"Unknown provider: {provider}")


def render_human(parsed):
    """Turns the parsed {"incidents": [...]} JSON into a short plain-text
    block per incident, for printing to the console (not sent to the LLM --
    this is purely local string formatting, so it costs no tokens)."""
    lines = []
    for inc in parsed.get("incidents", []):
        lines.append(f"[{inc.get('incident_id', '?')}] {inc.get('when', '')}  —  severity: {inc.get('severity', '?')}")
        lines.append(f"  What broke:      {inc.get('what_broke', '')}")
        lines.append(f"  Customer impact: {inc.get('customer_impact', '')}")
        lines.append(f"  Verify fix by:   {inc.get('how_to_verify_fix', '')}")
        lines.append(f"  Status:          {inc.get('status', '')}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reduced_incident_file", help="output of reduce_for_llm.py")
    ap.add_argument("--config", default="log_anomaly.properties",
                     help="properties file to read the [LLM] section from (default: log_anomaly.properties)")
    ap.add_argument("--provider", choices=["anthropic", "openai", "google"], default=None,
                     help="force a provider; overrides [LLM] provider / env auto-detection")
    ap.add_argument("--mock", action="store_true", help="skip the API call, return a canned example (0 tokens)")
    ap.add_argument("--max-tokens", type=int, default=None)
    args = ap.parse_args()

    # Config file provides the defaults; explicit CLI flags always win over it.
    cfg_provider, cfg_mock, cfg_max_tokens = load_llm_settings(args.config)
    provider = args.provider or cfg_provider
    mock = args.mock or cfg_mock
    max_tokens = args.max_tokens or cfg_max_tokens

    raw = analyze(args.reduced_incident_file, provider=provider, mock=mock, max_tokens=max_tokens)

    # Always save the raw response next to the input file, even if it's not
    # valid JSON, so nothing is lost if the model misbehaves.
    out_path = os.path.splitext(args.reduced_incident_file)[0] + "_summary.json"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(raw)

    try:
        parsed = json.loads(raw)
        print(render_human(parsed))
        print(f"wrote: {out_path}")
    except json.JSONDecodeError:
        print("Warning: model did not return valid JSON. Raw output saved to", out_path)
        print(raw)
