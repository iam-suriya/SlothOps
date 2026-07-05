"""
reduce_for_llm.py  -  Token-reduction pass for the LLM stage.

WHAT IT DOES (in order):
  1. Fold stack traces   -> keep the top + bottom frames, drop the middle.
  2. Trim payload bodies -> shorten noisy INFO/Solr/XML/JSON lines, keep error
                            lines long so the model still sees the real signal.
  3. Template + collapse -> group lines with the same "shape" and show a count,
                            using Drain3 if installed (falls back to a regex shape).
  4. Report token savings (before vs after) so you can SEE the reduction.

HOW TO RUN:
    pip install drain3 tiktoken          # both optional but recommended
    python reduce_for_llm.py /tmp/incident_2026-06-19_14-55-22.txt

Output is written next to the input as *_reduced.txt  ->  feed THAT to the LLM.

This does NOT touch your collection script. It is a clean stage that runs after it.
"""
import os
import re
import sys

# ── Optional deps: the script still works without them, just less effectively ──
try:
    from drain3 import TemplateMiner
    _miner = TemplateMiner()
    _HAS_DRAIN = True
except Exception:
    _miner = None
    _HAS_DRAIN = False

try:
    import tiktoken
    _enc = tiktoken.get_encoding("cl100k_base")   # generic counter, close enough for sizing
except Exception:
    _enc = None


# ── Tunables ───────────────────────────────────────────────────────────────
ERROR_HINTS = ("error", "exception", "severe", "fatal", "caused by")
ERROR_LINE_CAP = 1500     # error/exception lines: keep this much (preserves stack signal)
NOISE_LINE_CAP = 300      # routine INFO / payload lines: trim hard
STACK_KEEP_TOP = 8        # stack frames to keep from the top (where it broke)
STACK_KEEP_BOTTOM = 3     # frames to keep from the bottom (entry point)


def _strip_prefix(line):
    """Your collector writes '[filename] message'. Split that off so we can
    analyse the message, but remember the prefix to put it back."""
    m = re.match(r'^(\[[^\]]+\]\s)(.*)$', line)
    return (m.group(1), m.group(2)) if m else ("", line)


def _is_stack_frame(msg):
    """True for Java stack-trace frame lines like '   at com.foo.Bar(Bar.java:42)'."""
    return bool(re.match(r'^\s*at\s+\S+\(', msg)) or msg.strip().startswith("... ")


def _shape(msg):
    """Stable 'shape' of a line, used to group duplicates. Drain3 if available,
    else a regex that blanks timestamps, long numbers and bracketed thread names."""
    if _HAS_DRAIN:
        return _miner.add_log_message(msg)["template_mined"]
    s = re.sub(r'\d{2,4}[-/.]\d{1,2}[-/.]\d{1,2}[ T]\d{1,2}:\d{2}:\d{2}([,.]\d{1,6})?', '<T>', msg)   # ISO/syslog
    s = re.sub(r'\d{1,2}/[A-Za-z]{3}/\d{4}:\d{1,2}:\d{2}:\d{2}(?:\s[+-]\d{4})?', '<T>', s)             # Apache combined
    s = re.sub(r'\d{1,2}-[A-Za-z]{3}-\d{4}\s\d{1,2}:\d{2}:\d{2}(?:\.\d{1,6})?', '<T>', s)              # Tomcat/Catalina
    s = re.sub(r'\d{4,}', '<N>', s)
    s = re.sub(r'\[[^\]]*\]', '<B>', s)
    return s.strip()


def _trim(msg):
    """Type-aware truncation: keep error lines long, trim routine/payload lines.
    Cutting the giant Solr query / XML / JSON bodies is where most tokens go,
    and it costs almost no diagnostic context.

    IMPORTANT: the x-amzn-trace-id is the strongest correlation key, but it sits
    deep in the line (past the 300-char noise cap). So even when we trim, we keep
    the trace-id on the end - otherwise we'd cut off the very thing the LLM needs
    to link Lambda <-> Tomcat <-> request/response lines together."""
    cap = ERROR_LINE_CAP if any(h in msg.lower() for h in ERROR_HINTS) else NOISE_LINE_CAP
    if len(msg) <= cap:
        return msg
    m = re.search(r'x-amzn-trace-id=Root=[\w-]+', msg)
    tail = f"  …{m.group()}" if m else " …(trimmed)"
    return msg[:cap] + tail


def _fold_stack(lines):
    """Collapse a long run of consecutive stack-trace frames into
    top frames + '[N frames omitted]' + bottom frames. The model reads that fine,
    and the top frames are the part that actually tells you where it broke."""
    out, i = [], 0
    while i < len(lines):
        prefix, msg = _strip_prefix(lines[i])
        if _is_stack_frame(msg):
            j = i
            while j < len(lines) and _is_stack_frame(_strip_prefix(lines[j])[1]):
                j += 1
            frames = lines[i:j]
            if len(frames) > STACK_KEEP_TOP + STACK_KEEP_BOTTOM:
                omitted = len(frames) - STACK_KEEP_TOP - STACK_KEEP_BOTTOM
                out.extend(frames[:STACK_KEEP_TOP])
                out.append(f"{prefix}    ... [{omitted} stack frames omitted] ...")
                out.extend(frames[-STACK_KEEP_BOTTOM:])
            else:
                out.extend(frames)
            i = j
        else:
            out.append(lines[i])
            i += 1
    return out


def reduce_file(in_path):
    with open(in_path, "r", encoding="utf-8-sig") as f:
        lines = [ln.rstrip("\n") for ln in f if ln.strip()]

    # 1) fold stack traces first (operates on raw lines)
    lines = _fold_stack(lines)

    # 2) + 3) trim each line, then collapse consecutive same-shape lines with a count
    out = []
    last_shape = None
    run = 0
    for ln in lines:
        prefix, msg = _strip_prefix(ln)
        sh = _shape(msg)
        if sh == last_shape:
            run += 1
            continue
        if run > 0:
            out.append(f"    ... [previous line repeated {run + 1}x] ...")
        out.append(prefix + _trim(msg))
        last_shape = sh
        run = 0
    if run > 0:
        out.append(f"    ... [previous line repeated {run + 1}x] ...")

    reduced = "\n".join(out) + "\n"

    out_path = os.path.splitext(in_path)[0] + "_reduced.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(reduced)

    # 4) report savings
    before_chars = sum(len(l) for l in lines)
    after_chars = len(reduced)
    print(f"lines : {len(lines)} -> {len(out)}")
    print(f"chars : {before_chars:,} -> {after_chars:,}  "
          f"({100 - after_chars * 100 // max(before_chars,1)}% smaller)")
    if _enc:
        b = len(_enc.encode("\n".join(lines)))
        a = len(_enc.encode(reduced))
        print(f"tokens: {b:,} -> {a:,}  ({100 - a * 100 // max(b,1)}% smaller)")
    else:
        print("tokens: install tiktoken to see the token count")
    print(f"templating: {'Drain3' if _HAS_DRAIN else 'regex fallback (pip install drain3 for better)'}")
    print(f"wrote: {out_path}")
    return out_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python reduce_for_llm.py <incident_file.txt>")
        sys.exit(1)
    reduce_file(sys.argv[1])
