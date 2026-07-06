"""
log_anamoly.py  -  Stage 1 of the pipeline: find an incident, then pull every
log line (across every source you point it at) that happened around the same
time, so a human or an LLM can see the whole story in one place.

WHAT IT DOES (in order):
  1. Read log_anomaly.properties to find out which folders to scan, which
     keywords count as a "trigger" (ERROR, WARN, etc.), and which mode to run.
  2. MODE A - individual_analysis = True:
     Plain grep. Print every line in log_folder that matches a keyword.
     No correlation, no time windows, no output file - just stdout.
  3. MODE B - individual_analysis = False (the main feature):
       a. Scan every log file in log_folder + request_response_log_folder for
          trigger keywords, and record the timestamp of every match.
       b. Turn each trigger timestamp into a +/-2 minute window, then merge
          any windows that overlap - this is what lets one incident that
          shows up in 3 different log files (Lambda, Tomcat, Apache/access
          log) get treated as ONE incident instead of three unrelated blips.
       c. Walk every log file again, this time writing out any line whose
          timestamp falls inside a merged window, in original file order.
          Consecutive lines with the same "shape" (see get_log_shape) get
          collapsed into a single line + a repeat count, so a burst of 200
          identical errors doesn't flood the report.
       d. Save everything to /tmp/incident_<first-trigger-time>.txt.

WHY MULTIPLE TIMESTAMP FORMATS MATTER:
  A typical stack does NOT log in one consistent format - a reverse proxy
  writes Apache combined log format, Tomcat writes its own Catalina format,
  and AWS Lambda writes ISO8601 to CloudWatch. TIMESTAMP_PATTERNS below
  covers all three so this tool can correlate across them, not just within
  a single file.

CONFIG FORMAT (log_anomaly.properties):
    [SETTINGS]
    individual_analysis = False       # True = Mode A, False = Mode B
    log_folder = logs/                # folder scanned for *.log / *.txt
    request_response_log_folder = request_response_logs/   # same, second folder
    search_keyword = ERROR|SEVERE|EXCEPTION|WARN   # pipe-separated, case-insensitive
    ignore_keywords = Exception in handleFault     # pipe-separated, lines containing these are skipped entirely

HOW TO RUN:
    python log_anamoly.py
    (reads ./log_anomaly.properties by default - see the __main__ block below)

Output of Mode B feeds directly into reduce_for_llm.py, which shrinks the
report before it's handed to an LLM in analyze_incident.py.
"""
import configparser
import os
import re
from datetime import timedelta, timezone
from dateutil import parser

# Supports the timestamp formats seen across a typical stack: app/Lambda logs
# (ISO/syslog style), Apache/nginx access logs, and Tomcat/Catalina logs.
# get_time_from_line() tries these in order and uses the first one that matches
# AND parses successfully, so adding a new log source is usually just adding
# one more pattern here.
TIMESTAMP_PATTERNS = [
    r'\d{2,4}[-/.]\d{1,2}[-/.]\d{1,2}[ T]\d{1,2}:\d{2}:\d{2}([,.]\d{1,6})?',   # 2026-07-04 09:15:32,123 / 2026-07-04T09:15:32.123Z
    r'\d{1,2}/[A-Za-z]{3}/\d{4}:\d{1,2}:\d{2}:\d{2}(?:\s[+-]\d{4})?',          # Apache combined: 04/Jul/2026:09:15:32 +0000
    r'\d{1,2}-[A-Za-z]{3}-\d{4}\s\d{1,2}:\d{2}:\d{2}(?:\.\d{1,6})?',           # Tomcat/Catalina: 04-Jul-2026 09:15:32.123
]


def get_time_from_line(line):
    """Parses timestamp with support for ISO/syslog, Apache combined, and Tomcat/Catalina formats.

    Returns a naive (no timezone) datetime, or None if nothing in the line
    matched any known format. Naive datetimes are used deliberately (see the
    comment below) so every timestamp in this program can be compared
    directly against every other one, regardless of which log it came from.
    """
    for pattern in TIMESTAMP_PATTERNS:
        match = re.search(pattern, line)
        if not match:
            continue
        raw = match.group()
        # Apache combined log writes "04/Jul/2026:09:15:32" with a ':' between
        # the date and the time instead of a space, which dateutil can't parse
        # as-is. Swap that one colon for a space before handing it off.
        normalized = re.sub(r'(\d{4}):(\d{1,2}:\d{2}:\d{2})', r'\1 \2', raw)
        try:
            parsed = parser.parse(normalized)
        except (ValueError, OverflowError):
            continue
        # Some formats (Apache combined, ISO with 'Z') parse as timezone-aware,
        # others (Tomcat/Catalina, plain ISO) parse as naive. Mixing the two
        # raises TypeError on comparison, so normalize everything to naive
        # UTC here -- correlation only needs consistent relative ordering.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    return None


def get_log_shape(line):
    """Strips dynamic content (timestamps, long numbers, bracketed thread/request IDs)
    to find the 'shape' of a log line, used to collapse runs of near-identical lines
    (e.g. the same error repeated 200 times in a retry loop) down to one line + a count.

    Two lines with different timestamps or thread IDs but the same underlying
    message will produce the same shape and therefore get collapsed together.
    """
    shape = line
    for pattern in TIMESTAMP_PATTERNS:
        shape = re.sub(pattern, '[TIME]', shape)
    shape = re.sub(r'\d{6,}', '[NUM]', shape)       # long numeric IDs (sequence numbers, offsets, etc.)
    shape = re.sub(r'\[.*?\]', '[THREAD]', shape)   # bracketed thread names / request IDs, e.g. [http-nio-8080-exec-22]
    return shape.strip()


def get_all_log_files(directories):
    """Collects every *.log / *.txt file across the given list of directories.
    Missing directories are silently skipped (useful when a config only sets
    one of log_folder / request_response_log_folder to something real)."""
    all_files = []
    for directory in directories:
        if os.path.exists(directory):
            all_files.extend([os.path.join(directory, f) for f in os.listdir(directory)
                             if f.endswith(('.log', '.txt'))])
    return all_files


def merge_windows(timestamps, minutes=2):
    """Turns a list of trigger timestamps into a list of (start, end) windows,
    each padded by `minutes` on either side, then merges any windows that
    overlap into one bigger window.

    This is the core of "correlation": if two ERRORs happen 90 seconds apart
    (each gets a +/-2 minute window), their windows overlap and get merged
    into a single incident window covering both - so one Lambda timeout and
    the Tomcat/Apache lines it caused a few seconds later end up in the same
    incident even though they came from different files.
    """
    if not timestamps: return []
    windows = sorted([(t - timedelta(minutes=minutes), t + timedelta(minutes=minutes)) for t in timestamps])
    merged = []
    curr_start, curr_end = windows[0]
    for next_start, next_end in windows[1:]:
        if next_start <= curr_end:
            curr_end = max(curr_end, next_end)   # overlap: extend the current window
        else:
            merged.append((curr_start, curr_end))  # no overlap: close out the current window, start a new one
            curr_start, curr_end = next_start, next_end
    merged.append((curr_start, curr_end))
    return merged


def run_log_analysis(config_file):
    """Entry point. Reads config_file, then runs either Mode A (grep) or
    Mode B (time-correlated incident report) depending on individual_analysis.

    Returns the path to the generated incident report on success (Mode B),
    or None (config error, no settings, no triggers found, or Mode A - which
    prints to stdout instead of writing a file). The return value is what
    lets this function be wrapped as an MCP tool / called from an agent
    pipeline, where the caller needs the report path to hand to the next stage.
    """
    if not os.path.exists(config_file):
        print(f"FAILED: Config '{config_file}' not found."); return None

    settings = configparser.ConfigParser()
    settings.read(config_file)

    try:
        is_individual = settings.getboolean('SETTINGS', 'individual_analysis')
        log_dir = settings['SETTINGS']['log_folder']
        rr_dir = settings['SETTINGS']['request_response_log_folder']
        # search_keyword / ignore_keywords are pipe-separated in the config file,
        # e.g. "ERROR|SEVERE|EXCEPTION|WARN" -> ["error", "severe", "exception", "warn"]
        search_terms = [k.strip().lower() for k in settings['SETTINGS']['search_keyword'].split('|')]
        ignore_terms = [k.strip().lower() for k in settings.get('SETTINGS', 'ignore_keywords', fallback='').split('|') if k.strip()]
    except KeyError as e:
        print(f"FAILED: Missing setting: {e}"); return None

    all_files = get_all_log_files([log_dir, rr_dir])

    if is_individual:
        # Mode A: plain keyword grep across log_folder only. No time correlation,
        # no output file - just prints every matching line with its source file.
        print("--- Mode: Individual Analysis (Grep) ---")
        for file_path in get_all_log_files([log_dir]):
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                for line in f:
                    if any(term in line.lower() for term in search_terms) and not any(ign in line.lower() for ign in ignore_terms):
                        print(f"[{os.path.basename(file_path)}] {line.strip()}")
        return None
    else:
        # Mode B: the main feature. First pass finds every trigger timestamp
        # across ALL files (app logs + request/response logs together).
        print("--- Mode: Correlation Analysis (Timeline-based) ---")
        trigger_timestamps = []
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8-sig') as f:
                    for line in f:
                        if any(term in line.lower() for term in search_terms) and not any(ign in line.lower() for ign in ignore_terms):
                            ts = get_time_from_line(line)
                            if ts: trigger_timestamps.append(ts)
            except Exception: continue  # unreadable/corrupt file - skip it, don't kill the whole run

        if not trigger_timestamps:
            print("No matching triggers found."); return None

        trigger_timestamps.sort()
        merged_windows = merge_windows(trigger_timestamps)

        # Name the report after the first incident's timestamp so multiple runs
        # on different days don't overwrite each other.
        output_filename = f"/tmp/incident_{trigger_timestamps[0].strftime('%Y-%m-%d_%H-%M-%S')}.txt"

        with open(output_filename, 'w', encoding='utf-8-sig') as outfile:
            # Second pass: walk every file again, this time writing out any
            # line that falls inside one of the merged windows.
            for file_path in all_files:
                last_shape = None
                repeat_count = 0
                # Tracks whether the CURRENT "record" is inside a trigger window.
                # A record can span multiple lines (e.g. a Java exception header
                # line followed by "at ..." stack frames that have no timestamp
                # of their own) - in_window lets those untimed continuation
                # lines inherit the in/out decision made for the line above them,
                # instead of being silently dropped for lacking a timestamp.
                in_window = False
                try:
                    with open(file_path, 'r', encoding='utf-8-sig') as f:
                        for line in f:
                            line_time = get_time_from_line(line)
                            if line_time:
                                in_window = any(start <= line_time <= end for start, end in merged_windows)
                            # else: no timestamp on this line -> keep whatever
                            # in_window was decided for the last timestamped line.

                            if in_window:
                                stripped = line.strip()
                                shape = get_log_shape(stripped)

                                if shape == last_shape:
                                    # Same shape as the line before it -> just bump the repeat counter,
                                    # don't write it out yet.
                                    repeat_count += 1
                                else:
                                    if repeat_count > 0:
                                        outfile.write(f"--- [Last line repeated {repeat_count + 1} times] ---\n")
                                    outfile.write(f"[{os.path.basename(file_path)}] {stripped}\n")
                                    last_shape = shape
                                    repeat_count = 0
                    # Final flush: if the file ended mid-repeat-run, write the count out.
                    if repeat_count > 0:
                        outfile.write(f"--- [Last line repeated {repeat_count + 1} times] ---\n")
                except Exception: continue  # unreadable/corrupt file - skip it, don't kill the whole run

        print(f"--- Analysis Complete. Report saved to: {output_filename} ---")
        return output_filename


if __name__ == "__main__":
    # Accepts an optional config path so you can switch between sample data
    # sets from the console instead of hand-editing log_anomaly.properties:
    #   python log_anamoly.py                                        # default: ./log_anomaly.properties
    #   python log_anamoly.py sample_data/log_anomaly.properties      # sample data 1 (3 incidents)
    #   python log_anamoly.py extended_incidents_v2/log_anomaly_v2.properties   # sample data 2 (5 incidents)
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", nargs="?", default="log_anomaly.properties",
                     help="properties file to read [SETTINGS] from (default: log_anomaly.properties)")
    args = ap.parse_args()
    run_log_analysis(args.config)
