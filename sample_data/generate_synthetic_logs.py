"""
generate_synthetic_logs.py — builds a fully synthetic, safe-to-publish log set
for the fictional "SlothStay Vacation Exchange" company, in the standard
formats a real stack actually produces, so the set can be dropped straight
into log_anamoly.py / reduce_for_llm.py as-is:

  sample_data/apache_logs/apache-access.log   - Apache combined log format (reverse proxy / front door)
  sample_data/logs/tomcat.log                 - Tomcat/Catalina application server log
  sample_data/logs/lambda.log                 - AWS Lambda / CloudWatch execution log

Nothing here is real: the domain uses the reserved .example TLD (RFC 2606),
IPs use the reserved documentation ranges 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24 (RFC 5737), and the API key/secret and trace IDs are obvious
placeholders.

Three incidents are seeded into a sea of normal traffic, correlated across
all three sources via shared trace IDs and timestamps within a couple of
seconds of each other — exactly the "Lambda <-> Tomcat <-> request/response"
correlation this toolkit is built to surface:
  1. Lambda cold-path timeout  -> Tomcat WARN slow response -> Apache 504
  2. Repeated Tomcat error burst (tests shape-based dedup/collapsing)
  3. Cross-file exception       -> Lambda ERROR -> Tomcat SEVERE + stack trace -> Apache 500

Run:  python generate_synthetic_logs.py
"""
import os
import random
from datetime import datetime, timedelta

random.seed(42)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APACHE_DIR = os.path.join(BASE_DIR, "apache_logs")
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(APACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

DOMAIN = "services.slothstay.example"
AFFILIATES = ["SLOTH", "NAP", "ZZZ", "YAWN", "LAZY", "COZY", "SNUG", "DOZE", "PJS"]
IPS = [f"192.0.2.{n}" for n in range(10, 30)] + \
      [f"198.51.100.{n}" for n in range(10, 30)] + \
      [f"203.0.113.{n}" for n in range(10, 30)]
API_KEY = "sloth-a1b2c3d4-NAPTIME-0007"

START = datetime(2026, 7, 4, 9, 0, 0)

apache_lines = []   # -> apache_logs/apache-access.log
tomcat_lines = []   # -> logs/tomcat.log
lambda_lines = []   # -> logs/lambda.log


def apache_ts(t):
    """Formats a datetime the way Apache's combined log format does:
    04/Jul/2026:09:15:32 +0000 -- this is one of the 3 formats
    log_anamoly.py's TIMESTAMP_PATTERNS knows how to parse."""
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def tomcat_ts(t):
    """Formats a datetime the way Tomcat/Catalina logs it:
    04-Jul-2026 09:15:32.123 (millisecond precision, randomized here
    since the source data doesn't carry sub-second granularity)."""
    ms = f"{random.randint(0, 999):03d}"
    return t.strftime("%d-%b-%Y %H:%M:%S") + f".{ms}"


def lambda_ts(t):
    """Formats a datetime the way AWS Lambda/CloudWatch logs it:
    2026-07-04T09:15:32.123Z (ISO8601 with a trailing Z for UTC)."""
    ms = f"{random.randint(0, 999):03d}"
    return t.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms}Z"


def fake_trace_id():
    """A fake x-amzn-trace-id-style value. Real trace IDs are how a Lambda
    invocation, its Tomcat backend call, and the Apache access log entry for
    the same request get tied together in real systems -- reusing ONE of
    these across all three synthetic log lines for a single request is what
    makes the correlation demo realistic."""
    return "Root=1-" + "".join(random.choices("0123456789abcdef", k=8)) + "-" + \
           "".join(random.choices("0123456789abcdef", k=24))


def fake_request_id():
    """A fake AWS Lambda RequestId (the UUID shown in START/END/REPORT lines)."""
    return "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12))


def emit_normal_traffic(t, n=1):
    """Everyday INFO traffic across all three logs, no incident."""
    for _ in range(n):
        aff = random.choice(AFFILIATES)
        ip = random.choice(IPS)
        trace_id = fake_trace_id()
        req_id = fake_request_id()
        bytes_sent = random.randint(200, 4000)
        path = f"/services/slothstay/listings/{aff}?start=0&count=25"

        lambda_lines.append(f"{lambda_ts(t)}\tSTART RequestId: {req_id} Version: $LATEST")
        lambda_lines.append(
            f"{lambda_ts(t)}\t{req_id}\tINFO\tInvoking SlothStay listings handler for affiliate={aff} traceId={trace_id}"
        )
        t_call = t + timedelta(milliseconds=random.randint(50, 400))
        lambda_lines.append(
            f"{lambda_ts(t_call)}\t{req_id}\tINFO\tBackend call to https://{DOMAIN}{path} succeeded (200)"
        )
        t_end = t_call + timedelta(milliseconds=random.randint(10, 60))
        lambda_lines.append(f"{lambda_ts(t_end)}\tEND RequestId: {req_id}")
        lambda_lines.append(
            f"{lambda_ts(t_end)}\tREPORT RequestId: {req_id}\tDuration: {random.randint(60,500)}.00 ms\t"
            f"Billed Duration: {random.randint(100,500)} ms\tMemory Size: 512 MB\tMax Memory Used: {random.randint(90,220)} MB"
        )

        tomcat_lines.append(
            f"{tomcat_ts(t_call)} INFO [http-nio-8080-exec-{random.randint(1,40)}] "
            f"com.slothstay.inventory.NapInventoryProvider.query Search Query: affiliate={aff} "
            f"AND validFrom:[* TO 20260704] AND validTo:[20260704 TO *]"
        )

        apache_lines.append(
            f'{ip} - - [{apache_ts(t)}] "GET {path} HTTP/1.1" 200 {bytes_sent} "-" "GuzzleHttp/7" trace_id={trace_id}'
        )
        t += timedelta(seconds=random.randint(5, 45))
    return t


def emit_incident_1_lambda_timeout(t):
    """Lambda times out waiting on the backend -> Tomcat logs it as slow -> Apache returns 504."""
    aff = random.choice(AFFILIATES)
    ip = random.choice(IPS)
    trace_id = fake_trace_id()
    req_id = fake_request_id()
    path = f"/services/slothstay/listings/{aff}?start=0&count=25"

    lambda_lines.append(f"{lambda_ts(t)}\tSTART RequestId: {req_id} Version: $LATEST")
    lambda_lines.append(
        f"{lambda_ts(t)}\t{req_id}\tINFO\tInvoking SlothStay listings handler for affiliate={aff} traceId={trace_id}"
    )
    t1 = t + timedelta(seconds=1)
    lambda_lines.append(
        f"{lambda_ts(t1)}\t{req_id}\tINFO\tBackend call to https://{DOMAIN}{path} in progress..."
    )
    t2 = t + timedelta(seconds=3)
    lambda_lines.append(
        f"{lambda_ts(t2)}\t{req_id}\tERROR\tNapLambdaTimeoutError: backend did not respond within 3000ms"
    )
    lambda_lines.append(f"{lambda_ts(t2)}\tEND RequestId: {req_id}")
    lambda_lines.append(f"{lambda_ts(t2)}\t{req_id}\tTask timed out after 3.00 seconds")
    lambda_lines.append(
        f"{lambda_ts(t2)}\tREPORT RequestId: {req_id}\tDuration: 3000.87 ms\t"
        f"Billed Duration: 3001 ms\tMemory Size: 512 MB\tMax Memory Used: 214 MB"
    )

    t1b = t + timedelta(seconds=1, milliseconds=200)
    tomcat_lines.append(
        f"{tomcat_ts(t1b)} WARN [http-nio-8080-exec-7] com.slothstay.inventory.NapInventoryProvider.query "
        f"Slow response, still waiting on affiliate={aff} after 2500ms"
    )

    t3 = t + timedelta(seconds=3, milliseconds=100)
    apache_lines.append(
        f'{ip} - - [{apache_ts(t3)}] "GET {path} HTTP/1.1" 504 210 "-" "GuzzleHttp/7" trace_id={trace_id}'
    )
    return t + timedelta(seconds=10)


def emit_incident_2_repeated_burst(t):
    """Same Tomcat error shape repeated many times -> tests shape-based dedup/collapsing."""
    aff = random.choice(AFFILIATES)
    for i in range(12):
        tomcat_lines.append(
            f"{tomcat_ts(t)} SEVERE [http-nio-8080-exec-3] com.slothstay.inventory.BlanketFortCollapseException "
            f"too many blankets in the fort, queue depth={90 + i} affiliate={aff}"
        )
        t += timedelta(seconds=1)
    return t + timedelta(seconds=10)


def emit_incident_3_cross_file(t):
    """PillowFightOverflowException, correlated across Lambda / Tomcat / Apache via shared trace id."""
    aff = random.choice(AFFILIATES)
    ip = random.choice(IPS)
    trace_id = fake_trace_id()
    req_id = fake_request_id()
    path = f"/services/slothstay/listings/{aff}?start=0&count=25"

    lambda_lines.append(f"{lambda_ts(t)}\tSTART RequestId: {req_id} Version: $LATEST")
    lambda_lines.append(
        f"{lambda_ts(t)}\t{req_id}\tINFO\tInvoking SlothStay listings handler for affiliate={aff} traceId={trace_id}"
    )
    t1 = t + timedelta(milliseconds=500)
    lambda_lines.append(
        f"{lambda_ts(t1)}\t{req_id}\tERROR\tPillowFightOverflowException: backend rejected request (too many pillows in flight)"
    )
    lambda_lines.append(f"{lambda_ts(t1)}\tEND RequestId: {req_id}")
    lambda_lines.append(
        f"{lambda_ts(t1)}\tREPORT RequestId: {req_id}\tDuration: 512.44 ms\t"
        f"Billed Duration: 513 ms\tMemory Size: 512 MB\tMax Memory Used: 118 MB"
    )

    t1b = t + timedelta(milliseconds=300)
    tomcat_lines.append(
        f"{tomcat_ts(t1b)} SEVERE [http-nio-8080-exec-15] com.slothstay.inventory.PillowFightQueue.push "
        f"PillowFightOverflowException: too many pillows in flight, dropping request (affiliate={aff})"
    )
    frames = [
        "com.slothstay.inventory.PillowFightQueue.push", "com.slothstay.inventory.PillowFightQueue.enqueue",
        "com.slothstay.inventory.NapInventoryProvider.query", "com.slothstay.web.ListingsController.get",
        "com.slothstay.web.FrontDispatchServlet.service", "org.apache.catalina.core.StandardWrapperValve.invoke",
        "org.apache.catalina.core.StandardEngineValve.invoke", "org.apache.catalina.connector.CoyoteAdapter.service",
        "org.apache.coyote.http11.Http11Processor.service", "org.apache.coyote.AbstractProcessorLight.process",
        "org.apache.coyote.AbstractProtocol$ConnectionHandler.process", "org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun",
    ]
    for i, f in enumerate(frames):
        tomcat_lines.append(f"    at {f}(PillowFightQueue.java:{40 + i})")

    t2 = t + timedelta(seconds=1)
    apache_lines.append(
        f'{ip} - - [{apache_ts(t2)}] "GET {path} HTTP/1.1" 500 340 "-" "GuzzleHttp/7" trace_id={trace_id}'
    )
    return t + timedelta(seconds=10)


# ── Build the timeline: noise -> incident -> noise -> incident -> noise -> incident -> noise ──
t = START
t = emit_normal_traffic(t, n=15)
t = emit_incident_1_lambda_timeout(t)
t = emit_normal_traffic(t, n=20)
t = emit_incident_2_repeated_burst(t)
t = emit_normal_traffic(t, n=20)
t = emit_incident_3_cross_file(t)
t = emit_normal_traffic(t, n=15)

with open(os.path.join(APACHE_DIR, "apache-access.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(apache_lines) + "\n")

with open(os.path.join(LOG_DIR, "tomcat.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(tomcat_lines) + "\n")

with open(os.path.join(LOG_DIR, "lambda.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(lambda_lines) + "\n")

props = """[SETTINGS]
individual_analysis = False
#individual_analysis = True
#if individual_analysis is true the below request_response_log will not be taken into account
request_response_log_folder = sample_data/apache_logs/
log_folder = sample_data/logs/
search_keyword = ERROR|SEVERE|EXCEPTION|WARN|timed out
ignore_keywords = Exception in handleFault

[LLM]
#provider = auto | anthropic | openai | google  (auto picks whichever API key is set in the environment: ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY)
provider = auto
#mock = True runs analyze_incident.py with zero API calls / zero tokens spent, good for testing the pipeline
mock = True
max_tokens = 700
"""
with open(os.path.join(BASE_DIR, "log_anomaly.properties"), "w", encoding="utf-8") as f:
    f.write(props)

print(f"wrote {len(apache_lines)} apache lines, {len(tomcat_lines)} tomcat lines, {len(lambda_lines)} lambda lines")
print(f"apache: {APACHE_DIR}")
print(f"logs:   {LOG_DIR}")
print(f"config: {os.path.join(BASE_DIR, 'log_anomaly.properties')}")
