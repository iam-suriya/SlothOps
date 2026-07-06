"""
generate_synthetic_logs_v2.py — an EXTENDED, 5-incident version of
sample_data/generate_synthetic_logs.py, kept in its own folder
(extended_incidents_v2/) so it never touches the logs/apache_logs used by
the current Kaggle submission or the committed repo.

Everything here is still fully synthetic (fictional "SlothStay Vacation
Exchange" company, .example domain, RFC 5737 IPs) -- this file only adds
2 more incident scenarios on top of the original 3:

  1. Lambda cold-path timeout      -> Tomcat WARN slow response -> Apache 504
  2. Repeated Tomcat error burst (tests shape-based dedup/collapsing)
  3. Cross-file exception          -> Lambda ERROR -> Tomcat SEVERE + stack trace -> Apache 500
  4. Connection pool exhaustion    -> Tomcat WARN then SEVERE -> Lambda ERROR -> Apache 503
  5. Thread deadlock (2 threads)   -> Tomcat SEVERE + two interleaved stack traces -> Apache 500

Run:  python generate_synthetic_logs_v2.py
Writes into: extended_incidents_v2/apache_logs/, extended_incidents_v2/logs/,
             extended_incidents_v2/log_anomaly_v2.properties
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

apache_lines = []
tomcat_lines = []
lambda_lines = []


def apache_ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def tomcat_ts(t):
    ms = f"{random.randint(0, 999):03d}"
    return t.strftime("%d-%b-%Y %H:%M:%S") + f".{ms}"


def lambda_ts(t):
    ms = f"{random.randint(0, 999):03d}"
    return t.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms}Z"


def fake_trace_id():
    return "Root=1-" + "".join(random.choices("0123456789abcdef", k=8)) + "-" + \
           "".join(random.choices("0123456789abcdef", k=24))


def fake_request_id():
    return "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12))


def emit_normal_traffic(t, n=1):
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
    aff = random.choice(AFFILIATES)
    for i in range(12):
        tomcat_lines.append(
            f"{tomcat_ts(t)} SEVERE [http-nio-8080-exec-3] com.slothstay.inventory.BlanketFortCollapseException "
            f"too many blankets in the fort, queue depth={90 + i} affiliate={aff}"
        )
        t += timedelta(seconds=1)
    return t + timedelta(seconds=10)


def emit_incident_3_cross_file(t):
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


def emit_incident_4_pool_exhaustion(t):
    """Every connection in the pool is busy because every sloth checked out a
    blanket and never checked it back in -> Tomcat WARN as the pool gets tight,
    then SEVERE when it's fully exhausted -> Lambda gives up -> Apache 503."""
    aff = random.choice(AFFILIATES)
    ip = random.choice(IPS)
    trace_id = fake_trace_id()
    req_id = fake_request_id()
    path = f"/services/slothstay/listings/{aff}?start=0&count=25"

    t0 = t
    tomcat_lines.append(
        f"{tomcat_ts(t0)} WARN [http-nio-8080-exec-22] com.slothstay.db.BlanketConnectionPool.borrow "
        f"Pool running low: 18/20 connections checked out, none returned in over 60s (affiliate={aff})"
    )

    lambda_lines.append(f"{lambda_ts(t)}\tSTART RequestId: {req_id} Version: $LATEST")
    lambda_lines.append(
        f"{lambda_ts(t)}\t{req_id}\tINFO\tInvoking SlothStay listings handler for affiliate={aff} traceId={trace_id}"
    )
    t1 = t + timedelta(seconds=2)
    tomcat_lines.append(
        f"{tomcat_ts(t1)} SEVERE [http-nio-8080-exec-22] com.slothstay.db.BlanketConnectionPool.borrow "
        f"NapConnectionPoolExhaustedException: no connections available, 20/20 checked out and unreturned (affiliate={aff})"
    )
    t2 = t + timedelta(seconds=2, milliseconds=400)
    lambda_lines.append(
        f"{lambda_ts(t2)}\t{req_id}\tERROR\tNapConnectionPoolExhaustedException: backend refused connection (pool exhausted)"
    )
    lambda_lines.append(f"{lambda_ts(t2)}\tEND RequestId: {req_id}")
    lambda_lines.append(
        f"{lambda_ts(t2)}\tREPORT RequestId: {req_id}\tDuration: 2411.02 ms\t"
        f"Billed Duration: 2412 ms\tMemory Size: 512 MB\tMax Memory Used: 132 MB"
    )

    t3 = t + timedelta(seconds=2, milliseconds=600)
    apache_lines.append(
        f'{ip} - - [{apache_ts(t3)}] "GET {path} HTTP/1.1" 503 190 "-" "GuzzleHttp/7" trace_id={trace_id}'
    )
    return t + timedelta(seconds=10)


def emit_incident_5_deadlock(t):
    """Two threads each hold one sloth's blanket and are waiting for the
    other's -> classic deadlock, logged as one SEVERE entry with two
    interleaved stack traces -> Apache 500 once the request watchdog gives up."""
    aff = random.choice(AFFILIATES)
    ip = random.choice(IPS)
    trace_id = fake_trace_id()
    req_id = fake_request_id()
    path = f"/services/slothstay/listings/{aff}?start=0&count=25"

    lambda_lines.append(f"{lambda_ts(t)}\tSTART RequestId: {req_id} Version: $LATEST")
    lambda_lines.append(
        f"{lambda_ts(t)}\t{req_id}\tINFO\tInvoking SlothStay listings handler for affiliate={aff} traceId={trace_id}"
    )

    t1 = t + timedelta(milliseconds=800)
    tomcat_lines.append(
        f"{tomcat_ts(t1)} SEVERE [http-nio-8080-exec-9] com.slothstay.inventory.BlanketSwapDeadlockException "
        f"deadlock detected between exec-9 and exec-14 over shared blanket locks (affiliate={aff})"
    )
    frames_a = [
        "com.slothstay.inventory.BlanketLock.acquire",
        "com.slothstay.inventory.NapInventoryProvider.reserveBlanket",
        "com.slothstay.web.ListingsController.get",
        "org.apache.catalina.core.StandardWrapperValve.invoke",
    ]
    for i, f in enumerate(frames_a):
        tomcat_lines.append(f"    at {f}(BlanketLock.java:{20 + i}) [Thread: http-nio-8080-exec-9, waiting on lock held by exec-14]")
    frames_b = [
        "com.slothstay.inventory.BlanketLock.acquire",
        "com.slothstay.inventory.NapInventoryProvider.reserveBlanket",
        "com.slothstay.web.ListingsController.get",
        "org.apache.catalina.core.StandardWrapperValve.invoke",
    ]
    for i, f in enumerate(frames_b):
        tomcat_lines.append(f"    at {f}(BlanketLock.java:{20 + i}) [Thread: http-nio-8080-exec-14, waiting on lock held by exec-9]")

    t2 = t + timedelta(seconds=5)
    lambda_lines.append(
        f"{lambda_ts(t2)}\t{req_id}\tERROR\tNapRequestWatchdogError: request abandoned after 5000ms, backend deadlocked"
    )
    lambda_lines.append(f"{lambda_ts(t2)}\tEND RequestId: {req_id}")
    lambda_lines.append(
        f"{lambda_ts(t2)}\tREPORT RequestId: {req_id}\tDuration: 5002.19 ms\t"
        f"Billed Duration: 5003 ms\tMemory Size: 512 MB\tMax Memory Used: 145 MB"
    )

    t3 = t + timedelta(seconds=5, milliseconds=200)
    apache_lines.append(
        f'{ip} - - [{apache_ts(t3)}] "GET {path} HTTP/1.1" 500 310 "-" "GuzzleHttp/7" trace_id={trace_id}'
    )
    return t + timedelta(seconds=10)


# ── Build the timeline: noise -> incident -> noise -> incident -> ... -> noise ──
t = START
t = emit_normal_traffic(t, n=15)
t = emit_incident_1_lambda_timeout(t)
t = emit_normal_traffic(t, n=20)
t = emit_incident_2_repeated_burst(t)
t = emit_normal_traffic(t, n=20)
t = emit_incident_3_cross_file(t)
t = emit_normal_traffic(t, n=15)
t = emit_incident_4_pool_exhaustion(t)
t = emit_normal_traffic(t, n=15)
t = emit_incident_5_deadlock(t)
t = emit_normal_traffic(t, n=15)

with open(os.path.join(APACHE_DIR, "apache-access.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(apache_lines) + "\n")

with open(os.path.join(LOG_DIR, "tomcat.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(tomcat_lines) + "\n")

with open(os.path.join(LOG_DIR, "lambda.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(lambda_lines) + "\n")

props = f"""[SETTINGS]
individual_analysis = False
request_response_log_folder = {APACHE_DIR}/
log_folder = {LOG_DIR}/
search_keyword = ERROR|SEVERE|EXCEPTION|WARN|timed out
ignore_keywords = Exception in handleFault

[LLM]
provider = auto
mock = True
max_tokens = 700
"""
with open(os.path.join(BASE_DIR, "log_anomaly_v2.properties"), "w", encoding="utf-8") as f:
    f.write(props)

print(f"wrote {len(apache_lines)} apache lines, {len(tomcat_lines)} tomcat lines, {len(lambda_lines)} lambda lines")
print(f"apache: {APACHE_DIR}")
print(f"logs:   {LOG_DIR}")
print(f"config: {os.path.join(BASE_DIR, 'log_anomaly_v2.properties')}")
