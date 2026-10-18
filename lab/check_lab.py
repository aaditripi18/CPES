"""Lab health check: can CPES see live telemetry?

Run this on the HOST (where CPES lives) once the Windows VM is up. It connects to
Elasticsearch on the VM and reports, in plain language, whether each link in the
chain is working:

    Elasticsearch reachable  ->  index exists  ->  Sysmon events present
    ->  recent events flowing  ->  the event types CPES needs are there

Nothing here changes anything. It only reads and reports.

Configuration comes from environment variables (no password is stored in code):

    CPES_ES_URL        default https://127.0.0.1:9200   (set to the VM's host-only IP)
    CPES_ES_USER       default elastic
    CPES_ES_PASSWORD   required
    CPES_ES_INDEX      default cpes-live-*               (index or pattern to inspect)

Example (PowerShell, on the host):

    $env:CPES_ES_URL = "https://192.168.56.10:9200"
    $env:CPES_ES_PASSWORD = "<the elastic password>"
    python lab/check_lab.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit("The 'elasticsearch' package is not installed. Activate the CPES venv first:\n"
             "    .\\.venv\\Scripts\\Activate.ps1")

# Sysmon event IDs CPES uses, with friendly names.
WANTED = {
    "1": "ProcessCreate (lineage)",
    "8": "CreateRemoteThread (injection evidence)",
    "12": "RegistryObject",
    "13": "RegistryValueSet (UAC-hijack evidence)",
    "17": "PipeCreated (token evidence)",
    "18": "PipeConnected (token evidence)",
}

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[0m"
if os.name == "nt":
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        GREEN = RED = YELLOW = DIM = RESET = ""


def ok(message: str) -> None:
    print(f"  {GREEN}[ OK ]{RESET} {message}")


def warn(message: str) -> None:
    print(f"  {YELLOW}[WARN]{RESET} {message}")


def fail(message: str, hint: str = "") -> None:
    print(f"  {RED}[FAIL]{RESET} {message}")
    if hint:
        print(f"         {DIM}{hint}{RESET}")


def main() -> int:
    url = os.environ.get("CPES_ES_URL", "https://127.0.0.1:9200")
    user = os.environ.get("CPES_ES_USER", "elastic")
    password = os.environ.get("CPES_ES_PASSWORD")
    index = os.environ.get("CPES_ES_INDEX", "cpes-live-*")

    print(f"\n{DIM}CPES lab health check{RESET}")
    print(f"  target : {url}  index: {index}  user: {user}\n")

    if not password:
        fail("CPES_ES_PASSWORD is not set.",
             'Set it first, e.g.  $env:CPES_ES_PASSWORD = "<elastic password>"')
        return 2

    # 1. Reach Elasticsearch (self-signed cert in the lab -> no cert verification).
    client = Elasticsearch(url, basic_auth=(user, password), verify_certs=False, ssl_show_warn=False, request_timeout=10)
    try:
        info = client.info()
    except Exception as error:  # connection, auth, TLS, etc.
        fail(f"could not reach Elasticsearch: {type(error).__name__}: {error}",
             "Is the VM up, Elasticsearch started, and the host-only IP/port right? "
             "From the host try:  Test-NetConnection <vm-ip> -Port 9200")
        return 1
    ok(f"Elasticsearch reachable (version {info['version']['number']})")

    # 2. Index / pattern exists and has documents.
    try:
        total = client.count(index=index)["count"]
    except Exception as error:
        fail(f"index '{index}' not found or not readable: {error}",
             "Check CPES_ES_INDEX. List what exists with:  python lab/check_lab.py --list")
        return 1
    if total == 0:
        warn(f"index '{index}' exists but is empty (0 documents).")
        print(f"         {DIM}Winlogbeat may not be shipping yet. Generate a bit of activity on the VM, wait ~30s, rerun.{RESET}")
        return 1
    ok(f"index '{index}' has {total:,} document(s)")

    # 3. Freshness: how old is the newest event?
    newest = client.search(index=index, size=1, sort=[{"@timestamp": "desc"}], query={"exists": {"field": "@timestamp"}})
    hits = newest["hits"]["hits"]
    if hits:
        stamp = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
        if age < 120:
            ok(f"newest event is {age:.0f}s old — telemetry is flowing live")
        elif age < 3600:
            warn(f"newest event is {age / 60:.0f} min old — no very recent activity (fine if the VM is idle)")
        else:
            warn(f"newest event is {age / 3600:.1f} h old — Winlogbeat may have stopped shipping")

    # 4. Which Sysmon event types are present (last 24h).
    try:
        agg = client.search(index=index, size=0, query={"range": {"@timestamp": {"gte": "now-24h"}}},
                            aggregations={"codes": {"terms": {"field": "event.code", "size": 30}}})
        buckets = {str(b["key"]): b["doc_count"] for b in agg["aggregations"]["codes"]["buckets"]}
    except Exception:
        buckets = {}
    print(f"\n  {DIM}Sysmon event types CPES uses (last 24h):{RESET}")
    present = 0
    for code, name in WANTED.items():
        count = buckets.get(code, 0)
        if count:
            present += 1
            print(f"    {GREEN}EID {code:<2}{RESET} {name:<38} {count:>8,}")
        else:
            print(f"    {DIM}EID {code:<2} {name:<38}        0{RESET}")
    print()
    if present == 0:
        fail("no Sysmon events of the types CPES uses were found.",
             "Is Sysmon installed and is Winlogbeat shipping the Sysmon channel? See lab/README.md Phase 0.")
        return 1
    if "1" not in buckets:
        warn("no ProcessCreate (EID 1) events — lineage needs these. Generate activity on the VM and rerun.")

    ok("Lab is ready for live CPES. Next: lab/README.md Phase 1 (live scoring).")
    return 0


def list_indices() -> int:
    url = os.environ.get("CPES_ES_URL", "https://127.0.0.1:9200")
    password = os.environ.get("CPES_ES_PASSWORD", "")
    client = Elasticsearch(url, basic_auth=(os.environ.get("CPES_ES_USER", "elastic"), password),
                          verify_certs=False, ssl_show_warn=False, request_timeout=10)
    try:
        rows = client.cat.indices(format="json", h="index,docs.count,store.size")
    except Exception as error:
        print(f"Could not list indices: {error}")
        return 1
    print("\nIndices on this cluster:")
    for row in sorted(rows, key=lambda r: r.get("index", "")):
        if not row.get("index", "").startswith("."):
            print(f"  {row['index']:<40} {row.get('docs.count', '?'):>12} docs   {row.get('store.size', '?')}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(list_indices() if "--list" in sys.argv else main())
