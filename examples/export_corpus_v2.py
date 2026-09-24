"""CPES corpus exporter v2 — recent-first, named-pipe aware.

Improvements over the v1 exporter:
  * Adds EID 17/18 (named-pipe create/connect) — the independent token-theft channel.
  * Sorts each event type RECENT-FIRST (@timestamp desc) so the just-run attack
    activity survives the per-EID cap (the v1 exporter sorted oldest-first, which
    truncated recent registry/pipe writes out of the export).
  * Window-bounded (default: last 3 hours) to keep the config-v2 pipe volume sane.

Deploy: copy to C:\\CPES\\export_corpus_v2.py on the VM, then:
    cd C:\\CPES ; .\\.venv\\Scripts\\Activate.ps1
    $env:CPES_ES_PASSWORD = "<elastic password>"
    python C:\\CPES\\export_corpus_v2.py            # writes corpus-export.ndjson

Environment variables (same convention as examples/run_live.py):
    CPES_ES_PASSWORD  (required)   elastic user password
    CPES_ES_URL       default https://localhost:9200
    CPES_ES_USER      default elastic
    CPES_ES_INDEX     default cpes-telemetry-raw-v1
    CPES_WINDOW_HOURS default 3    lookback window
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from elasticsearch import Elasticsearch

# Per-EID caps. Recent-first sort means these keep the MOST RECENT N of each type,
# i.e. the attack-window activity. Pipes (17/18) and registry (13) are the noisy
# ones, so they get the largest budgets.
CAPS = {
    "1": 10000,   # ProcessCreate
    "6": 500,     # DriverLoad
    "7": 4000,    # ImageLoad
    "8": 3000,    # CreateRemoteThread
    "10": 6000,   # ProcessAccess
    "11": 6000,   # FileCreate
    "12": 6000,   # RegistryEvent (create/delete key)
    "13": 10000,  # RegistryEvent (set/delete value) — was truncated in v1
    # NB: Elasticsearch default index.max_result_window is 10000, so no single
    # per-EID cap may exceed it (a bounded window keeps recent-first attack activity).
    "17": 8000,   # PipeCreated  (NEW — token-theft evidence)
    "18": 8000,   # PipeConnected (NEW)
}

OUTFILE = "corpus-export.ndjson"


def main() -> None:
    password = os.environ.get("CPES_ES_PASSWORD")
    if not password:
        raise SystemExit(
            'Set CPES_ES_PASSWORD first, e.g.  $env:CPES_ES_PASSWORD = "<elastic password>"'
        )
    url = os.environ.get("CPES_ES_URL", "https://localhost:9200")
    user = os.environ.get("CPES_ES_USER", "elastic")
    index = os.environ.get("CPES_ES_INDEX", "cpes-telemetry-raw-v1")
    window_hours = int(os.environ.get("CPES_WINDOW_HOURS", "3"))

    client = Elasticsearch(
        url, basic_auth=(user, password), verify_certs=False, ssl_show_warn=False
    )
    version = client.info()["version"]["number"]
    print(f"Connected to Elasticsearch {version} at {url}")
    print(f"Window: last {window_hours}h   index: {index}")

    time_filter = {"range": {"@timestamp": {"gte": f"now-{window_hours}h"}}}

    total = 0
    with Path(OUTFILE).open("w", encoding="utf-8") as out:
        for code, cap in CAPS.items():
            query = {
                "bool": {
                    "must": [
                        {"term": {"event.code": code}},
                        {"term": {"winlog.provider_name": "Microsoft-Windows-Sysmon"}},
                        time_filter,
                    ]
                }
            }
            # RECENT-FIRST: keep the newest `cap` events of this type.
            resp = client.search(
                index=index,
                query=query,
                size=cap,
                sort=[{"@timestamp": "desc"}],
            )
            hits = resp["hits"]["hits"]
            for hit in hits:
                out.write(json.dumps(hit["_source"], default=str))
                out.write("\n")
            total += len(hits)
            note = "  <-- NEW in v2" if code in ("17", "18") else ""
            print(f"  EID {code:>2}: exported {len(hits):6d}  (cap {cap}){note}")

    print(f"\nWrote {total} events to {OUTFILE}")
    print("Next: Compress-Archive corpus-export.ndjson + cpes-atomic-log.csv and copy to the share.")


if __name__ == "__main__":
    main()
