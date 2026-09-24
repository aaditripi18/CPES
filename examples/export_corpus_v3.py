"""CPES corpus exporter v3 — search_after pagination (no 10k cap).

Elasticsearch refuses a single query over index.max_result_window (default 10,000).
The v2 exporter therefore capped each EID. This v3 exporter uses **search_after
pagination** to export every matching record of each EID within the window, so
EID 13 (registry) comes out complete — required to condition signal 510 on the
UAC-hijack registry write at full coverage.

Deploy: copy to C:\\CPES\\export_corpus_v3.py on the VM, then:
    cd C:\\CPES ; .\\.venv\\Scripts\\Activate.ps1
    $env:CPES_ES_PASSWORD = "<elastic password>"
    python C:\\CPES\\export_corpus_v3.py            # writes corpus-export.ndjson

Env vars: CPES_ES_PASSWORD (req), CPES_ES_URL, CPES_ES_USER, CPES_ES_INDEX,
          CPES_WINDOW_HOURS (default 4).
"""
from __future__ import annotations
import json, os
from pathlib import Path
from elasticsearch import Elasticsearch

EIDS = ["1", "6", "7", "8", "10", "11", "12", "13", "17", "18"]
PAGE = 5000                 # per-page size (<= max_result_window); pagination handles the rest
HARD_LIMIT = 200000         # safety ceiling per EID
OUTFILE = "corpus-export.ndjson"


def main() -> None:
    pw = os.environ.get("CPES_ES_PASSWORD")
    if not pw:
        raise SystemExit('Set CPES_ES_PASSWORD first.')
    url = os.environ.get("CPES_ES_URL", "https://localhost:9200")
    user = os.environ.get("CPES_ES_USER", "elastic")
    index = os.environ.get("CPES_ES_INDEX", "cpes-telemetry-raw-v1")
    hours = int(os.environ.get("CPES_WINDOW_HOURS", "4"))
    es = Elasticsearch(url, basic_auth=(user, pw), verify_certs=False, ssl_show_warn=False)
    print(f"Connected to Elasticsearch {es.info()['version']['number']} at {url}")
    print(f"Window: last {hours}h   index: {index}   (search_after pagination, no per-EID cap)")

    total = 0
    with Path(OUTFILE).open("w", encoding="utf-8") as out:
        for code in EIDS:
            q = {"bool": {"must": [
                {"term": {"event.code": code}},
                {"term": {"winlog.provider_name": "Microsoft-Windows-Sysmon"}},
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            ]}}
            # deterministic total order for search_after: timestamp asc, then a tiebreak
            sort = [{"@timestamp": "asc"}, {"winlog.record_id": "asc"}]
            after = None
            n = 0
            while n < HARD_LIMIT:
                kw = dict(index=index, query=q, size=PAGE, sort=sort)
                if after is not None:
                    kw["search_after"] = after
                hits = es.search(**kw)["hits"]["hits"]
                if not hits:
                    break
                for h in hits:
                    out.write(json.dumps(h["_source"], default=str)); out.write("\n")
                n += len(hits)
                after = hits[-1]["sort"]
                if len(hits) < PAGE:
                    break
            total += n
            note = "  <-- complete (paginated)" if code in ("13", "12", "10", "11", "7") else ""
            print(f"  EID {code:>2}: exported {n:>7}{note}")
    print(f"\nWrote {total} events to {OUTFILE}")


if __name__ == "__main__":
    main()
