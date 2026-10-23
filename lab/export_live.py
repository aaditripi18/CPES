"""Export one live session's telemetry from Elasticsearch to a private NDJSON file.

Run on the HOST after a session, while Elasticsearch in the VM is still up:

    python lab/export_live.py --start 2026-10-23T15:00:00Z --end 2026-10-23T23:00:00Z

Reads CPES_ES_URL / CPES_ES_USER / CPES_ES_PASSWORD / CPES_ES_INDEX like
lab/check_lab.py. Writes lab-data/<name>/corpus.ndjson (git-ignored: it holds
host and account identifiers) sorted by @timestamp, one raw _source per line,
and prints the document count, the per-channel / per-event-code counts and the
file's SHA-256. Nothing in Elasticsearch is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit("The 'elasticsearch' package is not installed. Activate the CPES venv first.")

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--start", required=True, help="inclusive @timestamp lower bound (ISO 8601, UTC)")
    parser.add_argument("--end", required=True, help="inclusive @timestamp upper bound (ISO 8601, UTC)")
    parser.add_argument("--name", default="vm-live-v1", help="output folder under lab-data/")
    args = parser.parse_args()

    password = os.environ.get("CPES_ES_PASSWORD")
    if not password:
        sys.exit('CPES_ES_PASSWORD is not set. Set it first:  $env:CPES_ES_PASSWORD = Read-Host "Elastic password"')
    client = Elasticsearch(os.environ.get("CPES_ES_URL", "https://127.0.0.1:9200"), basic_auth=(os.environ.get("CPES_ES_USER", "elastic"), password),
                           verify_certs=False, ssl_show_warn=False, request_timeout=120)
    index = os.environ.get("CPES_ES_INDEX", "cpes-live-v1")
    query = {"range": {"@timestamp": {"gte": args.start, "lte": args.end}}}
    expected = client.count(index=index, query=query)["count"]
    print(f"{expected:,} documents in {index} between {args.start} and {args.end}")

    out_dir = ROOT / "lab-data" / args.name
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "corpus.ndjson"
    pit = client.open_point_in_time(index=index, keep_alive="5m")["id"]
    written, after = 0, None
    codes: Counter = Counter()
    digest = hashlib.sha256()
    try:
        with path.open("wb") as handle:
            while True:
                page = client.search(size=5000, query=query, pit={"id": pit, "keep_alive": "5m"},
                                     sort=[{"@timestamp": "asc"}, {"_shard_doc": "asc"}], search_after=after)
                hits = page["hits"]["hits"]
                if not hits:
                    break
                pit, after = page["pit_id"], hits[-1]["sort"]
                for hit in hits:
                    source = hit["_source"]
                    line = (json.dumps(source, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
                    handle.write(line)
                    digest.update(line)
                    codes[(((source.get("winlog") or {}).get("channel")) or "?", str((source.get("event") or {}).get("code")))] += 1
                written += len(hits)
                print(f"\r  {written:,} / {expected:,}", end="", flush=True)
    finally:
        client.close_point_in_time(id=pit)
    print()
    if written != expected:
        print(f"WARNING: wrote {written:,} documents but {expected:,} were counted.")
    for (channel, code), count in sorted(codes.items()):
        print(f"  {channel:<40} {code:>5} {count:>10,}")
    print(f"{path.relative_to(ROOT)}  sha256 {digest.hexdigest()}")
    return 0 if written == expected else 1


if __name__ == "__main__":
    sys.exit(main())
