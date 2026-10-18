"""Read Windows .evtx files into plain dictionaries (lossless, no field derivation).

Each record becomes the JSON produced by the `evtx` parser: ``{"Event": {"System":
{...}, "EventData": {...}}}``. Records are returned in file order with the
channel and file name available for filtering. Files are parsed only; nothing in
them is executed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def records(path: Path) -> Iterator[dict]:
    from evtx import PyEvtxParser  # optional dependency, imported on use

    for record in PyEvtxParser(str(path)).records_json():
        yield json.loads(record["data"])


def channel(document: dict) -> str:
    return str(((document.get("Event") or {}).get("System") or {}).get("Channel") or "")


def sysmon_records(path: Path) -> list[dict]:
    return [document for document in records(path) if channel(document) == SYSMON_CHANNEL]


def convert(path: Path, out: Path, *, sysmon_only: bool = True) -> int:
    """Write one record per line (JSONL); returns the number written."""

    rows = sysmon_records(path) if sysmon_only else list(records(path))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(rows)
