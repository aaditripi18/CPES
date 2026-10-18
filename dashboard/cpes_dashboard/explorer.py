"""Read-only views over a parsed dataset: schema, columns, facets, filtered pages."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from typing import Any

from .ingest import ParsedDataset, flatten, type_name

# Shown first when present; the rest of the schema is selectable in the UI.
PREFERRED_COLUMNS = (
    "@timestamp",
    "event.code",
    "host.name",
    "winlog.computer_name",
    "user.name",
    "process.executable",
    "process.entity_id",
    "process.parent.entity_id",
    "winlog.event_data.IntegrityLevel",
    "process.command_line",
    "registry.path",
    "file.name",
    "winlog.record_id",
    # raw .evtx records
    "Event.System.TimeCreated.#attributes.SystemTime",
    "Event.System.EventID",
    "Event.System.Computer",
    "Event.EventData.Image",
    "Event.EventData.IntegrityLevel",
    "Event.EventData.User",
    "Event.EventData.CommandLine",
    "Event.EventData.TargetObject",
    "Event.EventData.PipeName",
)
FACET_CANDIDATES = (
    "event.code",
    "host.name",
    "winlog.computer_name",
    "user.name",
    "winlog.event_data.IntegrityLevel",
    "process.name",
    "process.executable",
    "winlog.channel",
    "Event.System.Channel",
    "Event.System.EventID",
    "Event.System.Computer",
    "Event.EventData.User",
    "Event.EventData.IntegrityLevel",
)
TIMESTAMP_FIELDS = ("@timestamp", "timestamp", "source_timestamp", "time", "Event.System.TimeCreated.#attributes.SystemTime")
MAX_CELL = 400


def _cell(value: Any) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= MAX_CELL else text[:MAX_CELL] + "…"


class DatasetIndex:
    def __init__(self, parsed: ParsedDataset) -> None:
        self.parsed = parsed
        self._columns: dict[str, list[str | None]] = {}
        self._schema: list[dict[str, Any]] | None = None
        self._timestamps: list[float | None] | None = None
        self._timestamp_field: str | None = None

    # -- schema -----------------------------------------------------------------
    def schema(self) -> list[dict[str, Any]]:
        if self._schema is not None:
            return self._schema
        counts: Counter = Counter()
        types: dict[str, Counter] = {}
        examples: dict[str, list[str]] = {}
        # Materialise the likely table/facet columns in the same pass (one parse of the file).
        prefill = [path for path in dict.fromkeys(PREFERRED_COLUMNS + FACET_CANDIDATES + TIMESTAMP_FIELDS) if path not in self._columns]
        prefilled: dict[str, list[str | None]] = {path: [] for path in prefill}
        for _, document in self.parsed.documents():
            flat = flatten(document)
            for path in prefill:
                prefilled[path].append(_cell(flat.get(path)))
            for path, value in flat.items():
                counts[path] += 1
                types.setdefault(path, Counter())[type_name(value)] += 1
                bucket = examples.setdefault(path, [])
                if len(bucket) < 3:
                    text = _cell(value)
                    if text is not None and text not in bucket:
                        bucket.append(text[:80])
        self._columns.update(prefilled)
        total = len(self.parsed) or 1
        self._schema = [
            {
                "path": path,
                "present": count,
                "missing": len(self.parsed) - count,
                "coverage": count / total,
                "types": dict(types[path].most_common()),
                "examples": examples.get(path, []),
            }
            for path, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ]
        return self._schema

    def default_columns(self) -> list[str]:
        present = {entry["path"] for entry in self.schema()}
        chosen = [column for column in PREFERRED_COLUMNS if column in present]
        if len(chosen) < 6:
            for entry in self.schema():
                if entry["path"] not in chosen:
                    chosen.append(entry["path"])
                if len(chosen) >= 8:
                    break
        return chosen

    def facet_fields(self) -> list[str]:
        present = {entry["path"]: entry for entry in self.schema()}
        fields = [name for name in FACET_CANDIDATES if name in present]
        if self.parsed.format == "csv":
            for entry in self.schema():
                if entry["path"] not in fields and len(fields) < 6 and entry["coverage"] > 0.5:
                    distinct = len(set(self.column(entry["path"])))
                    if 1 < distinct <= 50:
                        fields.append(entry["path"])
        return fields

    # -- columns ------------------------------------------------------------------
    def column(self, path: str) -> list[str | None]:
        self.ensure_columns([path])
        return self._columns[path]

    def ensure_columns(self, paths: list[str]) -> None:
        """Materialise several columns in one pass over the records."""

        missing = [path for path in dict.fromkeys(paths) if path not in self._columns]
        if not missing:
            return
        values: dict[str, list[str | None]] = {path: [] for path in missing}
        for _, document in self.parsed.documents():
            flat = flatten(document)
            for path in missing:
                values[path].append(_cell(flat.get(path)))
        self._columns.update(values)

    def timestamp_field(self) -> str | None:
        if self._timestamp_field is None:
            present = {entry["path"] for entry in self.schema()}
            self._timestamp_field = next((name for name in TIMESTAMP_FIELDS if name in present), "")
        return self._timestamp_field or None

    def timestamps(self) -> list[float | None]:
        if self._timestamps is None:
            field = self.timestamp_field()
            parsed: list[float | None] = []
            for value in (self.column(field) if field else [None] * len(self.parsed)):
                try:
                    stamp = datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
                    parsed.append(stamp.timestamp() if stamp and stamp.tzinfo else None)
                except ValueError:
                    parsed.append(None)
            self._timestamps = parsed
        return self._timestamps

    def facets(self, fields: list[str], selection: list[int] | None = None, limit: int = 40) -> dict[str, Any]:
        out = {}
        self.ensure_columns(fields)
        for name in fields:
            column = self.column(name)
            values = column if selection is None else [column[i] for i in selection]
            counter = Counter(value if value is not None else "∅ missing" for value in values)
            out[name] = {"distinct": len(counter), "values": counter.most_common(limit)}
        return out

    # -- query -------------------------------------------------------------------
    def select(
        self,
        *,
        q: str | None = None,
        filters: dict[str, list[str]] | None = None,
        missing: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        indices: list[int] | None = None,
    ) -> list[int]:
        selection = list(range(len(self.parsed))) if indices is None else [i for i in indices if 0 <= i < len(self.parsed)]
        for name, wanted in (filters or {}).items():
            column = self.column(name)
            accept = set(wanted)
            want_missing = "∅ missing" in accept
            selection = [i for i in selection if (column[i] in accept) or (want_missing and column[i] is None)]
        if missing:
            column = self.column(missing)
            selection = [i for i in selection if column[i] is None]
        if time_from or time_to:
            stamps = self.timestamps()
            low = _epoch(time_from)
            high = _epoch(time_to)
            selection = [
                i for i in selection
                if stamps[i] is not None and (low is None or stamps[i] >= low) and (high is None or stamps[i] <= high)
            ]
        if q:
            pattern = re.compile(re.escape(q), re.IGNORECASE)
            originals = self.parsed.originals
            selection = [i for i in selection if pattern.search(originals[i])]
        return selection

    def page(
        self,
        selection: list[int],
        *,
        columns: list[str],
        sort: str | None,
        order: str,
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        if sort == "__position__" or not sort:
            ordered = selection if order != "desc" else list(reversed(selection))
        elif sort == "__time__":
            stamps = self.timestamps()
            ordered = sorted(selection, key=lambda i: (stamps[i] is None, stamps[i] or 0.0, i), reverse=order == "desc")
        else:
            column = self.column(sort)
            ordered = sorted(selection, key=lambda i: (column[i] is None, _sort_key(column[i]), i), reverse=order == "desc")
        window = ordered[offset: offset + limit]
        self.ensure_columns(columns)
        data = {name: self.column(name) for name in columns}
        rows = [
            {"index": i, "location": self.parsed.locations[i], "cells": {name: data[name][i] for name in columns}}
            for i in window
        ]
        return {"total": len(selection), "offset": offset, "limit": limit, "columns": columns, "rows": rows}


def _sort_key(value: str | None) -> tuple:
    if value is None:
        return (1, 0.0, "")
    try:
        return (0, float(value), "")
    except ValueError:
        return (0, 0.0, value.lower())


def _epoch(value: str | None) -> float | None:
    if not value:
        return None
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("time filter must include an offset (e.g. Z).")
    return stamp.timestamp()
