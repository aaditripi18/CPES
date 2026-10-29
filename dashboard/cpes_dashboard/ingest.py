"""Parse uploaded telemetry and validate it against a C5 mapping, record by record.

The ``cpes`` mapper and translator fail on the first bad document; for a
dataset report we need every failure. So each record is passed, on its own,
through the *same* public ``CanonicalEventMapper.map_document`` and
``CanonicalEventTranslator.translate`` calls that a run uses. A record is
accepted only if both succeed. Nothing is repaired, coerced or guessed.

Format rules (shown to the user in the UI):

* JSONL / NDJSON: one JSON object per line. Blank lines are skipped and counted.
* JSON: an array of objects, an object with a ``records`` array, an
  Elasticsearch response (``hits.hits[]._source``), or a single object.
* CSV: header row required. A dotted column name (``process.entity_id``) is
  read as a nested path. An **empty cell means the field is absent** — CSV
  cannot tell "empty string" from "missing". Values stay strings.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.adapters.models import CanonicalEvent, FieldMapping, MappingConfiguration
from cpes.lineage.builder import LineageBuilder
from cpes.orchestration.translation import CanonicalEventTranslator

from .paths import CONFIGS

FORMATS = ("jsonl", "json", "csv", "evtx")
MAX_UPLOAD_BYTES = 256 * 1024 * 1024
CANONICAL_FIELDS = tuple(CanonicalEvent.__dataclass_fields__)
REQUIRED_FIELDS = ("source_timestamp", "source_event_id")
# Injected only into a *copy* of a document, and only when the user opts in to
# position-derived event ids. Never written back to the stored record.
POSITION_KEY = "__cpes_record_position__"
UNMAPPED_SOURCE = "__cpes_unmapped__"
# Integrity levels the single-event baseline and resolver can rank.
KNOWN_INTEGRITY_LEVELS = ("Untrusted", "Low", "Medium", "High", "System")

MAPPING_PRESETS = {
    "elastic-sysmon-field-mapping-v1": CONFIGS / "elastic-sysmon-field-mapping-v1.yaml",
    "evtx-sysmon-field-mapping-v1": CONFIGS / "evtx-sysmon-field-mapping-v1.yaml",
    # v2 = v1 plus the optional parent image, used by the v3 resolver modes.
    "elastic-sysmon-field-mapping-v2": CONFIGS / "elastic-sysmon-field-mapping-v2.yaml",
    "evtx-sysmon-field-mapping-v2": CONFIGS / "evtx-sysmon-field-mapping-v2.yaml",
}
# The mapping a freshly uploaded file of each format is validated with first.
DEFAULT_PRESET_BY_FORMAT = {"evtx": "evtx-sysmon-field-mapping-v1"}


def detect_format(filename: str) -> str | None:
    suffix = Path(filename).suffix.lower()
    return {".jsonl": "jsonl", ".ndjson": "jsonl", ".json": "json", ".csv": "csv", ".evtx": "evtx"}.get(suffix)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class ParsedDataset:
    """Records as their original text, plus every parse failure."""

    format: str
    originals: list[str] = field(default_factory=list)  # JSON text of the record as read
    locations: list[int] = field(default_factory=list)  # 1-based line (JSONL/CSV) or array index
    parse_errors: list[dict[str, Any]] = field(default_factory=list)
    blank_lines: int = 0
    csv_columns: list[str] | None = None
    structure_errors: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.originals)

    def original(self, index: int) -> dict[str, Any]:
        return json.loads(self.originals[index])

    def document(self, index: int) -> dict[str, Any]:
        """The record in the nested shape the mapper reads."""

        record = self.original(index)
        return unflatten_csv_row(record) if self.format == "csv" else record

    def documents(self) -> Iterator[tuple[int, dict[str, Any]]]:
        for index in range(len(self.originals)):
            yield index, self.document(index)


def parse_file(path: Path, fmt: str) -> ParsedDataset:
    if fmt not in FORMATS:
        raise ValueError(f"unsupported format '{fmt}'; supported: {', '.join(FORMATS)}.")
    parsed = ParsedDataset(format=fmt)
    if fmt == "jsonl":
        _parse_jsonl(path, parsed)
    elif fmt == "json":
        _parse_json(path, parsed)
    elif fmt == "evtx":
        _parse_evtx(path, parsed)
    else:
        _parse_csv(path, parsed)
    return parsed


def _parse_evtx(path: Path, parsed: ParsedDataset) -> None:
    """Windows event log export: every record kept (all channels), parsed, never executed."""

    try:
        from evaluation.evtx_source import records
    except ImportError as error:  # the optional `evtx` parser is not installed
        parsed.structure_errors.append(f"EVTX support needs the 'evtx' package ({error}). pip install -r dashboard/requirements.txt")
        return
    try:
        for number, document in enumerate(records(path), start=1):
            parsed.originals.append(json.dumps(document, ensure_ascii=False))
            parsed.locations.append(number)
    except Exception as error:  # corrupt or non-EVTX file
        parsed.structure_errors.append(f"not a readable .evtx file: {error}")


def _excerpt(text: str, limit: int = 160) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _parse_jsonl(path: Path, parsed: ParsedDataset) -> None:
    with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
        try:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    parsed.blank_lines += 1
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    parsed.parse_errors.append(
                        {"location": line_number, "error": f"invalid JSON: {error.msg} (col {error.colno})", "excerpt": _excerpt(line)}
                    )
                    continue
                if not isinstance(value, dict):
                    parsed.parse_errors.append(
                        {"location": line_number, "error": f"expected a JSON object, got {type(value).__name__}", "excerpt": _excerpt(line)}
                    )
                    continue
                parsed.originals.append(json.dumps(value, ensure_ascii=False))
                parsed.locations.append(line_number)
        except UnicodeDecodeError as error:
            parsed.structure_errors.append(f"file is not valid UTF-8 ({error.reason} at byte {error.start}).")


def _parse_json(path: Path, parsed: ParsedDataset) -> None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except UnicodeDecodeError as error:
        parsed.structure_errors.append(f"file is not valid UTF-8 ({error.reason}).")
        return
    except json.JSONDecodeError as error:
        parsed.structure_errors.append(f"invalid JSON: {error.msg} at line {error.lineno} col {error.colno}.")
        return
    if isinstance(value, dict) and isinstance(value.get("records"), list):
        items = value["records"]
    elif isinstance(value, dict) and isinstance(value.get("hits"), dict) and isinstance(value["hits"].get("hits"), list):
        items = []
        for hit in value["hits"]["hits"]:
            items.append(hit.get("_source") if isinstance(hit, dict) else hit)
    elif isinstance(value, list):
        items = value
    elif isinstance(value, dict):
        items = [value]
    else:
        parsed.structure_errors.append(f"top-level JSON must be an array or object, got {type(value).__name__}.")
        return
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            parsed.parse_errors.append(
                {"location": index, "error": f"expected a JSON object, got {type(item).__name__}", "excerpt": _excerpt(json.dumps(item))}
            )
            continue
        parsed.originals.append(json.dumps(item, ensure_ascii=False))
        parsed.locations.append(index)


def _parse_csv(path: Path, parsed: ParsedDataset) -> None:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as error:
        parsed.structure_errors.append(f"file is not valid UTF-8 ({error.reason}).")
        return
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader)
    except StopIteration:
        parsed.structure_errors.append("CSV file is empty (no header row).")
        return
    header = [column.strip() for column in header]
    parsed.csv_columns = header
    if any(not column for column in header):
        parsed.structure_errors.append("CSV header contains an empty column name.")
    duplicates = sorted(name for name, count in Counter(header).items() if count > 1)
    if duplicates:
        parsed.structure_errors.append(f"CSV header repeats column(s): {', '.join(duplicates)}.")
    conflicts = sorted(
        {a for a in header for b in header if a != b and b.startswith(a + ".")}
    )
    if conflicts:
        parsed.structure_errors.append(
            "CSV column(s) are both a value and a parent path: " + ", ".join(conflicts) + "."
        )
    if parsed.structure_errors:
        return
    for row in reader:
        line_number = reader.line_num
        if not any(cell.strip() for cell in row):
            parsed.blank_lines += 1
            continue
        if len(row) != len(header):
            parsed.parse_errors.append(
                {"location": line_number, "error": f"row has {len(row)} cells, header has {len(header)}", "excerpt": _excerpt(",".join(row))}
            )
            continue
        parsed.originals.append(json.dumps(dict(zip(header, row)), ensure_ascii=False))
        parsed.locations.append(line_number)


def unflatten_csv_row(row: dict[str, str]) -> dict[str, Any]:
    """Turn ``{"process.pid": "9"}`` into ``{"process": {"pid": "9"}}``; drop empty cells."""

    document: dict[str, Any] = {}
    for column, value in row.items():
        if value == "":
            continue
        target = document
        segments = column.split(".")
        for segment in segments[:-1]:
            target = target.setdefault(segment, {})
        target[segments[-1]] = value
    return document


# --------------------------------------------------------------------------- mapping


def preset_configuration(name: str) -> MappingConfiguration:
    if name not in MAPPING_PRESETS:
        raise ValueError(f"unknown mapping preset '{name}'.")
    return load_mapping_configuration(MAPPING_PRESETS[name])


def resolve_mapping(spec: dict[str, Any] | None) -> tuple[MappingConfiguration, dict[str, Any]]:
    """Build a ``MappingConfiguration`` from a dashboard mapping spec.

    ``spec = {"preset": str | None, "overrides": {dest: source_path | None},
    "event_id_from_position": bool}``. With no preset every canonical field
    starts unmapped. An override of ``None`` unmaps a field (allowed only for
    optional fields). Returns the configuration and the normalised spec.
    """

    spec = dict(spec or {})
    preset = spec.get("preset", "elastic-sysmon-field-mapping-v1")
    overrides = dict(spec.get("overrides") or {})
    from_position = bool(spec.get("event_id_from_position", False))
    unknown = sorted(set(overrides) - set(CANONICAL_FIELDS))
    if unknown:
        raise ValueError(f"unknown canonical field(s) in mapping: {', '.join(unknown)}.")

    fields: dict[str, FieldMapping] = {}
    version = "dashboard-custom"
    if preset:
        base = preset_configuration(preset)
        version = base.version
        fields = {item.destination_field: item for item in base.fields}
    for destination in CANONICAL_FIELDS:
        if destination in overrides:
            source = overrides[destination]
            if source is None or not str(source).strip():
                if destination in REQUIRED_FIELDS:
                    raise ValueError(f"'{destination}' is required and cannot be unmapped.")
                fields[destination] = FieldMapping(UNMAPPED_SOURCE, destination, True)
            else:
                fields[destination] = FieldMapping(str(source).strip(), destination, destination not in REQUIRED_FIELDS)
        elif destination not in fields:
            if destination in REQUIRED_FIELDS and not (destination == "source_event_id" and from_position):
                raise ValueError(f"'{destination}' is required; map it to a source field.")
            fields[destination] = FieldMapping(UNMAPPED_SOURCE, destination, True)
    if from_position:
        fields["source_event_id"] = FieldMapping(POSITION_KEY, "source_event_id", False)
    if overrides or from_position:
        version = f"{version}+dashboard-overrides"
    configuration = MappingConfiguration(version=version, fields=tuple(fields[name] for name in CANONICAL_FIELDS))
    CanonicalEventMapper(configuration)  # validates destinations exactly as a run would
    normalised = {"preset": preset, "overrides": overrides, "event_id_from_position": from_position}
    return configuration, normalised


def mapping_table(configuration: MappingConfiguration) -> list[dict[str, Any]]:
    return [
        {
            "destination": item.destination_field,
            "source": None if item.source_field == UNMAPPED_SOURCE else item.source_field,
            "derived_from_position": item.source_field == POSITION_KEY,
            "optional": item.optional,
            "required": item.destination_field in REQUIRED_FIELDS,
        }
        for item in configuration.fields
    ]


def mapping_key(normalised: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(normalised, sort_keys=True).encode()).hexdigest()[:16]


def position_id(index: int) -> str:
    return f"rec-{index + 1:07d}"


def mapped_document(document: dict[str, Any], index: int, from_position: bool) -> dict[str, Any]:
    if not from_position:
        return document
    copy = dict(document)
    copy[POSITION_KEY] = position_id(index)
    return copy


@dataclass
class MappedRecords:
    events: list[CanonicalEvent]
    record_indices: list[int]  # dataset record index of each accepted event
    rejections: list[dict[str, Any]]


def map_records(parsed: ParsedDataset, configuration: MappingConfiguration, from_position: bool) -> MappedRecords:
    mapper = CanonicalEventMapper(configuration)
    translator = CanonicalEventTranslator()
    events: list[CanonicalEvent] = []
    indices: list[int] = []
    rejections: list[dict[str, Any]] = []
    for index, document in parsed.documents():
        try:
            event = mapper.map_document(mapped_document(document, index, from_position))
        except (ValueError, TypeError) as error:
            rejections.append({"index": index, "location": parsed.locations[index], "stage": "mapping", "error": str(error)})
            continue
        try:
            translator.translate([event])
        except (ValueError, TypeError) as error:
            rejections.append({"index": index, "location": parsed.locations[index], "stage": "translation", "error": str(error)})
            continue
        events.append(event)
        indices.append(index)
    return MappedRecords(events, indices, rejections)


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate(parsed: ParsedDataset, spec: dict[str, Any] | None) -> dict[str, Any]:
    """Full validation report for one dataset under one mapping."""

    report: dict[str, Any] = {
        "computed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "format": parsed.format,
        "records_read": len(parsed),
        "blank_lines": parsed.blank_lines,
        "parse_errors": parsed.parse_errors[:500],
        "parse_error_count": len(parsed.parse_errors),
        "structure_errors": list(parsed.structure_errors),
        "warnings": [],
        "cross_record_errors": [],
    }
    try:
        configuration, normalised = resolve_mapping(spec)
    except ValueError as error:
        report.update(status="invalid", mapping_error=str(error), accepted=0, rejected=0)
        return report
    report["mapping"] = {"spec": normalised, "key": mapping_key(normalised), "version": configuration.version, "fields": mapping_table(configuration)}
    if parsed.structure_errors:
        report.update(status="invalid", accepted=0, rejected=0)
        return report

    mapped = map_records(parsed, configuration, normalised["event_id_from_position"])
    events = mapped.events
    report["accepted"] = len(events)
    report["rejected"] = len(mapped.rejections)
    report["rejections"] = mapped.rejections[:500]
    report["rejection_summary"] = [
        {"stage": stage, "error": error, "count": count}
        for (stage, error), count in Counter((r["stage"], r["error"]) for r in mapped.rejections).most_common(25)
    ]

    presence = {name: sum(1 for event in events if getattr(event, name) is not None) for name in CANONICAL_FIELDS}
    report["field_presence"] = presence
    for name in CANONICAL_FIELDS:
        if name not in REQUIRED_FIELDS and events and presence[name] == 0:
            report["warnings"].append({"code": "field_never_present", "field": name, "message": f"'{name}' is absent in every accepted record; signals that read it cannot fire."})

    without_guid = sum(1 for event in events if event.process_guid is None)
    report["without_process_guid"] = without_guid
    if without_guid:
        report["warnings"].append({"code": "no_process_guid", "count": without_guid, "message": f"{without_guid} accepted record(s) have no process_guid; the pipeline keeps them as canonical events but they join no lineage chain or context."})

    levels = Counter(event.integrity_level for event in events if event.integrity_level is not None)
    report["integrity_levels"] = dict(levels.most_common())
    unranked = {level: count for level, count in levels.items() if level not in KNOWN_INTEGRITY_LEVELS}
    if unranked:
        report["warnings"].append({"code": "unranked_integrity", "levels": unranked, "message": "integrity level(s) outside Untrusted<Low<Medium<High<System are ignored by the integrity-transition baseline: " + ", ".join(f"{k} ({v})" for k, v in unranked.items())})

    keys = Counter((event.source_timestamp, event.source_event_id) for event in events)
    tied = sum(count for count in keys.values() if count > 1)
    if tied:
        report["warnings"].append({"code": "ordering_ties", "count": tied, "message": f"{tied} record(s) share (timestamp, event id) with another record; their relative order is not determined by the data."})
    report["event_codes"] = dict(Counter(str(event.event_code) for event in events).most_common())

    if events:
        stamps = [_parse_ts(event.source_timestamp) for event in events]
        report["time_range"] = {"start": min(stamps).isoformat(), "end": max(stamps).isoformat(), "seconds": (max(stamps) - min(stamps)).total_seconds()}

    parents: dict[str, set] = defaultdict(set)
    for event in events:
        if isinstance(event.process_guid, str) and isinstance(event.parent_process_guid, str):
            parents[event.process_guid].add(event.parent_process_guid)
    for guid, assertions in sorted(parents.items()):
        if len(assertions) > 1:
            report["cross_record_errors"].append({"code": "conflicting_parent", "process_guid": guid, "parents": sorted(assertions), "message": f"process {guid} is asserted to have {len(assertions)} different parents; CPES refuses to guess which is right."})
    if not report["cross_record_errors"] and events:
        try:
            translated = CanonicalEventTranslator().translate(events)
            chains = LineageBuilder().build(translated.process_nodes)
            report["lineage_preview"] = {"process_nodes": len(translated.process_nodes), "chains": len(chains), "truncated_chains": sum(1 for c in chains if c.is_truncated)}
        except ValueError as error:
            report["cross_record_errors"].append({"code": "pipeline_rejects", "message": str(error)})

    if not events or report["cross_record_errors"]:
        report["status"] = "invalid"
    elif mapped.rejections or parsed.parse_errors:
        report["status"] = "valid_with_rejections"
    else:
        report["status"] = "valid"
    return report


# --------------------------------------------------------------------------- record inspection


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        if not value and prefix:
            out[prefix] = {}
        for key, item in value.items():
            out.update(flatten(item, f"{prefix}.{key}" if prefix else str(key)))
    else:
        out[prefix] = value
    return out


def type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def inspect_record(parsed: ParsedDataset, index: int, spec: dict[str, Any] | None) -> dict[str, Any]:
    """Original record, its canonical mapping, and which fields the mapping ignores."""

    original = parsed.original(index)
    document = parsed.document(index)
    result: dict[str, Any] = {"index": index, "location": parsed.locations[index], "format": parsed.format, "original": original}
    configuration, normalised = resolve_mapping(spec)
    from_position = normalised["event_id_from_position"]
    flat = flatten(document)
    used_sources = {item.source_field for item in configuration.fields}
    canonical = []
    for item in configuration.fields:
        source = None if item.source_field == UNMAPPED_SOURCE else item.source_field
        value = position_id(index) if item.source_field == POSITION_KEY else flat.get(item.source_field) if source else None
        present = item.source_field == POSITION_KEY or (source is not None and item.source_field in flat)
        canonical.append({
            "destination": item.destination_field,
            "source": source,
            "present": present,
            "value": value,
            "derived_from_position": item.source_field == POSITION_KEY,
            "required": item.destination_field in REQUIRED_FIELDS,
        })
    result["canonical"] = canonical
    result["unmapped_fields"] = sorted(path for path in flat if path not in used_sources)
    issues = []
    try:
        event = CanonicalEventMapper(configuration).map_document(mapped_document(document, index, from_position))
        CanonicalEventTranslator().translate([event])
        result["accepted"] = True
    except (ValueError, TypeError) as error:
        result["accepted"] = False
        issues.append(str(error))
    result["issues"] = issues
    return result
