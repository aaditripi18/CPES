"""Parsing and record-by-record validation (no record is dropped silently)."""

from __future__ import annotations

import json

import pytest

from cpes.adapters.mapping import CanonicalEventMapper
from cpes_dashboard.ingest import (
    POSITION_KEY,
    inspect_record,
    parse_file,
    preset_configuration,
    resolve_mapping,
    unflatten_csv_row,
    validate,
)


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_jsonl_reports_every_bad_line_with_its_number(tmp_path, uac_documents):
    lines = [json.dumps(uac_documents[0]), "", "{not json", "[1, 2]", json.dumps(uac_documents[1])]
    parsed = parse_file(write(tmp_path, "a.jsonl", "\n".join(lines) + "\n"), "jsonl")
    assert len(parsed) == 2
    assert parsed.blank_lines == 1
    assert [error["location"] for error in parsed.parse_errors] == [3, 4]
    assert "invalid JSON" in parsed.parse_errors[0]["error"]
    assert "expected a JSON object" in parsed.parse_errors[1]["error"]
    assert parsed.locations == [1, 5]


def test_json_accepts_array_records_hits_and_single_object(tmp_path, uac_documents):
    doc = uac_documents[0]
    for body in ([doc, doc], {"records": [doc, doc]}, {"hits": {"hits": [{"_source": doc}, {"_source": doc}]}}):
        assert len(parse_file(write(tmp_path, "a.json", json.dumps(body)), "json")) == 2
    assert len(parse_file(write(tmp_path, "b.json", json.dumps(doc)), "json")) == 1
    bad = parse_file(write(tmp_path, "c.json", "{oops"), "json")
    assert bad.structure_errors and len(bad) == 0


def test_csv_dotted_columns_nest_and_empty_cells_are_absent(tmp_path):
    text = "@timestamp,winlog.record_id,process.entity_id,process.parent.entity_id\n2026-07-20T10:00:00Z,1,{A},\n2026-07-20T10:00:01Z,2,{B},{A}\n"
    parsed = parse_file(write(tmp_path, "a.csv", text), "csv")
    assert parsed.document(0) == {"@timestamp": "2026-07-20T10:00:00Z", "winlog": {"record_id": "1"}, "process": {"entity_id": "{A}"}}
    assert parsed.document(1)["process"]["parent"]["entity_id"] == "{A}"
    assert parsed.original(0)["process.parent.entity_id"] == ""  # original row kept verbatim
    assert unflatten_csv_row({"a.b": "", "c": "x"}) == {"c": "x"}


def test_csv_structure_problems_are_reported(tmp_path):
    assert parse_file(write(tmp_path, "a.csv", "a,a\n1,2\n"), "csv").structure_errors
    assert parse_file(write(tmp_path, "b.csv", "process,process.pid\n1,2\n"), "csv").structure_errors
    ragged = parse_file(write(tmp_path, "c.csv", "a,b\n1,2\n1,2,3\n"), "csv")
    assert ragged.parse_errors[0]["location"] == 3 and len(ragged) == 1


def test_validation_counts_add_up_and_errors_are_the_package_messages(tmp_path, uac_documents):
    no_id = dict(uac_documents[1])
    no_id["winlog"] = {"event_data": {"IntegrityLevel": "Medium"}}  # no record_id
    naive_time = dict(uac_documents[2], **{"@timestamp": "2026-07-20T10:00:12"})  # no offset
    documents = [uac_documents[0], no_id, naive_time, uac_documents[3]]
    parsed = parse_file(write(tmp_path, "a.jsonl", "\n".join(json.dumps(d) for d in documents) + "\nnot-json\n"), "jsonl")
    report = validate(parsed, None)
    assert report["records_read"] == 4
    assert report["accepted"] + report["rejected"] == report["records_read"]
    assert report["parse_error_count"] == 1
    stages = {r["stage"]: r["error"] for r in report["rejections"]}
    assert stages["mapping"] == "required source field is missing: winlog.record_id"
    assert stages["translation"] == "source_timestamp must include an offset."
    assert report["status"] == "valid_with_rejections"


def test_conflicting_parent_assertions_make_the_dataset_invalid(tmp_path, uac_documents):
    conflicting = json.loads(json.dumps(uac_documents[3]))
    conflicting["winlog"]["record_id"] = "99"
    conflicting["process"]["parent"] = {"entity_id": "{EXPLORER}"}  # FOD already has parent CMD
    parsed = parse_file(write(tmp_path, "a.jsonl", "\n".join(json.dumps(d) for d in uac_documents + [conflicting])), "jsonl")
    report = validate(parsed, None)
    assert report["status"] == "invalid"
    assert report["cross_record_errors"][0]["process_guid"] == "{FOD}"


def test_position_ids_are_opt_in_and_never_written_to_the_record(tmp_path, uac_documents):
    stripped = []
    for d in uac_documents:
        copy = json.loads(json.dumps(d))
        del copy["winlog"]["record_id"]
        stripped.append(copy)
    parsed = parse_file(write(tmp_path, "a.jsonl", "\n".join(json.dumps(d) for d in stripped)), "jsonl")
    assert validate(parsed, None)["accepted"] == 0
    report = validate(parsed, {"preset": "elastic-sysmon-field-mapping-v1", "event_id_from_position": True})
    assert report["accepted"] == len(stripped) and report["status"] == "valid"
    assert POSITION_KEY not in parsed.original(0)
    detail = inspect_record(parsed, 2, {"event_id_from_position": True})
    row = next(r for r in detail["canonical"] if r["destination"] == "source_event_id")
    assert row["derived_from_position"] and row["value"] == "rec-0000003"


def test_custom_mapping_rules(tmp_path):
    with pytest.raises(ValueError, match="required"):
        resolve_mapping({"preset": None})
    with pytest.raises(ValueError, match="cannot be unmapped"):
        resolve_mapping({"overrides": {"source_timestamp": None}})
    with pytest.raises(ValueError, match="unknown canonical"):
        resolve_mapping({"overrides": {"hostname": "host.name"}})
    configuration, spec = resolve_mapping({"preset": None, "overrides": {"source_timestamp": "t", "source_event_id": "id"}})
    assert spec["preset"] is None
    assert sum(1 for f in configuration.fields if f.source_field not in ("t", "id")) == 10  # the rest unmapped, optional


def test_inspect_record_matches_the_package_mapper(tmp_path, uac_documents):
    parsed = parse_file(write(tmp_path, "a.jsonl", "\n".join(json.dumps(d) for d in uac_documents)), "jsonl")
    event = CanonicalEventMapper(preset_configuration("elastic-sysmon-field-mapping-v1")).map_document(uac_documents[3])
    detail = inspect_record(parsed, 3, None)
    values = {row["destination"]: row["value"] for row in detail["canonical"] if row["present"]}
    assert values["process_guid"] == event.process_guid == "{FOD}"
    assert values["integrity_level"] == event.integrity_level == "High"
    assert "process.pid" in detail["unmapped_fields"] or "process.pid" in {r["source"] for r in detail["canonical"]}
    assert detail["accepted"] is True
