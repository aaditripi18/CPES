"""Runs reproduce the package exactly, never overwrite, and only evaluate with labels."""

from __future__ import annotations

import csv
import io
import json
from datetime import timedelta
from decimal import Decimal

from conftest import jsonl, upload

from cpes.adapters.mapping import CanonicalEventMapper
from cpes.exporting import ResultExporter
from cpes.orchestration import CpesPipeline, PipelineConfiguration
from cpes.windowing.models import SlidingWindowParameters
from cpes_dashboard.evidence import load_model, to_evidence_model
from cpes_dashboard.ingest import preset_configuration
from cpes_dashboard.runner import SIGNAL_IDS, make_generator, make_resolver


def start(client, dataset_id, **extra):
    response = client.post("/api/runs", json={"dataset_id": dataset_id, **extra})
    assert response.status_code == 200, response.text
    return response.json()


def test_run_output_equals_a_direct_package_run(client, data_root, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"], span_seconds=60, advance_seconds=30)
    status = client.get(f"/api/runs/{run['id']}").json()
    assert status["state"] == "completed", status.get("traceback")

    # Independent direct call of the unchanged package with the recorded configuration.
    config = status["config"]
    mapper = CanonicalEventMapper(preset_configuration("elastic-sysmon-field-mapping-v1"))
    events = [mapper.map_document(d) for d in uac_documents]
    from datetime import datetime

    stamps = [datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) for e in events]
    params = SlidingWindowParameters(min(stamps), max(stamps) + timedelta(seconds=60), 60.0, 30.0)
    model = load_model("research-v3-full-table")
    context = CpesPipeline().run(events, PipelineConfiguration(params, to_evidence_model(model, SIGNAL_IDS), Decimal("0.5"), make_generator(make_resolver())))
    direct = ResultExporter().build(context)

    recorded = json.loads((data_root / "runs" / run["id"] / "export.json").read_text(encoding="utf-8"))
    assert recorded["detections"] == direct["detections"]
    assert recorded["summary"] == direct["summary"]
    assert config["window"]["start_at"] == min(stamps).isoformat()
    assert config["dataset"]["sha256"] == dataset["sha256"]


def test_scores_decompose_exactly_and_uac_chain_is_detected(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"], span_seconds=60, advance_seconds=30)
    export = client.get(f"/api/runs/{run['id']}/download/export.json").json()
    for record in export["detections"]:
        total = Decimal(record["prior_log_odds"]) + sum((Decimal(c["signed_log_likelihood"]) for c in record["contributions"]), Decimal(0))
        assert Decimal(record["cpes_score"]) == total
        assert record["is_detected"] == (Decimal(record["cpes_score"]) >= Decimal(record["detection_threshold"]))
    detected = [r for r in export["detections"] if r["is_detected"]]
    assert {r["lineage_chain_id"] for r in detected} == {"{EXPLORER}"}
    assert all(c["signal_id"] == "autoelevation_lolbin" for r in detected for c in r["contributions"])

    window = client.get(f"/api/runs/{run['id']}/windows", params={"detected": True}).json()["rows"][0]
    detail = client.get(f"/api/runs/{run['id']}/windows/{window['window_index']}").json()
    resolved = detail["audit"]["resolved"][0]
    assert resolved["anchor_process_guid"] == "{FOD}" and resolved["actor_process_guid"] == "{CMD}"
    assert {e["event_id"] for e in detail["evidence_events"]} == {"3", "4"}
    assert all(e["record_indices"] for e in detail["evidence_events"])


def test_detections_csv_has_one_row_per_detected_window(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"], span_seconds=60, advance_seconds=30)
    text = client.get(f"/api/runs/{run['id']}/download/detections.csv").text
    rows = list(csv.DictReader(io.StringIO(text)))
    status = client.get(f"/api/runs/{run['id']}").json()
    assert len(rows) == status["summary"]["detected_windows"] > 0
    assert all(row["run_id"] == run["id"] and row["signals"] for row in rows)


def test_runs_never_overwrite_each_other(client, data_root, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    first = start(client, dataset["id"], threshold="0.5")
    before = (data_root / "runs" / first["id"] / "export.json").read_bytes()
    second = start(client, dataset["id"], threshold="100")
    assert first["id"] != second["id"]
    assert (data_root / "runs" / first["id"] / "export.json").read_bytes() == before
    assert client.get(f"/api/runs/{second['id']}").json()["summary"]["detected_windows"] == 0
    assert [r["id"] for r in client.get("/api/runs").json()][:2] == [second["id"], first["id"]]


def test_no_metrics_without_ground_truth(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"])
    evaluation = client.get(f"/api/runs/{run['id']}/evaluation").json()
    assert evaluation["available"] is False
    assert "precision" not in json.dumps(evaluation).lower() or "no precision" in evaluation["reason"].lower()


def test_invalid_dataset_cannot_be_run_and_bad_parameters_are_refused(client, uac_documents):
    stripped = [{k: v for k, v in d.items() if k != "winlog"} for d in uac_documents]
    dataset = upload(client, "bad.jsonl", jsonl(stripped)).json()
    assert dataset["validation_report"]["status"] == "invalid"
    assert client.post("/api/runs", json={"dataset_id": dataset["id"]}).status_code == 400
    good = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    response = client.post("/api/runs", json={"dataset_id": good["id"], "span_seconds": 30, "advance_seconds": 60})
    assert response.status_code == 400 and "advance" in response.json()["detail"]


def test_lineage_graph_contains_only_reconstructed_edges(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"])
    chains = {c["lineage_chain_id"]: c for c in client.get(f"/api/runs/{run['id']}/chains").json()}
    graph = client.get(f"/api/runs/{run['id']}/chains/{{EXPLORER}}/graph").json()
    assert {(e["source"], e["target"]) for e in graph["edges"]} == {("{EXPLORER}", "{CMD}"), ("{CMD}", "{FOD}")}
    orphan = client.get(f"/api/runs/{run['id']}/chains/{{ORPHAN}}/graph").json()
    assert orphan["edges"] == [] and orphan["unresolved_parent_process_guids"] == ["{NOT-IN-DATA}"]
    assert orphan["nodes"][0]["parent_unresolved"] is True
    assert chains["{ORPHAN}"]["is_truncated"] is True
    process = client.get(f"/api/runs/{run['id']}/processes/{{ORPHAN}}").json()
    assert process["parent_in_telemetry"] is False


def _pipe_docs():
    # Hand-written test fixture: a SYSTEM cmd.exe (child of services.exe) connects to a
    # pipe created by a user process in another chain, inside one window.
    def doc(record_id, ts, code, guid, *, parent=None, image=None, integrity=None, user=None, pipe=None):
        d = {"@timestamp": ts, "event": {"code": code}, "winlog": {"record_id": str(record_id), "event_data": {}}, "process": {"entity_id": guid}}
        if parent:
            d["process"]["parent"] = {"entity_id": parent}
        if image:
            d["process"]["executable"] = image
        if integrity:
            d["winlog"]["event_data"]["IntegrityLevel"] = integrity
        if user:
            d["user"] = {"name": user}
        if pipe:
            d["file"] = {"name": pipe}
        return d

    return [
        doc(1, "2026-07-20T10:00:00Z", "1", "{USER}", image=r"C:\Users\u\evil.exe", integrity="Medium"),
        doc(2, "2026-07-20T10:00:01Z", "1", "{SCM}", image=r"C:\Windows\System32\services.exe", integrity="System"),
        doc(3, "2026-07-20T10:00:02Z", "1", "{SHELL}", parent="{SCM}", image=r"C:\Windows\System32\cmd.exe", integrity="System"),
        doc(4, "2026-07-20T10:00:03Z", "17", "{USER}", image=r"C:\Users\u\evil.exe", user="u", pipe=r"\evilpipe"),
        doc(5, "2026-07-20T10:00:04Z", "18", "{SHELL}", image=r"C:\Windows\System32\cmd.exe", user="SYSTEM", pipe=r"\evilpipe"),
    ]


def test_evidence_channels_make_token_impersonation_detectable(client):
    dataset = upload(client, "pipes.jsonl", jsonl(_pipe_docs())).json()
    on = start(client, dataset["id"], span_seconds=60, advance_seconds=30)
    off = start(client, dataset["id"], span_seconds=60, advance_seconds=30, evidence_channels=False)
    on_status = client.get(f"/api/runs/{on['id']}").json()
    assert on_status["summary"]["signals_fired"] == {"token_impersonation": on_status["summary"]["detected_windows"]} and on_status["summary"]["detected_windows"] > 0
    assert on_status["config"]["evidence_channels"]["pipe_evidence"] == 2
    assert on_status["config"]["signals"]["token_impersonation"]["wired"] is True
    off_status = client.get(f"/api/runs/{off['id']}").json()
    assert off_status["summary"]["detected_windows"] == 0
    assert off_status["config"]["signals"]["token_impersonation"]["wired"] is False
    window = client.get(f"/api/runs/{on['id']}/windows", params={"detected": True}).json()["rows"][0]
    resolved = client.get(f"/api/runs/{on['id']}/windows/{window['window_index']}").json()["audit"]["resolved"][0]
    assert (resolved["anchor_kind"], resolved["anchor_process_guid"], resolved["actor_process_guid"]) == ("token_impersonation", "{SHELL}", "{USER}")
    assert set(resolved["evidence_event_ids"]) == {"4", "5"}
